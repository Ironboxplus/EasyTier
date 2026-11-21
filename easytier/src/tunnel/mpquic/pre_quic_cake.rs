//! The queue in front of QUIC: the original `sch_cake.c` (`cake_sqm::Cake`)
//! with its rate unlimited, for the frames a session hands to QUIC when the
//! QUIC side holds only a little unsent (Linux's `TCP_NOTSENT_LOWAT` idea).
//!
//! `bandwidth: 0` is CAKE's own meaning of no shaper: it keeps per-flow
//! queues served by deficit round robin with sparse-flow priority, runs
//! COBALT (CoDel and BLUE) per flow on the queueing time, and bounds its
//! packet memory, but never holds a frame back for rate. The egress CAKE
//! below QUIC shapes as before. Without this queue the backlog of an
//! overloaded session sat in a first-in first-out place instead (the ET
//! pipe, or a tail-drop channel behind it): no queueing-time judgement, no
//! isolation of the inner flows (RFC 7567 section 4.1, RFC 8289, RFC 8290).
//!
//! Users: `fair_pipe` (the single stream of a session with SQM on and the
//! data plane off) and the datagram classes of the data plane
//! (`dataplane_driver`). A frame keeps the inner flow hash it came with.

use std::time::{Duration, Instant};

use bytes::Bytes;
use cake_sqm::{Cake, CakeConfig, Dequeued, PacketHeader, PacketMeta};

use super::stream_queue::{StreamAqm, StreamDrops};

pub(super) struct PreQuicCake {
    cake: Cake<(Bytes, Option<u32>)>,
    /// The `target`, `interval` and `mtu` CAKE runs with.
    timing: (Duration, Duration, u32),
    drops: StreamDrops,
}

fn cake_config((target, interval, mtu): (Duration, Duration, u32)) -> CakeConfig {
    CakeConfig {
        // CAKE's own "unlimited": per-flow queues, AQM and memory limit
        // without a shaper.
        bandwidth: 0,
        rtt: interval,
        target,
        mtu,
        ..CakeConfig::default()
    }
}

fn timing_of(aqm: &StreamAqm) -> (Duration, Duration, u32) {
    (aqm.target, aqm.interval, aqm.mtu)
}

impl PreQuicCake {
    pub(super) fn new(aqm: &StreamAqm, now: Instant) -> Result<Self, String> {
        let timing = timing_of(aqm);
        let cake = Cake::new(&cake_config(timing), now).map_err(|error| error.to_string())?;
        Ok(Self {
            cake,
            timing,
            drops: StreamDrops::default(),
        })
    }

    /// Follows the egress's `target`, `interval` and MTU. The rate is not
    /// CAKE's here.
    pub(super) fn set_aqm(&mut self, aqm: &StreamAqm, now: Instant) {
        let timing = timing_of(aqm);
        if timing != self.timing && self.cake.reconfigure(&cake_config(timing), now).is_ok() {
            self.timing = timing;
        }
    }

    /// What CAKE dropped so far: its COBALT decisions apart from the memory
    /// limit's (`tin.dropped_packets` counts both).
    pub(super) fn drops(&self) -> StreamDrops {
        self.drops
    }

    pub(super) fn is_empty(&self) -> bool {
        self.cake.is_empty()
    }

    pub(super) fn backlog_bytes(&self) -> u64 {
        self.cake.backlog_bytes()
    }

    /// Queues `frame` of the inner flow `flow`; a frame without one (EasyTier's
    /// own and non-IP frames) queues with the others like it as one flow.
    pub(super) fn enqueue(&mut self, frame: Bytes, flow: Option<u32>, now: Instant) {
        let meta = PacketMeta {
            len: frame.len() as u32,
            header: PacketHeader::None,
            flow_hash: flow,
            mark: 0,
        };
        if !self.cake.enqueue(meta, (frame, flow), now).is_empty() {
            self.count_drops();
        }
    }

    /// The next frame CAKE lets go, with its flow.
    pub(super) fn dequeue(&mut self, now: Instant) -> Option<(Bytes, Option<u32>)> {
        let frame = match self.cake.dequeue(now) {
            Dequeued::Packet { item, .. } => Some(item),
            // The shaper is unlimited: nothing is ever held back for time.
            Dequeued::NotBefore(_) | Dequeued::Empty => None,
        };
        if !self.cake.take_dropped().is_empty() {
            self.count_drops();
        }
        frame
    }

    /// `dequeue`, but only while the lower layer holds less than `lowat`
    /// unsent (`queued`): the next frame is handed over only when there is room.
    pub(super) fn dequeue_below(
        &mut self,
        queued: usize,
        lowat: usize,
        now: Instant,
    ) -> Option<(Bytes, Option<u32>)> {
        if queued >= lowat {
            return None;
        }
        self.dequeue(now)
    }

    fn count_drops(&mut self) {
        let stats = self.cake.stats();
        let Some(tin) = stats.tins.first() else {
            return;
        };
        let overlimit = u64::from(tin.drop_overlimit);
        self.drops = StreamDrops {
            aqm: u64::from(tin.dropped_packets).saturating_sub(overlimit),
            overlimit,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOWAT: usize = 64 * 1024;
    const DATAGRAM: usize = 1200;

    fn aqm() -> StreamAqm {
        StreamAqm {
            rate_bytes_per_sec: 0,
            mtu: 1500,
            target: Duration::from_millis(5),
            interval: Duration::from_millis(100),
        }
    }

    struct Outcome {
        /// Bytes handed to the lower layer, by flow (1, 2).
        handed: [u64; 2],
        max_queued: usize,
        drops: StreamDrops,
        backlog: u64,
    }

    /// The lower layer (QUIC's datagram queue) sends `rate` bytes a second.
    /// Flow 1 is offered `a` datagrams and flow 2 `b` datagrams every
    /// millisecond (fractions, spread evenly), for `ms` milliseconds; the
    /// driver's loop hands frames over with `dequeue_below`.
    fn run(a: f64, b: f64, rate: u64, ms: u64) -> Outcome {
        let t0 = Instant::now();
        let mut queue = PreQuicCake::new(&aqm(), t0).unwrap();
        let (mut queued, mut credit, mut max_queued) = (0usize, 0.0f64, 0usize);
        let mut owed = [0.0f64; 2];
        let mut handed = [0u64; 2];
        let mut window = [0u64; 2];
        for step in 0..ms {
            let now = t0 + Duration::from_millis(step);
            owed[0] += a;
            owed[1] += b;
            for (index, flow) in [1u32, 2].into_iter().enumerate() {
                while owed[index] >= 1.0 {
                    owed[index] -= 1.0;
                    queue.enqueue(Bytes::from(vec![flow as u8; DATAGRAM]), Some(flow), now);
                }
            }
            while let Some((frame, flow)) = queue.dequeue_below(queued, LOWAT, now) {
                let flow = flow.unwrap() as usize - 1;
                queued += frame.len();
                max_queued = max_queued.max(queued);
                handed[flow] += frame.len() as u64;
                if step >= ms / 2 {
                    window[flow] += frame.len() as u64;
                }
            }
            credit += rate as f64 / 1000.0;
            let sent = (credit as usize).min(queued);
            credit -= sent as f64;
            queued -= sent;
        }
        Outcome {
            handed: window,
            max_queued,
            drops: queue.drops(),
            backlog: queue.backlog_bytes(),
        }
    }

    /// One flow offers three times the other's rate and the lower layer is
    /// the bottleneck: each gets half of it, the lower layer never holds more
    /// than the low-water mark and one datagram, and the overload is dropped
    /// here (COBALT on queueing time first), not by QUIC's drop-oldest queue.
    #[test]
    fn overload_is_shared_per_flow_held_at_the_lowat_and_dropped_by_cobalt() {
        let rate = 1_250_000u64; // 10 Mbit/s
        let per_ms = rate as f64 / 1000.0 / DATAGRAM as f64;
        let out = run(per_ms * 2.25, per_ms * 0.75, rate, 10_000);
        let share = out.handed[0] as f64 / (out.handed[0] + out.handed[1]) as f64;
        assert!((0.4..=0.6).contains(&share), "flow 1 got {share:.3}");
        assert!(
            out.max_queued <= LOWAT + DATAGRAM,
            "the lower layer held {} unsent",
            out.max_queued
        );
        assert!(out.backlog > 0, "the overload must queue here");
        assert!(out.drops.aqm > 0, "COBALT never dropped");
        // COBALT alone cannot hold a flow that ignores drops: at 3 times the
        // rate for 10 s the memory limit takes the rest, so `overlimit` is
        // counted apart and not asserted to be zero.
    }

    /// Nothing is dropped or delayed below the lower layer's rate.
    #[test]
    fn an_underloaded_queue_drops_nothing() {
        let rate = 1_250_000u64;
        let per_ms = rate as f64 / 1000.0 / DATAGRAM as f64;
        let out = run(per_ms * 0.3, per_ms * 0.3, rate, 5_000);
        assert_eq!(out.drops, StreamDrops::default());
        assert_eq!(out.backlog, 0);
    }
}

//! One-way delay probing (OWD_AUTORATE_PLAN.md 1.1): the delay signal of the
//! egress's Autorate.
//!
//! QUIC's round trip contains the ACK path, and with it the queue the peer's
//! own egress queue (CAKE) builds for its ACKs: two ends that both shape
//! would read each other's queue as the link's, and cut each other to the
//! floor. RFC 6817 Section 3.1 therefore measures the one-way delay of the
//! data direction, "to avoid measuring additional delay from ... queue
//! buildup on the reverse path". cake-autorate does the same with irtt/tsping.
//!
//! The sender stamps a small datagram when it leaves for the wire (after the
//! egress queue, so its own queue is no part of the delay), the receiver
//! answers with its own clock at arrival, and the difference is the one-way
//! delay plus the fixed offset between the two clocks. The offset cancels
//! against the base delay (RFC 6817 Section 2.3, 3.1.1): the queueing delay
//! is the sample less the smallest one seen in the last `BASE_HISTORY`
//! minutes (Section 2.4.2, 2.5).

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Mutex;
#[cfg(not(target_os = "linux"))]
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::common::egress_quality::EgressHandle;
use crate::common::transport_quality::budget::EgressScope;

/// A measurement clock in microseconds. Linux's ordinary MONOTONIC clock is
/// slewed by time synchronization; comparing it with a peer's unslewed clock
/// would turn that adjustment into queueing delay (RFC 6817 Appendix A.2).
/// Use the OS raw clock through the existing nix binding. A failed read yields
/// no measurement, rather than switching epochs or manufacturing a low base.
#[cfg(target_os = "linux")]
pub(crate) fn owd_clock_us() -> Option<u64> {
    use nix::sys::time::TimeValLike;
    use nix::time::{ClockId, clock_gettime};

    let at = clock_gettime(ClockId::CLOCK_MONOTONIC_RAW).ok()?;
    u64::try_from(at.num_microseconds()).ok()
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn owd_clock_us() -> Option<u64> {
    static START: OnceLock<Instant> = OnceLock::new();
    Some(START.get_or_init(Instant::now).elapsed().as_micros() as u64)
}

/// RFC 6817 Section 2.4.2: one-minute minima kept for the base delay.
const BASE_HISTORY: usize = 10;
const MINUTE_US: u64 = 60_000_000;

/// Probe every 100 ms while data flows, every second otherwise.
const PROBE_BUSY: Duration = Duration::from_millis(100);
const PROBE_IDLE: Duration = Duration::from_secs(1);
/// Data was sent this recently: the link is busy.
const DATA_RECENT: Duration = Duration::from_secs(1);
/// A probe not reported by now is lost.
const PROBE_EXPIRY: Duration = Duration::from_secs(2);

/// The flow hash of probe `seq`: its own, nonzero (`seq | 1` would give
/// neighbours one flow). TQUIC puts only datagrams
/// of one flow into a packet (CAKE_SQM_PLAN.md B1), so the packet that carries
/// a probe is known by it. It marks the packet only: the egress queue keeps
/// the probe in order with its path's other packets (`EgressCake::enqueue`).
pub(super) fn probe_flow(seq: u32) -> u32 {
    seq.wrapping_mul(0x9E37_79B9) | 1
}

/// When the next probe is due (OWD_AUTORATE_PLAN.md 1.1).
pub(super) struct ProbeSchedule {
    last_sent: Option<Instant>,
    next_seq: u32,
}

impl ProbeSchedule {
    pub(super) fn new() -> Self {
        Self {
            last_sent: None,
            next_seq: 0,
        }
    }

    fn interval(now: Instant, last_data: Option<Instant>) -> Duration {
        match last_data {
            Some(at) if now.saturating_duration_since(at) <= DATA_RECENT => PROBE_BUSY,
            _ => PROBE_IDLE,
        }
    }

    /// The sequence number of the probe to send now, if one is due. Nothing
    /// is due unless `enabled` (the capability was negotiated).
    pub(super) fn poll(
        &mut self,
        now: Instant,
        enabled: bool,
        last_data: Option<Instant>,
    ) -> Option<u32> {
        if !enabled {
            return None;
        }
        if let Some(last) = self.last_sent
            && now.saturating_duration_since(last) < Self::interval(now, last_data)
        {
            return None;
        }
        self.last_sent = Some(now);
        let seq = self.next_seq;
        self.next_seq = seq.wrapping_add(1);
        Some(seq)
    }

    /// When the driver must wake for the next probe.
    pub(super) fn next_wake(&self, enabled: bool, last_data: Option<Instant>) -> Option<Instant> {
        if !enabled {
            return None;
        }
        let last = self.last_sent?;
        Some(last + Self::interval(Instant::now(), last_data))
    }
}

/// The base delay of one path (RFC 6817 Section 2.4.2): the smallest sample of
/// each of the last `BASE_HISTORY` minutes; a minute without samples adds
/// none (Section 2.5), so an idle path keeps what it learned.
///
/// A minimum keeps any sample that reads low for the whole history, so no
/// error may make a sample smaller: the wire time is read before the socket
/// has the packet (`EgressCake::pump`) and the arrival after it arrived;
/// every stall in between is delay.
///
/// The minima are relative to a clock that drifts against the peer's: at
/// 50 ppm the difference grows 3 ms a minute, so the oldest of ten minutes
/// would read 27 ms of queue where there is none. The drift is the slope of
/// the minima (RFC 6817 Appendix A.2), taken as the median of the slopes
/// between every two of them (Theil-Sen): a minute whose minimum held a
/// queue, as a minute of saturating traffic does, tilts few of the slopes
/// and not their median. Each minimum is carried to the present along it.
#[derive(Default)]
struct Base {
    /// Completed minutes: (time of the minimum, the minimum).
    minutes: VecDeque<(u64, i64)>,
    /// The minute in progress: (its start, time of the minimum, the minimum).
    current: Option<(u64, u64, i64)>,
    /// The drift of the clocks (µs per µs), from `minutes`.
    drift: f64,
}

impl Base {
    /// Take one sample (`raw` = receive time - wire time, taken at `at_us` on
    /// the sender's clock) and return the base delay including it.
    fn observe(&mut self, at_us: u64, raw: i64) -> i64 {
        match &mut self.current {
            Some((start, min_at, min)) if at_us.saturating_sub(*start) < MINUTE_US => {
                if raw < *min {
                    *min_at = at_us;
                    *min = raw;
                }
            }
            Some((_, min_at, min)) => {
                self.minutes.push_back((*min_at, *min));
                while self.minutes.len() >= BASE_HISTORY {
                    self.minutes.pop_front();
                }
                self.drift = Self::drift_of(&self.minutes);
                self.current = Some((at_us, at_us, raw));
            }
            None => self.current = Some((at_us, at_us, raw)),
        }
        self.minutes
            .iter()
            .copied()
            .chain(self.current.map(|(_, at, min)| (at, min)))
            .map(|(min_at, min)| {
                min + (self.drift * at_us.saturating_sub(min_at) as f64).round() as i64
            })
            .min()
            .unwrap_or(raw)
    }

    /// The median slope (µs per µs) between every two completed minutes'
    /// minima, clamped to what a clock crystal does. Five minima are needed
    /// before one bad minute touches fewer than half of the slopes; until
    /// then there is none, and the history alone bounds the drift's error
    /// (RFC 6817 Appendix A.2).
    fn drift_of(minutes: &VecDeque<(u64, i64)>) -> f64 {
        const MIN_MINUTES: usize = 5;
        const MAX_DRIFT: f64 = 100e-6;
        if minutes.len() < MIN_MINUTES {
            return 0.0;
        }
        let mut slopes: Vec<f64> = minutes
            .iter()
            .enumerate()
            .flat_map(|(i, &(a_at, a))| {
                minutes
                    .iter()
                    .skip(i + 1)
                    .filter(move |&&(b_at, _)| b_at > a_at)
                    .map(move |&(b_at, b)| (b - a) as f64 / (b_at - a_at) as f64)
            })
            .collect();
        if slopes.is_empty() {
            return 0.0;
        }
        slopes.sort_by(f64::total_cmp);
        let mid = slopes.len() / 2;
        let median = if slopes.len() % 2 == 0 {
            (slopes[mid - 1] + slopes[mid]) / 2.0
        } else {
            slopes[mid]
        };
        median.clamp(-MAX_DRIFT, MAX_DRIFT)
    }
}

/// A probe on its way to the wire.
struct Queued {
    seq: u32,
    at: Instant,
}

/// A probe that left for the wire.
struct OnWire {
    wire_us: u64,
    egress: EgressHandle,
    remote: SocketAddr,
    at: Instant,
}

#[derive(Default)]
struct Book {
    /// Registered probes not yet seen by the egress queue, by flow hash.
    queued: HashMap<u32, Queued>,
    on_wire: HashMap<u32, OnWire>,
    /// One base per path: paths of one egress differ in delay.
    bases: HashMap<(EgressScope, SocketAddr), Base>,
}

/// The probes of one session, shared between its driver (sends them, reads
/// the reports) and its egress queue (stamps the wire time).
#[derive(Default)]
pub(crate) struct OwdProbes {
    book: Mutex<Book>,
    /// `book.queued.len()`, so the packet path can skip the lock.
    queued_len: AtomicUsize,
}

impl OwdProbes {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Probe `seq` is about to be queued with QUIC.
    pub(super) fn register(&self, seq: u32, now: Instant) {
        let mut book = self.book.lock().unwrap();
        book.queued.insert(probe_flow(seq), Queued { seq, at: now });
        self.queued_len.store(book.queued.len(), Ordering::Release);
    }

    /// QUIC refused the probe.
    pub(super) fn cancel(&self, seq: u32) {
        let mut book = self.book.lock().unwrap();
        book.queued.remove(&probe_flow(seq));
        self.queued_len.store(book.queued.len(), Ordering::Release);
    }

    /// The egress queue takes a packet of `flow`: the sequence number of the
    /// probe it carries, if it is a registered probe's flow.
    pub(super) fn claim(&self, flow: u32) -> Option<u32> {
        if self.queued_len.load(Ordering::Acquire) == 0 {
            return None;
        }
        let mut book = self.book.lock().unwrap();
        let queued = book.queued.remove(&flow)?;
        self.queued_len.store(book.queued.len(), Ordering::Release);
        Some(queued.seq)
    }

    /// The packet carrying probe `seq` left through `egress` towards `remote`
    /// at `wire_us` on this process's clock.
    pub(super) fn on_wire(
        &self,
        seq: u32,
        wire_us: u64,
        egress: EgressHandle,
        remote: SocketAddr,
        now: Instant,
    ) {
        let mut book = self.book.lock().unwrap();
        book.on_wire.insert(
            seq,
            OnWire {
                wire_us,
                egress,
                remote,
                at: now,
            },
        );
    }

    /// The peer reports when probes arrived (its clock, `recv_us`). Each
    /// becomes a queueing-delay sample of the egress it left through.
    pub(super) fn on_report(&self, entries: &[(u32, u64)], now: Instant) {
        let mut book = self.book.lock().unwrap();
        for &(seq, recv_us) in entries {
            let Some(wire) = book.on_wire.remove(&seq) else {
                continue;
            };
            let raw = recv_us as i64 - wire.wire_us as i64;
            let base = book
                .bases
                .entry((wire.egress.scope().clone(), wire.remote))
                .or_default()
                .observe(wire.wire_us, raw);
            let queue = (raw - base).max(0) as u64;
            tracing::trace!(
                seq,
                wire_us = wire.wire_us,
                recv_us,
                raw,
                base,
                queue,
                remote = %wire.remote,
                "mpquic owd sample"
            );
            wire.egress.record_owd_queue_at(queue, now);
        }
    }

    /// Drop probes nobody reported.
    pub(super) fn expire(&self, now: Instant) {
        let mut book = self.book.lock().unwrap();
        book.queued
            .retain(|_, queued| now.saturating_duration_since(queued.at) < PROBE_EXPIRY);
        book.on_wire
            .retain(|_, wire| now.saturating_duration_since(wire.at) < PROBE_EXPIRY);
        self.queued_len.store(book.queued.len(), Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::egress_inventory::EgressStableId;
    use crate::common::egress_quality::{EgressQualityConfig, EgressQualityManager};
    use crate::common::transport_quality::{EgressDirection, EgressScope};

    fn handle(manager: &std::sync::Arc<EgressQualityManager>, ifindex: u32) -> EgressHandle {
        manager.handle_for(EgressScope {
            stable_id: EgressStableId::Linux {
                netns_inode: 1,
                ifindex,
            },
            direction: EgressDirection::Egress,
            generation: 1,
        })
    }

    /// The smallest one-way queueing delay reported since the last sample.
    fn drain(handle: &EgressHandle, now: Instant) -> Option<u64> {
        let published = handle.publish_at(1_000_000, None, now).unwrap();
        (published.source == crate::common::egress_quality::QueueDelaySource::OneWay)
            .then_some(published.queue_delay_us)
    }

    /// One probe, `delay_us` after it left (on the peer's clock, which runs
    /// `offset_us` ahead and gains `drift_ppm`), reported at once.
    fn probe(
        probes: &OwdProbes,
        egress: &EgressHandle,
        seq: u32,
        wire_us: u64,
        delay_us: i64,
        offset_us: i64,
        drift_ppm: f64,
    ) -> Option<u64> {
        let remote: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let now = Instant::now();
        probes.on_wire(seq, wire_us, egress.clone(), remote, now);
        let peer_clock = wire_us as f64 * (1.0 + drift_ppm * 1e-6);
        let recv_us = (peer_clock as i64 + offset_us + delay_us) as u64;
        probes.on_report(&[(seq, recv_us)], now);
        drain(egress, now)
    }

    /// OWD_AUTORATE_PLAN.md 2 (R4): a constant offset between the clocks and a
    /// crystal's drift are no queue; a real one is seen.
    #[tokio::test]
    async fn the_base_cancels_a_clock_offset_and_follows_drift() {
        let manager = EgressQualityManager::new(EgressQualityConfig::default());
        let egress = handle(&manager, 1);
        let probes = OwdProbes::new();
        let (offset, drift) = (-5_000_000, 50.0);
        // Until five minutes are in, there is no slope: the drift reads as
        // up to five minutes' worth of it (15 ms at 50 ppm).
        let (mut worst_early, mut worst_settled) = (0u64, 0u64);
        let mut last = 0;
        // One probe a second for ten minutes over a 20 ms link.
        for second in 0..600u32 {
            let queuing = probe(
                &probes,
                &egress,
                second,
                1_000_000 + second as u64 * 1_000_000,
                20_000,
                offset,
                drift,
            )
            .expect("a sample");
            if second >= 310 {
                worst_settled = worst_settled.max(queuing);
            } else {
                worst_early = worst_early.max(queuing);
            }
            last = queuing;
        }
        assert!(
            worst_early < 16_000,
            "early on, drift read as {worst_early} us of queue"
        );
        assert!(
            worst_settled < 5_000,
            "drift read as {worst_settled} us of queue"
        );
        assert!(last < 5_000, "{last} us of queue on an empty link");

        // 80 ms of queue appears.
        let queued = probe(&probes, &egress, 600, 601_000_000, 100_000, offset, drift).unwrap();
        assert!(queued >= 70_000, "an 80 ms queue was seen as {queued} us");
        assert!(queued <= 90_000, "an 80 ms queue was seen as {queued} us");
    }

    /// A minute of saturating traffic holds a queue for the whole minute, so
    /// its minimum is high. The slope from it to the newest minimum ran
    /// downwards, and every later minimum, carried to the present along it,
    /// read about 20 ms of queue on an empty link.
    #[tokio::test]
    async fn a_busy_minute_does_not_tilt_the_drift() {
        let manager = EgressQualityManager::new(EgressQualityConfig::default());
        let egress = handle(&manager, 3);
        let probes = OwdProbes::new();
        let mut worst = 0u64;
        for second in 0..600u32 {
            // 20 ms of queue through the first minute, none after.
            let queue = if second < 60 { 20_000 } else { 0 };
            let queuing = probe(
                &probes,
                &egress,
                second,
                1_000_000 + second as u64 * 1_000_000,
                20_000 + queue,
                -5_000_000,
                50.0,
            )
            .expect("a sample");
            if second >= 310 {
                worst = worst.max(queuing);
            }
        }
        assert!(
            worst < 5_000,
            "an empty link read as {worst} us of queue after one busy minute"
        );
    }

    /// The offset alone is not queue either, from the very first sample, and
    /// two paths of one egress do not share a base.
    #[tokio::test]
    async fn a_constant_offset_is_never_queue_and_paths_have_their_own_base() {
        let manager = EgressQualityManager::new(EgressQualityConfig::default());
        let egress = handle(&manager, 2);
        let probes = OwdProbes::new();
        let near: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let far: SocketAddr = "198.51.100.7:443".parse().unwrap();
        let now = Instant::now();
        for (seq, (remote, delay)) in [(near, 5_000), (far, 80_000), (near, 5_000), (far, 80_000)]
            .into_iter()
            .enumerate()
        {
            let wire = 1_000_000 * (seq as u64 + 1);
            probes.on_wire(seq as u32, wire, egress.clone(), remote, now);
            probes.on_report(
                &[(seq as u32, (wire as i64 + 123_456_789 + delay) as u64)],
                now,
            );
            assert_eq!(drain(&egress, now), Some(0), "probe {seq}");
        }
    }

    #[test]
    fn probes_are_sent_busy_every_100_ms_idle_every_second_and_never_unnegotiated() {
        let t0 = Instant::now();
        let mut schedule = ProbeSchedule::new();
        assert_eq!(schedule.poll(t0, false, Some(t0)), None, "not negotiated");
        assert_eq!(schedule.poll(t0, true, None), Some(0));
        assert_eq!(
            schedule.poll(t0 + Duration::from_millis(50), true, None),
            None
        );
        // Idle: a second.
        assert_eq!(
            schedule.poll(t0 + Duration::from_millis(900), true, None),
            None
        );
        assert_eq!(
            schedule.poll(t0 + Duration::from_millis(1_000), true, None),
            Some(1)
        );
        // Data in the last second: 100 ms.
        let t1 = t0 + Duration::from_millis(1_050);
        assert_eq!(schedule.poll(t1, true, Some(t1)), None);
        assert_eq!(
            schedule.poll(t0 + Duration::from_millis(1_100), true, Some(t1)),
            Some(2)
        );
        // ...and back to a second once data stopped for longer than that.
        let later = t0 + Duration::from_millis(5_000);
        assert_eq!(schedule.poll(later, true, Some(t1)), Some(3));
        assert_eq!(
            schedule.poll(later + Duration::from_millis(500), true, Some(t1)),
            None
        );
    }

    #[test]
    fn a_probe_flow_is_nonzero_distinct_and_claimed_once() {
        let probes = OwdProbes::new();
        assert_eq!(probes.claim(probe_flow(3)), None);
        let flows: std::collections::HashSet<_> = (0..10_000u32).map(probe_flow).collect();
        assert_eq!(flows.len(), 10_000);
        assert!(flows.iter().all(|flow| *flow != 0));
        probes.register(3, Instant::now());
        assert_eq!(probes.claim(probe_flow(4)), None);
        assert_eq!(probes.claim(probe_flow(3)), Some(3));
        assert_eq!(
            probes.claim(probe_flow(3)),
            None,
            "the packet is claimed once"
        );
    }
}

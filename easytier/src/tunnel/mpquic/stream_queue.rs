//! The pending frames of one reliable stream, controlled by COBALT
//! (CAKE_SQM_PLAN.md B5).
//!
//! Reliable-stream classes (TCP and proxy traffic by default) lose nothing in
//! QUIC: whatever CAKE drops on the egress is retransmitted, so the inner TCP
//! only sees delay. The place where that delay builds up is this queue, in
//! front of the stream. RFC 7567 §4.1/§4.2/§4.4 and RFC 3819 §13 ask for a
//! controlled drop decided by queueing time, not a tail drop when the buffer
//! is full, so the frames here go through the same COBALT (CoDel + BLUE) that
//! `sch_cake.c` runs per flow (`cake_sqm::Cobalt`), judged when a frame
//! leaves the queue for the QUIC stream. A dropped frame is an inner IP
//! packet: the inner TCP treats it as the congestion signal.
//!
//! Deviation from RFC 7567 §4.2.1: the inner packets are encrypted, so they
//! cannot be marked with ECN; dropping is the only signal.
//!
//! The queues of a session share one packet memory, sized and enforced as
//! CAKE's own (`enqueue`): COBALT holds the queues, and the memory only
//! catches what COBALT has not had time to act on. A per-stream limit of
//! 256 KiB with a tail drop used to sit below one CoDel interval of a LAN's
//! bursts, so it, not COBALT, dropped about 45% of a proxied transfer.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use cake_sqm::Cobalt;

/// CAKE's queue limit in packets (`sch->limit` default), which caps the memory
/// at that many MTUs.
const CAKE_PACKET_LIMIT: usize = 10_240;

/// The packet memory CAKE gives a queue of this rate (`cake_reconfigure`): four
/// intervals of data, at least 4 MiB, at most [`CAKE_PACKET_LIMIT`] MTUs.
pub(super) fn memory_limit(aqm: &StreamAqm) -> usize {
    let by_rate = (aqm.rate_bytes_per_sec as f64 * aqm.interval.as_secs_f64() * 4.0) as usize;
    by_rate
        .max(4 << 20)
        .min(CAKE_PACKET_LIMIT * aqm.mtu as usize)
}

/// Queues `frame` on `stream_id`, then holds the session's queues to
/// [`memory_limit`] as `cake_enqueue` does: the arriving frame is always
/// taken, and while the memory is over, the longest queue loses its head
/// (`cake_drop`), which also raises its BLUE drop probability.
pub(super) fn enqueue(
    queues: &mut HashMap<u64, StreamQueue>,
    stream_id: u64,
    frame: Bytes,
    now: Instant,
    aqm: &StreamAqm,
    drops: &mut StreamDrops,
) {
    queues
        .entry(stream_id)
        .or_insert_with(StreamQueue::new)
        .push(frame, now);
    let limit = memory_limit(aqm);
    let mut used = queues.values().map(StreamQueue::bytes).sum::<usize>();
    while used > limit {
        let Some(longest) = queues
            .values_mut()
            .filter(|queue| !queue.frames.is_empty())
            .max_by_key(|queue| queue.bytes())
        else {
            break;
        };
        used -= longest.drop_head(now, aqm);
        drops.overlimit += 1;
    }
    // The queue belongs to the stream, not to its current burst. Empty
    // queues retain COBALT's decay/history until the stream is retired.
}

/// What one write to the QUIC stream carries at most.
pub(super) const CHUNK: usize = 64 * 1024;

/// How much a stream may hold unsent in QUIC's own send buffer, as Linux's
/// `TCP_NOTSENT_LOWAT` limits a socket: the data the stream has not yet put on
/// the wire is invisible to COBALT, so it is kept to about two `target`s of
/// the egress's rate (at least three packets, at most [`CHUNK`]). The rest
/// waits in the queue, where COBALT judges it.
pub(super) fn notsent_lowat(aqm: &StreamAqm) -> usize {
    let by_rate = (aqm.rate_bytes_per_sec as f64 * 2.0 * aqm.target.as_secs_f64()) as usize;
    by_rate.clamp(3 * aqm.mtu as usize, CHUNK)
}

/// A rate that moved by this fraction gets new COBALT parameters.
const RETUNE_FRACTION: f64 = 0.25;

/// The egress the stream's session sends through, as COBALT needs to know it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct StreamAqm {
    pub(super) rate_bytes_per_sec: u64,
    pub(super) mtu: u32,
    pub(super) target: Duration,
    pub(super) interval: Duration,
}

impl StreamAqm {
    fn close_to(&self, other: &StreamAqm) -> bool {
        self.mtu == other.mtu
            && self.target == other.target
            && self.interval == other.interval
            && (self.rate_bytes_per_sec.abs_diff(other.rate_bytes_per_sec) as f64)
                < other.rate_bytes_per_sec as f64 * RETUNE_FRACTION
    }
}

/// Frames the queues dropped on purpose.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct StreamDrops {
    /// COBALT decided on the queueing time.
    pub(super) aqm: u64,
    /// The queue was over its limit.
    pub(super) overlimit: u64,
}

pub(super) struct StreamQueue {
    frames: VecDeque<(Bytes, Instant)>,
    /// The chunk handed out by `next_chunk`, of which the stream took part.
    partial: Option<Bytes>,
    bytes: usize,
    cobalt: Option<(Cobalt, StreamAqm)>,
}

impl StreamQueue {
    pub(super) fn new() -> Self {
        Self {
            frames: VecDeque::new(),
            partial: None,
            bytes: 0,
            cobalt: None,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.frames.is_empty() && self.partial.is_none()
    }

    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }

    fn push(&mut self, frame: Bytes, now: Instant) {
        self.bytes += frame.len();
        self.frames.push_back((frame, now));
    }

    /// Drops the oldest queued frame because the memory is full; returns its
    /// length. The chunk the stream already took part of is not a frame here.
    fn drop_head(&mut self, now: Instant, aqm: &StreamAqm) -> usize {
        let Some((frame, _)) = self.frames.pop_front() else {
            return 0;
        };
        self.bytes -= frame.len();
        if let Some(cobalt) = self.cobalt_for(aqm, now) {
            cobalt.queue_full(now);
        }
        frame.len()
    }

    fn cobalt_for(&mut self, aqm: &StreamAqm, now: Instant) -> Option<&mut Cobalt> {
        if let Some((cobalt, used)) = &mut self.cobalt
            && !aqm.close_to(used)
        {
            // New parameters, same CoDel/BLUE state (`Cobalt::set_rate`).
            if cobalt
                .set_rate(aqm.rate_bytes_per_sec, aqm.mtu, aqm.target, aqm.interval)
                .is_ok()
            {
                *used = *aqm;
            }
        }
        if self.cobalt.is_none() {
            let cobalt = Cobalt::new(
                aqm.rate_bytes_per_sec,
                aqm.mtu,
                aqm.target,
                aqm.interval,
                // Frames queued before the first judgement still need a sojourn.
                now.checked_sub(Duration::from_secs(3600)).unwrap_or(now),
            )
            .ok()?;
            self.cobalt = Some((cobalt, *aqm));
        }
        self.cobalt.as_mut().map(|(cobalt, _)| cobalt)
    }

    /// Part of a chunk the stream took is still to be written.
    pub(super) fn has_partial(&self) -> bool {
        self.partial.is_some()
    }

    /// The next bytes for the stream: the unfinished chunk, else the frames
    /// COBALT lets through, up to `limit` bytes (one frame at least). `None`
    /// when nothing is left.
    pub(super) fn next_chunk(
        &mut self,
        now: Instant,
        aqm: &StreamAqm,
        limit: usize,
        drops: &mut StreamDrops,
    ) -> Option<Bytes> {
        if let Some(partial) = &self.partial {
            return Some(partial.clone());
        }
        let limit = limit.min(CHUNK);
        let mut chunk = BytesMut::new();
        while let Some((frame, queued_at)) = self.frames.front() {
            if !chunk.is_empty() && chunk.len() + frame.len() > limit {
                break;
            }
            let (frame, queued_at) = (frame.clone(), *queued_at);
            self.frames.pop_front();
            // The last frame of a queue is never dropped (as in CAKE): the
            // queue is empty after it, so there is nothing standing.
            let last = self.frames.is_empty();
            // As in cake_dequeue, judge the last packet too so the state
            // sees it; only suppress the resulting drop decision.
            let drop = self
                .cobalt_for(aqm, now)
                .is_some_and(|cobalt| cobalt.should_drop(now, queued_at, 0))
                && !last;
            if drop {
                self.bytes -= frame.len();
                drops.aqm += 1;
            } else {
                chunk.extend_from_slice(&frame);
            }
        }
        if chunk.is_empty() {
            if let Some(cobalt) = self.cobalt_for(aqm, now) {
                cobalt.queue_empty(now);
            }
            return None;
        }
        let chunk = chunk.freeze();
        self.partial = Some(chunk.clone());
        Some(chunk)
    }

    /// The stream took `n` bytes of the chunk `next_chunk` returned.
    pub(super) fn written(&mut self, n: usize, now: Instant) {
        self.bytes -= n.min(self.bytes);
        self.partial = match self.partial.take() {
            Some(chunk) if n < chunk.len() => Some(chunk.slice(n..)),
            _ => None,
        };
        self.idle(now);
    }

    /// A drained stream keeps its flow's congestion state, but tells COBALT
    /// that no standing queue remains (CAKE's decaying-flow handling).
    pub(super) fn idle(&mut self, now: Instant) {
        if self.is_empty()
            && let Some((cobalt, _)) = self.cobalt.as_mut()
        {
            cobalt.queue_empty(now);
        }
    }

    /// The stream is gone: forget everything; returns the bytes dropped.
    pub(super) fn clear(&mut self) -> usize {
        self.frames.clear();
        self.partial = None;
        std::mem::take(&mut self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRAME: usize = 1200;

    fn aqm(rate_bytes_per_sec: u64) -> StreamAqm {
        StreamAqm {
            rate_bytes_per_sec,
            mtu: 1500,
            target: Duration::from_millis(5),
            interval: Duration::from_millis(100),
        }
    }

    struct Outcome {
        delivered: u64,
        backlog: usize,
        drops: StreamDrops,
        /// Wait at the end: what is queued here plus what the stream holds
        /// unsent, at the stream's rate.
        wait: Duration,
    }

    /// The wire takes `rate` bytes a second, the source offers `offered`
    /// bytes a second in frames of [`FRAME`] bytes, for `secs`. The stream is
    /// QUIC's: it accepts whatever is written and sends it at `rate`.
    fn run(rate: u64, offered: u64, secs: u64) -> Outcome {
        let t0 = Instant::now();
        let aqm = aqm(rate);
        let lowat = notsent_lowat(&aqm);
        let mut queues = HashMap::new();
        let mut drops = StreamDrops::default();
        let (mut delivered, mut unsent, mut credit, mut owed) = (0u64, 0usize, 0f64, 0f64);
        for ms in 0..secs * 1000 {
            let now = t0 + Duration::from_millis(ms);
            owed += offered as f64 / 1000.0;
            while owed >= FRAME as f64 {
                owed -= FRAME as f64;
                enqueue(
                    &mut queues,
                    4,
                    Bytes::from(vec![7u8; FRAME]),
                    now,
                    &aqm,
                    &mut drops,
                );
            }
            let queue = queues.entry(4).or_insert_with(StreamQueue::new);
            loop {
                let room = lowat.saturating_sub(unsent);
                if room == 0 && !queue.has_partial() {
                    break;
                }
                let Some(chunk) = queue.next_chunk(now, &aqm, room, &mut drops) else {
                    break;
                };
                queue.written(chunk.len(), now);
                unsent += chunk.len();
            }
            credit += rate as f64 / 1000.0;
            let sent = (credit as usize).min(unsent);
            credit -= sent as f64;
            unsent -= sent;
            delivered += sent as u64;
        }
        let backlog = queues.values().map(StreamQueue::bytes).sum::<usize>();
        Outcome {
            delivered,
            backlog,
            drops,
            wait: Duration::from_secs_f64((backlog + unsent) as f64 / rate as f64),
        }
    }

    /// Twice the rate offered for 20 s: the queue wait stays near CoDel's
    /// interval, controlled by drops decided on queueing time, and the memory
    /// limit is never what holds it.
    #[test]
    fn overload_is_held_to_a_short_wait_by_controlled_drops() {
        let out = run(125_000, 250_000, 20);
        assert!(out.drops.aqm > 0, "COBALT never dropped");
        assert_eq!(
            out.drops.overlimit, 0,
            "the limit, not COBALT, held the queue"
        );
        assert!(out.wait < Duration::from_millis(250), "wait {:?}", out.wait);
    }

    /// The AQM does not starve the stream: it still carries its full rate.
    #[test]
    fn the_stream_keeps_its_full_rate_under_overload() {
        let out = run(125_000, 250_000, 20);
        let full = 125_000u64 * 20;
        assert!(
            out.delivered as f64 > full as f64 * 0.95,
            "delivered {} of {full}",
            out.delivered
        );
    }

    /// At 40 kB/s (a slow link) the same holds: the last frame of a queue is
    /// never dropped and the wait stays bounded (A6's scenario).
    #[test]
    fn a_slow_stream_is_not_starved() {
        let out = run(40_000, 60_000, 30);
        assert!(
            out.delivered as f64 > 40_000.0 * 30.0 * 0.9,
            "delivered {}",
            out.delivered
        );
        assert!(
            out.wait < Duration::from_millis(500),
            "wait {:?} backlog {}",
            out.wait,
            out.backlog
        );
    }

    /// Offered below the rate nothing is dropped at all.
    #[test]
    fn an_underloaded_stream_loses_nothing() {
        let out = run(125_000, 80_000, 10);
        assert_eq!(out.drops, StreamDrops::default());
        assert!(out.delivered >= 80_000 * 10 - 2 * FRAME as u64);
    }

    /// CAKE's packet memory for the rate (`cake_reconfigure`).
    #[test]
    fn the_memory_is_cakes() {
        assert_eq!(
            memory_limit(&aqm(6_250_000)),
            4 << 20,
            "50 Mbit/s: the 4 MiB floor"
        );
        assert_eq!(
            memory_limit(&aqm(25_000_000)),
            10_000_000,
            "200 Mbit/s: four intervals"
        );
        assert_eq!(
            memory_limit(&aqm(125_000_000)),
            10_240 * 1500,
            "1 Gbit/s: the packet cap"
        );
    }

    /// On a LAN the inner sender's window arrives in a few milliseconds: a
    /// 1 MiB burst into a stream drained at 50 Mbit/s. The old 256 KiB per
    /// stream tail-dropped three quarters of it before COBALT could act.
    #[test]
    fn a_burst_within_cakes_memory_is_queued_whole() {
        let t0 = Instant::now();
        let aqm = aqm(6_250_000);
        let mut queues = HashMap::new();
        let mut drops = StreamDrops::default();
        for _ in 0..1024 {
            enqueue(
                &mut queues,
                4,
                Bytes::from(vec![0u8; 1024]),
                t0,
                &aqm,
                &mut drops,
            );
        }
        assert_eq!(drops, StreamDrops::default());
        assert_eq!(queues[&4].bytes(), 1 << 20);
    }

    /// Over the memory, the longest queue loses its oldest frames and a short
    /// queue loses nothing (CAKE's A11), each drop counted apart.
    #[test]
    fn over_the_memory_the_longest_queue_loses_its_head() {
        let t0 = Instant::now();
        let aqm = aqm(6_250_000);
        let limit = memory_limit(&aqm);
        let mut queues = HashMap::new();
        let mut drops = StreamDrops::default();
        for i in 0..5u8 {
            enqueue(
                &mut queues,
                8,
                Bytes::from(vec![i; 1000]),
                t0,
                &aqm,
                &mut drops,
            );
        }
        let flood = limit / 1000 + 100;
        for i in 0..flood {
            let frame = Bytes::from((i as u32).to_be_bytes().repeat(250));
            enqueue(&mut queues, 4, frame, t0, &aqm, &mut drops);
        }
        assert_eq!(drops.aqm, 0);
        assert!(drops.overlimit >= 100, "overlimit {}", drops.overlimit);
        assert_eq!(queues[&8].frames.len(), 5, "the short queue lost a frame");
        let total = queues.values().map(StreamQueue::bytes).sum::<usize>();
        assert!(total <= limit, "{total} over {limit}");
        let first = &queues[&4].frames.front().unwrap().0;
        assert_eq!(
            &first[..4],
            &(drops.overlimit as u32).to_be_bytes(),
            "not the head that went"
        );
        let last = &queues[&4].frames.back().unwrap().0;
        assert_eq!(
            &last[..4],
            &((flood - 1) as u32).to_be_bytes(),
            "the arriving frame was taken"
        );
    }

    /// A partly written chunk goes on where it stopped, whole frames are
    /// never cut by the AQM, and the byte count stays exact.
    #[test]
    fn a_partly_written_chunk_resumes_and_the_count_is_exact() {
        let t0 = Instant::now();
        let aqm = aqm(1_000_000);
        let mut queue = StreamQueue::new();
        let mut drops = StreamDrops::default();
        for i in 0..3u8 {
            queue.push(Bytes::from(vec![i; 100]), t0);
        }
        let chunk = queue.next_chunk(t0, &aqm, CHUNK, &mut drops).unwrap();
        assert_eq!(chunk.len(), 300);
        queue.written(150, t0);
        assert_eq!(queue.bytes(), 150);
        let rest = queue.next_chunk(t0, &aqm, CHUNK, &mut drops).unwrap();
        assert_eq!(rest.len(), 150);
        assert_eq!(rest[0], 1);
        queue.written(150, t0);
        assert!(queue.is_empty());
        assert_eq!(queue.bytes(), 0);
        assert!(queue.next_chunk(t0, &aqm, CHUNK, &mut drops).is_none());
    }

    /// CAKE keeps a flow's BLUE state when its packet queue drains. Serving
    /// another flow must not reset an overloaded flow to zero probability.
    #[test]
    fn an_empty_flow_keeps_its_congestion_history_across_other_flows() {
        let t0 = Instant::now();
        let aqm = aqm(1_000_000);
        let mut queues = HashMap::new();
        let mut drops = StreamDrops::default();
        enqueue(
            &mut queues,
            4,
            Bytes::from_static(b"seed"),
            t0,
            &aqm,
            &mut drops,
        );
        let now = t0 + Duration::from_secs(4);
        let queue = queues.get_mut(&4).unwrap();
        for i in 0..300u32 {
            queue
                .cobalt_for(&aqm, t0)
                .unwrap()
                .queue_full(t0 + aqm.target * 2 * (i + 1));
        }
        let last = queue.next_chunk(now, &aqm, CHUNK, &mut drops).unwrap();
        queue.written(last.len(), now);
        assert!(queue.is_empty());

        enqueue(
            &mut queues,
            8,
            Bytes::from_static(b"other"),
            now,
            &aqm,
            &mut drops,
        );
        for _ in 0..16 {
            enqueue(
                &mut queues,
                4,
                Bytes::from_static(b"fresh"),
                now,
                &aqm,
                &mut drops,
            );
        }
        let queue = queues.get_mut(&4).unwrap();
        let delivered = queue.next_chunk(now, &aqm, CHUNK, &mut drops).unwrap();
        assert!(
            drops.aqm >= 12,
            "an idle flow lost its BLUE history: {drops:?}"
        );
        assert!(
            delivered.len() <= 20,
            "fresh packets bypassed the existing congestion signal"
        );
    }
}

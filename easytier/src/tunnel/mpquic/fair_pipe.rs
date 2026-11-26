//! Fair queueing in front of the single QUIC stream of a session that has SQM
//! on and the data plane off (the default).
//!
//! Without the data plane every inner flow shares one QUIC stream, and the
//! frames reach it in the order the pipe delivers them, so one inner flow
//! that sends faster takes a larger part of the stream and the egress CAKE,
//! seeing only that one stream, cannot tell the flows apart. The frames wait
//! here, in the original `sch_cake.c` with the rate unlimited
//! (`pre_quic_cake`): per-flow queues served by deficit round robin with
//! sparse-flow priority, COBALT (CoDel and BLUE) per flow, a bounded memory,
//! and no delay for rate. The egress CAKE shapes as before.
//!
//! This is the one place a standing queue forms. The stream takes a frame
//! only while it holds less than the not-sent low-water mark unsent
//! (Linux's `TCP_NOTSENT_LOWAT` idea, as `stream_queue::notsent_lowat`
//! does for the data plane's streams), so the backlog is judged by COBALT
//! here and not hidden in QUIC's send buffer.
//!
//! The pipe carries the same framing as the data plane's
//! (`MpPipeZCPacketToBytes`): the inner flow hash behind each frame places
//! the frame in CAKE, and the driver strips tag and hash before the frame
//! reaches the stream, so the bytes on the wire are those of a session
//! without this queue. A frame without a flow hash (EasyTier's own control
//! and non-IP frames) has none for CAKE either, and they queue together as
//! one flow.

use std::time::Instant;

use bytes::{Bytes, BytesMut};

use super::pre_quic_cake::PreQuicCake;
use super::stream_queue::{CHUNK, StreamAqm, StreamDrops};
use crate::tunnel::mp_dataplane::FrameSplitter;

/// What the stream of the session offers the pump.
pub(super) trait StreamSink {
    /// Bytes written to the stream and not yet sent.
    fn unsent(&mut self) -> u64;
    /// Writes as much of `data` as the stream takes: `Some(n)` bytes were
    /// taken, `None` the stream is blocked (flow control).
    fn write(&mut self, data: &Bytes) -> Result<Option<usize>, String>;
}

pub(super) struct FairPipe {
    splitter: FrameSplitter,
    cake: PreQuicCake,
    /// The frame the stream took only part of, or none of.
    pending: Option<Bytes>,
}

impl FairPipe {
    pub(super) fn new(aqm: &StreamAqm, now: Instant) -> Result<Self, String> {
        Ok(Self {
            splitter: FrameSplitter::pipe(),
            cake: PreQuicCake::new(aqm, now)?,
            pending: None,
        })
    }

    /// Follows the egress's `target`, `interval` and MTU.
    pub(super) fn set_aqm(&mut self, aqm: &StreamAqm, now: Instant) {
        self.cake.set_aqm(aqm, now);
    }

    /// What CAKE dropped so far, COBALT's decisions apart from the memory
    /// limit's.
    pub(super) fn drops(&self) -> StreamDrops {
        self.cake.drops()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.pending.is_none() && self.cake.is_empty()
    }

    pub(super) fn backlog_bytes(&self) -> u64 {
        self.cake.backlog_bytes()
            + self.pending.as_ref().map_or(0, |pending| pending.len() as u64)
    }

    /// Takes bytes read from the pipe and queues every whole frame in them.
    /// An error means the framing is broken, which no later byte repairs.
    pub(super) fn push(&mut self, data: &[u8], now: Instant) -> Result<(), String> {
        self.splitter.push(data);
        while let Some(frame) = self.splitter.next_frame() {
            let frame = frame?;
            self.cake.enqueue(frame.frame.clone(), frame.flow(), now);
        }
        Ok(())
    }

    /// Hands the stream the frames CAKE lets go while it holds less than
    /// `lowat` unsent, as `stream_queue::next_chunk` does for a reliable stream:
    /// one chunk of whole frames of at least `min(room, CHUNK)` bytes (CAKE
    /// cannot look ahead, so the last frame may go over by one frame), written
    /// at once, not a write per frame. A chunk the stream took only part of is
    /// finished first.
    pub(super) fn pump(
        &mut self,
        sink: &mut dyn StreamSink,
        lowat: u64,
        now: Instant,
    ) -> Result<(), String> {
        loop {
            let chunk = match self.pending.take() {
                Some(chunk) => chunk,
                None => {
                    let room = lowat.saturating_sub(sink.unsent());
                    if room == 0 {
                        return Ok(());
                    }
                    let limit = usize::try_from(room).unwrap_or(usize::MAX).min(CHUNK);
                    let mut chunk = BytesMut::new();
                    while chunk.len() < limit {
                        let Some((frame, _)) = self.cake.dequeue(now) else {
                            break;
                        };
                        chunk.extend_from_slice(&frame);
                    }
                    if chunk.is_empty() {
                        return Ok(());
                    }
                    chunk.freeze()
                }
            };
            match sink.write(&chunk)? {
                Some(written) if written >= chunk.len() => {}
                Some(written) => {
                    self.pending = Some(chunk.slice(written..));
                    return Ok(());
                }
                None => {
                    self.pending = Some(chunk);
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::stream_queue::CHUNK;
    use std::time::Duration;
    use crate::tunnel::mp_dataplane::encode_pipe_len;
    use crate::tunnel::packet_def::PEER_MANAGER_HEADER_SIZE;

    const BODY: usize = 1200;
    /// The lowat the driver uses.
    const LOWAT: u64 = 32 * 1024;

    fn aqm() -> StreamAqm {
        StreamAqm {
            rate_bytes_per_sec: 0,
            mtu: 1500,
            target: Duration::from_millis(5),
            interval: Duration::from_millis(100),
        }
    }

    /// One frame as the ET end of the pipe writes it: tag in the length's
    /// upper byte, `flow` as the trailer. The body repeats `flow`'s low byte.
    fn pipe_frame(flow: u32, body: usize) -> Vec<u8> {
        let body_len = PEER_MANAGER_HEADER_SIZE + body;
        let mut frame = encode_pipe_len(body_len, 3).to_le_bytes().to_vec();
        frame.extend(vec![flow as u8; body_len]);
        frame.extend(flow.to_le_bytes());
        frame
    }

    /// A stream that sends `rate` bytes a second and takes `accept` bytes at
    /// most per write; what it took is kept to be split into frames again.
    struct SimStream {
        unsent: u64,
        max_unsent: u64,
        accept: usize,
        credit: f64,
        written: Vec<u8>,
        /// The length of every `write` call.
        writes: Vec<usize>,
    }

    impl SimStream {
        fn new(accept: usize) -> Self {
            Self {
                unsent: 0,
                max_unsent: 0,
                accept,
                credit: 0.0,
                written: Vec::new(),
                writes: Vec::new(),
            }
        }

        /// The wire takes `bytes` more.
        fn send(&mut self, bytes: f64) {
            self.credit += bytes;
            let sent = (self.credit as u64).min(self.unsent);
            self.credit -= sent as f64;
            self.unsent -= sent;
        }
    }

    impl StreamSink for SimStream {
        fn unsent(&mut self) -> u64 {
            self.unsent
        }

        fn write(&mut self, data: &Bytes) -> Result<Option<usize>, String> {
            let taken = data.len().min(self.accept);
            self.writes.push(data.len());
            self.written.extend_from_slice(&data[..taken]);
            self.unsent += taken as u64;
            self.max_unsent = self.max_unsent.max(self.unsent);
            Ok(Some(taken))
        }
    }

    /// The first body byte of each whole frame the stream got.
    fn frames_written(stream: &SimStream) -> Vec<(u8, usize)> {
        let mut splitter = FrameSplitter::default();
        splitter.push(&stream.written);
        let mut frames = Vec::new();
        while let Some(frame) = splitter.next_frame() {
            let frame = frame.unwrap();
            // After the length header comes the EasyTier header, whose
            // first byte the test fills with the flow's low byte.
            frames.push((frame.frame[4], frame.frame.len()));
        }
        frames
    }

    /// Flow `a` offered `a_per_ms` frames and flow `b` `b_per_ms` frames
    /// every millisecond (as a fraction, spread evenly), the stream sends
    /// `rate` bytes a second, for `ms` milliseconds.
    fn run(a: (u32, f64), b: (u32, f64), rate: u64, ms: u64) -> (FairPipe, SimStream) {
        let t0 = Instant::now();
        let mut pipe = FairPipe::new(&aqm(), t0).unwrap();
        let mut stream = SimStream::new(usize::MAX);
        let mut owed = [0.0f64; 2];
        let mut wrote_before_last_half = 0;
        for step in 0..ms {
            let now = t0 + Duration::from_millis(step);
            owed[0] += a.1;
            owed[1] += b.1;
            for (index, flow) in [a.0, b.0].into_iter().enumerate() {
                while owed[index] >= 1.0 {
                    owed[index] -= 1.0;
                    pipe.push(&pipe_frame(flow, BODY), now).unwrap();
                }
            }
            pipe.pump(&mut stream, LOWAT, now).unwrap();
            stream.send(rate as f64 / 1000.0);
            if step == ms / 2 {
                wrote_before_last_half = stream.written.len();
            }
        }
        // Only the second half counts: COBALT needs an interval to act.
        stream.written.drain(..wrote_before_last_half);
        (pipe, stream)
    }

    /// The share of the bytes the stream got that belongs to flow `a`.
    fn share_of(stream: &SimStream, flow: u32) -> f64 {
        // The first half was cut at a byte, not a frame boundary: skip to the
        // first whole frame by splitting from the first length header.
        let frames = frames_written_from_boundary(stream);
        let total: usize = frames.iter().map(|(_, len)| len).sum();
        let of_flow: usize = frames
            .iter()
            .filter(|(first, _)| *first == flow as u8)
            .map(|(_, len)| len)
            .sum();
        of_flow as f64 / total as f64
    }

    fn frames_written_from_boundary(stream: &SimStream) -> Vec<(u8, usize)> {
        let frame_len = 4 + PEER_MANAGER_HEADER_SIZE + BODY;
        // Every frame has the same length, so resynchronise on that.
        let start = (frame_len - stream.written.len() % frame_len) % frame_len;
        let mut shifted = SimStream::new(usize::MAX);
        shifted.written = stream.written[start..].to_vec();
        frames_written(&shifted)
    }

    /// Two inner flows, one offered three times the rate of the other, the
    /// stream the bottleneck: each gets half of it, as the flow isolation of
    /// CAKE does. A first-in first-out queue gives them 3:1.
    #[test]
    fn two_flows_share_the_stream_evenly_when_one_offers_three_times_the_other() {
        let rate = 1_250_000u64; // 10 Mbit/s
        let per_ms = rate as f64 / 1000.0 / (4 + PEER_MANAGER_HEADER_SIZE + BODY) as f64;
        // A offers 2.25 times the rate, B 0.75 times: 3:1, three times over.
        let (_pipe, stream) = run((1, per_ms * 2.25), (2, per_ms * 0.75), rate, 10_000);
        let a = share_of(&stream, 1);
        assert!((0.4..=0.6).contains(&a), "flow a got {a:.3} of the stream");
    }

    /// The backlog is in CAKE, where COBALT judges it, and not in the
    /// stream: it never holds more than the low-water mark and a frame.
    #[test]
    fn the_standing_queue_is_in_cake_and_the_stream_holds_at_most_the_lowat() {
        let rate = 1_250_000u64;
        let per_ms = rate as f64 / 1000.0 / (4 + PEER_MANAGER_HEADER_SIZE + BODY) as f64;
        let (pipe, stream) = run((1, per_ms * 1.5), (2, per_ms * 1.5), rate, 3_000);
        let frame = (4 + PEER_MANAGER_HEADER_SIZE + BODY) as u64;
        assert!(
            stream.max_unsent <= LOWAT + frame,
            "the stream held {} unsent",
            stream.max_unsent
        );
        assert!(pipe.backlog_bytes() > 0, "overload must queue in CAKE");
        assert!(pipe.drops().aqm > 0, "COBALT never dropped");
        assert_eq!(pipe.drops().overlimit, 0, "the memory limit, not COBALT, held the queue");
    }

    /// Frames reach the stream whole, in a flow's order, with tag and hash
    /// stripped, and without a flow hash too. Frames without a hash all queue
    /// as one flow, so their order is kept.
    #[test]
    fn frames_reach_the_stream_stripped_and_in_order() {
        let t0 = Instant::now();
        let mut pipe = FairPipe::new(&aqm(), t0).unwrap();
        let mut stream = SimStream::new(usize::MAX);
        let mut expected = Vec::new();
        for (flow, body) in [(0u32, 100), (0, 300), (7, 200), (0, 50), (7, 400)] {
            pipe.push(&pipe_frame(flow, body), t0).unwrap();
            let mut wire = ((PEER_MANAGER_HEADER_SIZE + body) as u32).to_le_bytes().to_vec();
            wire.extend(vec![flow as u8; PEER_MANAGER_HEADER_SIZE + body]);
            expected.push((flow, wire));
        }
        pipe.pump(&mut stream, LOWAT, t0).unwrap();
        assert!(pipe.is_empty());
        let written = stream.written.clone();
        // Walk the stream: whole frames, no trailer left.
        let mut at = 0;
        let mut got = Vec::new();
        while at < written.len() {
            let len = u32::from_le_bytes(written[at..at + 4].try_into().unwrap()) as usize;
            got.push(written[at..at + 4 + len].to_vec());
            at += 4 + len;
        }
        assert_eq!(at, written.len());
        for flow in [0u32, 7] {
            let of_flow = |frames: &mut dyn Iterator<Item = &Vec<u8>>| {
                frames.map(|frame| frame.clone()).collect::<Vec<_>>()
            };
            let want = of_flow(
                &mut expected
                    .iter()
                    .filter(|(f, _)| *f == flow)
                    .map(|(_, wire)| wire),
            );
            let have = of_flow(&mut got.iter().filter(|frame| frame[4] == flow as u8));
            assert_eq!(have, want, "flow {flow} changed or reordered");
        }
    }

    /// A stream that takes a few bytes at a time gets every frame whole in the
    /// end, the unfinished one first.
    #[test]
    fn a_partly_written_frame_resumes_where_it_stopped() {
        let t0 = Instant::now();
        let mut pipe = FairPipe::new(&aqm(), t0).unwrap();
        let mut stream = SimStream::new(100);
        for flow in [1u32, 2, 1, 2] {
            pipe.push(&pipe_frame(flow, 500), t0).unwrap();
        }
        // The sim stream takes 100 bytes of each frame handed to it and
        // reports that; the pump keeps the rest and offers it again.
        let mut rounds = 0;
        while !pipe.is_empty() {
            pipe.pump(&mut stream, u64::MAX, t0).unwrap();
            rounds += 1;
            assert!(rounds < 1000, "the pump made no progress");
        }
        let frames = frames_written(&stream);
        assert_eq!(frames.len(), 4);
        assert!(frames.iter().all(|(_, len)| *len == 4 + PEER_MANAGER_HEADER_SIZE + 500));
    }

    /// With a backlog the pump hands the stream one chunk of frames, as
    /// `stream_queue::next_chunk` does, not one write per frame: a chunk of at
    /// least `min(room, CHUNK)` bytes and at most one frame more.
    #[test]
    fn a_backlog_is_written_in_one_chunk_not_frame_by_frame() {
        let t0 = Instant::now();
        let mut pipe = FairPipe::new(&aqm(), t0).unwrap();
        let mut stream = SimStream::new(usize::MAX);
        for i in 0..200u32 {
            pipe.push(&pipe_frame(1 + i % 4, BODY), t0).unwrap();
        }
        pipe.pump(&mut stream, LOWAT, t0).unwrap();
        let frame = 4 + PEER_MANAGER_HEADER_SIZE + BODY;
        let want = (LOWAT as usize).min(CHUNK);
        assert_eq!(stream.writes.len(), 1, "writes {:?}", stream.writes);
        assert!(
            (want..=want + frame).contains(&stream.writes[0]),
            "chunk {} not in {want}..={}",
            stream.writes[0],
            want + frame
        );
        // Frames stay whole in the chunk.
        assert_eq!(stream.writes[0] % frame, 0);
    }

    /// A chunk the stream took only part of is finished first, whole frames
    /// and order intact.
    #[test]
    fn a_partly_written_chunk_goes_on_where_it_stopped() {
        let t0 = Instant::now();
        let mut pipe = FairPipe::new(&aqm(), t0).unwrap();
        let mut stream = SimStream::new(1000);
        for i in 0..20u32 {
            pipe.push(&pipe_frame(1 + i % 3, 300), t0).unwrap();
        }
        let mut rounds = 0;
        while !pipe.is_empty() {
            pipe.pump(&mut stream, u64::MAX, t0).unwrap();
            rounds += 1;
            assert!(rounds < 1000, "the pump made no progress");
        }
        let mut splitter = FrameSplitter::default();
        splitter.push(&stream.written);
        let mut count = 0;
        while let Some(frame) = splitter.next_frame() {
            assert_eq!(frame.unwrap().frame.len(), 4 + PEER_MANAGER_HEADER_SIZE + 300);
            count += 1;
        }
        assert_eq!(count, 20);
    }

    /// Bytes that are not whole frames wait; a broken length is an error.
    #[test]
    fn a_frame_split_across_reads_is_queued_once_it_is_whole() {
        let t0 = Instant::now();
        let mut pipe = FairPipe::new(&aqm(), t0).unwrap();
        let frame = pipe_frame(9, 300);
        pipe.push(&frame[..100], t0).unwrap();
        assert!(pipe.is_empty());
        pipe.push(&frame[100..], t0).unwrap();
        assert!(!pipe.is_empty());
        let mut bad = FairPipe::new(&aqm(), t0).unwrap();
        // A body shorter than the EasyTier header cannot be a frame.
        assert!(bad.push(&[2, 0, 0, 0, 1, 1], t0).is_err());
    }
}

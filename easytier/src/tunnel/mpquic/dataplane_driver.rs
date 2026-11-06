//! MP_SQM_PLAN.md S2.10/S2.11: the driver half of the datagram data plane.
//!
//! Only sessions built with the data plane on (`MpQuicSessionConfig::
//! data_plane`) use this; every other session keeps the historical
//! single-stream pump in `drive()` unchanged. Everything engine-free
//! (classes, codec, fragmentation, negotiation, counters) lives in
//! `tunnel::mp_dataplane`; this file only moves whole EasyTier frames
//! between the ET pipe and one TQUIC `Connection`.
//!
//! Streams: the client's first stream (`CLIENT_PRIMARY_STREAM`) carries
//! every stream-bound frame of a session that is not on the datagram plane,
//! exactly like a legacy session, so a legacy peer on either side still
//! works. `reliable_stream` classes get their own streams on top. Every
//! stream is read, and only whole frames ever reach the ET pipe, so frames
//! from different streams and datagrams interleave safely.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;

use super::owd::{OwdProbes, ProbeSchedule, probe_flow};
use super::pre_quic_cake::PreQuicCake;
use super::stream_queue::{self, StreamAqm, StreamDrops, StreamQueue, notsent_lowat};
use crate::proto::api::instance::MpDataPlaneStatus;
use crate::tunnel::mp_dataplane::{
    ClassMode, DataPlaneCounters, DataPlanePolicy, DataPlaneStatusInput, Datagram, FrameSplitter,
    Negotiated, OWD_REPORT_MAX_ENTRIES, OversizePolicy, PipeFrame, Reassembler, ReliableStreams,
    fragment, is_whole_frame, negotiate, status,
};

/// The stream a client opens first. Its FIN ends the session on both
/// sides, as the single stream of a legacy session does.
pub(super) const CLIENT_PRIMARY_STREAM: u64 = 0;
/// COBALT parameters before the first shaping rate is known: 100 Mbit/s.
const DEFAULT_AQM_RATE: u64 = 12_500_000;
const HOUSEKEEPING_INTERVAL: Duration = Duration::from_secs(1);
const READ_CHUNK: usize = 64 * 1024;

pub(super) struct DataPlaneDriver {
    policy: Arc<DataPlanePolicy>,
    peer_caps: Option<u32>,
    negotiated: Negotiated,
    /// Where stream-bound frames go: the client's own first stream; on the
    /// server the client's first stream once seen (a legacy client reads
    /// only that one), else a stream of its own.
    primary: Option<u64>,
    outbound: FrameSplitter,
    /// Frames waiting for stream credit, per stream, each queue under COBALT
    /// (`stream_queue`). The driver always reads the ET pipe: datagram
    /// classes must not wait behind a stream (RFC 9484 §10).
    // One queue/state per live outgoing stream, including while it is
    // empty. Retired streams release their state after their FIN is sent.
    stream_queues: HashMap<u64, StreamQueue>,
    /// The egress this session sends through, for COBALT's parameters.
    aqm: StreamAqm,
    /// The datagram classes' frames wait here per inner flow, under COBALT,
    /// while QUIC holds `DGRAM_NOTSENT_LOWAT` unsent (`pre_quic_cake`).
    dgram_queue: PreQuicCake,
    /// Frames the stream queues dropped on purpose, since the session began.
    drops: StreamDrops,
    /// Reaped reliable streams, finished once their queue drains.
    finishing: HashSet<u64>,
    reliable: ReliableStreams,
    inbound: HashMap<u64, FrameSplitter>,
    reassembler: Reassembler,
    counters: DataPlaneCounters,
    next_packet_id: u32,
    last_housekeeping: Instant,
    read_buf: Vec<u8>,
    /// One-way delay probing (OWD_AUTORATE_PLAN.md 1.1): shared with this
    /// session's `DatagramSender`, which marks the packets that carry probes.
    probes: Arc<OwdProbes>,
    probe_schedule: ProbeSchedule,
    /// When the ET pipe last gave this session a frame: the link is busy.
    last_data_at: Option<Instant>,
    /// Probes that arrived and are not yet reported: (seq, `owd_clock_us`).
    arrived: Vec<(u32, u64)>,
}

pub(super) struct Inbound {
    pub(super) frames: Vec<Bytes>,
    /// The peer finished `CLIENT_PRIMARY_STREAM`: the session is over.
    pub(super) primary_finished: bool,
    /// This bounded read left work to revisit after application delivery.
    pub(super) more: bool,
}

/// Queues a datagram, telling TQUIC which inner flow it belongs to (if any), so
/// that the egress queue below can isolate flows.
fn send_datagram(
    conn: &mut tquic::Connection,
    data: Bytes,
    flow: Option<u32>,
) -> Result<(), tquic::SendDatagramError> {
    match flow {
        Some(flow) => conn.dgram_send_with_flow(data, true, flow),
        None => conn.dgram_send(data, true),
    }
}

impl DataPlaneDriver {
    pub(super) fn new(
        policy: Arc<DataPlanePolicy>,
        now: Instant,
        probes: Arc<OwdProbes>,
    ) -> Self {
        let aqm = StreamAqm {
            rate_bytes_per_sec: DEFAULT_AQM_RATE,
            mtu: 1500,
            target: Duration::from_millis(5),
            interval: Duration::from_millis(100),
        };
        Self {
            reliable: ReliableStreams::new(policy.reliable_stream_max, policy.reliable_stream_idle),
            policy,
            peer_caps: None,
            negotiated: Negotiated::Disabled("connection not established".into()),
            primary: None,
            outbound: FrameSplitter::pipe(),
            stream_queues: HashMap::new(),
            dgram_queue: PreQuicCake::new(&aqm, now)
                .expect("cake accepts a valid configuration"),
            aqm,
            drops: StreamDrops::default(),
            finishing: HashSet::new(),
            inbound: HashMap::new(),
            reassembler: Reassembler::default(),
            counters: DataPlaneCounters::default(),
            next_packet_id: 0,
            last_housekeeping: now,
            read_buf: vec![0u8; READ_CHUNK],
            probes,
            probe_schedule: ProbeSchedule::new(),
            last_data_at: None,
            arrived: Vec::new(),
        }
    }

    /// The first call wins: a later stream never replaces the primary.
    pub(super) fn set_primary(&mut self, stream_id: u64) {
        self.primary.get_or_insert(stream_id);
    }

    /// Server side: the client's first stream appeared. It becomes the
    /// primary even if the server already opened one of its own, because a
    /// legacy client reads nothing else.
    pub(super) fn adopt_client_primary(&mut self) {
        self.primary = Some(CLIENT_PRIMARY_STREAM);
    }

    pub(super) fn set_policy(&mut self, policy: Arc<DataPlanePolicy>, peer_caps: Option<u32>) {
        self.reliable
            .set_limits(policy.reliable_stream_max, policy.reliable_stream_idle);
        self.policy = policy;
        self.peer_caps = peer_caps;
    }

    /// The egress's current shaping rate and CAKE timing, which COBALT on the
    /// stream queues takes its parameters from.
    pub(super) fn set_aqm(&mut self, aqm: StreamAqm, now: Instant) {
        self.dgram_queue.set_aqm(&aqm, now);
        self.aqm = aqm;
    }

    /// Frames dropped on purpose since the session began.
    pub(super) fn stream_drops(&self) -> StreamDrops {
        self.drops
    }

    /// Datagram frames the queue in front of QUIC dropped on purpose.
    pub(super) fn dgram_drops(&self) -> StreamDrops {
        self.dgram_queue.drops()
    }

    pub(super) fn push_outbound(&mut self, data: &[u8]) {
        self.outbound.push(data);
    }

    /// Redo negotiation.
    pub(super) fn refresh(&mut self, conn: &mut tquic::Connection) {
        self.negotiated = negotiate(
            self.policy.enabled,
            self.peer_caps,
            conn.dgram_max_writable_len(),
        );
    }

    /// Route every whole frame read from the ET pipe so far.
    pub(super) fn route_outbound(
        &mut self,
        conn: &mut tquic::Connection,
        now: Instant,
    ) -> Result<(), String> {
        self.refresh(conn);
        while let Some(frame) = self.outbound.next_frame() {
            let frame = frame.map_err(|error| format!("ET pipe framing: {error}"))?;
            self.route_frame(conn, frame, now);
        }
        Ok(())
    }

    fn route_frame(&mut self, conn: &mut tquic::Connection, frame: PipeFrame, now: Instant) {
        let class = frame.class();
        let len = frame.frame.len();
        self.counters.on_tx(class, len);
        self.last_data_at = Some(now);
        if !matches!(self.negotiated, Negotiated::Datagram { .. }) {
            return self.queue_primary(conn, frame.frame, now);
        }
        match self.policy.mode_for(class) {
            ClassMode::ReliableStream => {
                let flow = (class.tag(), frame.bucket());
                match self
                    .reliable
                    .stream_for(flow, now, || conn.stream_bidi_new(0, true).ok())
                {
                    Some(stream_id) => self.queue(stream_id, frame.frame, now),
                    None => self.queue_primary(conn, frame.frame, now),
                }
            }
            // Queued per inner flow in front of QUIC; `flush_datagrams` sends
            // it (whole, fragmented or dropped) once QUIC has room.
            ClassMode::Datagram => {
                let flow = frame.flow();
                self.dgram_queue.enqueue(frame.frame, flow, now);
            }
        }
    }

    /// Sends the datagram frames that wait in front of QUIC while QUIC holds
    /// less than `DGRAM_NOTSENT_LOWAT` unsent: the backlog waits where COBALT
    /// judges it, not in QUIC's drop-oldest queue (RFC 9221 section 5.4)
    /// nor, as it did, back in the pipe.
    pub(super) fn flush_datagrams(&mut self, conn: &mut tquic::Connection, now: Instant) {
        while let Some((frame, flow)) = self.dgram_queue.dequeue_below(
            conn.dgram_send_queue_bytes(),
            super::DGRAM_NOTSENT_LOWAT,
            now,
        ) {
            self.send_queued_datagram(conn, frame, flow, now);
        }
    }

    /// Frames wait in front of QUIC and QUIC has room again: the driver must
    /// run `flush_datagrams` without waiting for an event. QUIC's queue
    /// empties when `process_connections` puts packets on the wire, after the
    /// turn's flush.
    pub(super) fn datagrams_ready(&self, conn: &tquic::Connection) -> bool {
        !self.dgram_queue.is_empty() && conn.dgram_send_queue_bytes() < super::DGRAM_NOTSENT_LOWAT
    }

    /// The datagram branch of the data plane, run when the frame leaves the
    /// queue, since the datagram size limit can change while it waited.
    fn send_queued_datagram(
        &mut self,
        conn: &mut tquic::Connection,
        frame: Bytes,
        flow: Option<u32>,
        now: Instant,
    ) {
        let Negotiated::Datagram { caps } = self.negotiated else {
            // Fell back to streams while the frame waited.
            return self.queue_primary(conn, frame, now);
        };
        let len = frame.len();
        let max = conn.dgram_max_writable_len().unwrap_or(0);
        if len + Datagram::WHOLE_OVERHEAD <= max
            && send_datagram(conn, Datagram::Whole(frame.clone()).encode(), flow).is_ok()
        {
            return;
        }
        if self.policy.oversize.restricted_to(caps) == OversizePolicy::Fragment {
            let packet_id = self.next_packet_id;
            self.next_packet_id = packet_id.wrapping_add(1);
            if let Some(pieces) = fragment(&frame, packet_id, max) {
                let count = pieces.len() as u64;
                // A piece refused midway loses the packet, like any
                // lost fragment.
                if pieces
                    .into_iter()
                    .all(|piece| send_datagram(conn, piece.encode(), flow).is_ok())
                {
                    self.counters.frag_sent += count;
                    return;
                }
            }
        }
        // RFC 9484 Section 10.1: a packet that does not fit is dropped,
        // never moved to a stream (it would pin the flow there and
        // queue behind the stream's retransmissions). `icmp_ptb` tells
        // the sender in `PeerManager`; what reaches here is what it
        // could not answer (non-IP, or no limit known yet).
        self.counters.oversize_dropped += 1;
    }

    /// Whether `stream_id` still holds data the peer has not acknowledged.
    fn in_flight(
        queues: &HashMap<u64, StreamQueue>,
        conn: &mut tquic::Connection,
        stream_id: u64,
    ) -> bool {
        Self::has_queued_frames(queues, stream_id)
            || conn.stream_unacked_bytes(stream_id).is_some_and(|bytes| bytes > 0)
    }

    fn has_queued_frames(queues: &HashMap<u64, StreamQueue>, stream_id: u64) -> bool {
        queues.get(&stream_id).is_some_and(|queue| !queue.is_empty())
    }

    fn queue_primary(&mut self, conn: &mut tquic::Connection, frame: Bytes, now: Instant) {
        let stream_id = match self.primary {
            Some(stream_id) => stream_id,
            None => match conn.stream_bidi_new(0, true) {
                Ok(stream_id) => *self.primary.insert(stream_id),
                Err(error) => {
                    tracing::debug!(?error, "mpquic data plane: no stream for a frame, dropped");
                    return;
                }
            },
        };
        self.queue(stream_id, frame, now);
    }

    fn queue(&mut self, stream_id: u64, frame: Bytes, now: Instant) {
        stream_queue::enqueue(&mut self.stream_queues, stream_id, frame, now, &self.aqm, &mut self.drops);
    }

    /// Hand queued stream bytes to QUIC as flow control allows. COBALT judges
    /// each frame as it leaves its queue (`stream_queue`).
    pub(super) fn flush(&mut self, conn: &mut tquic::Connection, now: Instant) -> Result<(), String> {
        let primary = self.primary;
        let aqm = self.aqm;
        let mut dead = Vec::new();
        let lowat = notsent_lowat(&aqm);
        for (&stream_id, queue) in self.stream_queues.iter_mut() {
            if queue.is_empty() {
                queue.idle(now);
                continue;
            }
            loop {
                // Keep what QUIC holds unsent small: the rest waits here,
                // where COBALT can judge it.
                let unsent = conn.stream_unsent_bytes(stream_id).unwrap_or(0) as usize;
                let room = lowat.saturating_sub(unsent);
                if room == 0 && !queue.has_partial() {
                    break;
                }
                let Some(chunk) = queue.next_chunk(now, &aqm, room, &mut self.drops) else {
                    break;
                };
                match conn.stream_write(stream_id, chunk.clone(), false) {
                    Ok(written) => {
                        queue.written(written, now);
                        if written < chunk.len() {
                            break;
                        }
                    }
                    Err(tquic::Error::Done) => break,
                    Err(error) if Some(stream_id) == primary => {
                        return Err(format!("stream_write: {error}"));
                    }
                    Err(error) => {
                        tracing::debug!(stream_id, ?error, "mpquic data plane: reliable stream gone");
                        dead.push(stream_id);
                        break;
                    }
                }
            }
        }
        for stream_id in dead {
            self.stream_queues.remove(&stream_id);
        }
        let drained = self
            .finishing
            .iter()
            .copied()
            .filter(|stream_id| !Self::has_queued_frames(&self.stream_queues, *stream_id))
            .collect::<Vec<_>>();
        for stream_id in drained {
            let _ = conn.stream_write(stream_id, Bytes::new(), true);
            self.finishing.remove(&stream_id);
            self.stream_queues.remove(&stream_id);
        }
        Ok(())
    }

    /// Whole frames received on any stream or as datagrams.
    pub(super) fn inbound(
        &mut self,
        conn: &mut tquic::Connection,
        now: Instant,
    ) -> Result<Inbound, String> {
        let mut out = Inbound {
            frames: Vec::new(),
            primary_finished: false,
            more: false,
        };
        let mut stream_bytes = 0;
        let mut frame_bytes = 0;
        let readable = conn.stream_readable_iter().collect::<Vec<u64>>();
        'streams: for stream_id in readable {
            loop {
                if stream_bytes >= READ_CHUNK || frame_bytes >= READ_CHUNK {
                    out.more = true;
                    break 'streams;
                }
                match conn.stream_read(stream_id, &mut self.read_buf[..READ_CHUNK - stream_bytes]) {
                    Ok((n, fin)) => {
                        stream_bytes += n;
                        let splitter = self.inbound.entry(stream_id).or_default();
                        splitter.push(&self.read_buf[..n]);
                        while let Some(frame) = splitter.next_frame() {
                            let frame = frame
                                .map_err(|error| format!("stream {stream_id} framing: {error}"))?;
                            self.counters.on_rx(frame.class(), frame.frame.len());
                            frame_bytes += frame.frame.len();
                            out.frames.push(frame.frame);
                        }
                        if fin {
                            self.inbound.remove(&stream_id);
                            if stream_id == CLIENT_PRIMARY_STREAM {
                                out.primary_finished = true;
                                return Ok(out);
                            }
                            // A bidi stream is only freed (and its MAX_STREAMS
                            // credit returned) once both directions are
                            // finished. The peer's reliable streams carry data
                            // one way only: finish our unused side, or every
                            // recycled stream stays open on both ends until
                            // the stream limit runs out. A stream this end
                            // finished first already has its FIN; the repeat
                            // is refused harmlessly.
                            if !Self::has_queued_frames(&self.stream_queues, stream_id) {
                                let _ = conn.stream_write(stream_id, Bytes::new(), true);
                            }
                            break;
                        }
                        if n == 0 {
                            break;
                        }
                    }
                    Err(tquic::Error::Done) => break,
                    Err(error) if stream_id == CLIENT_PRIMARY_STREAM => {
                        return Err(format!("stream_read: {error}"));
                    }
                    Err(error) => {
                        tracing::debug!(stream_id, ?error, "mpquic data plane: reliable stream reset");
                        self.inbound.remove(&stream_id);
                        break;
                    }
                }
            }
        }
        // Give datagrams their own budget: a continuously readable reliable
        // stream must not starve them. Both malformed and control datagrams
        // count toward the work budget even when they yield no application data.
        let mut datagram_bytes = 0;
        for index in 0..32 {
            let Some((data, received_at)) = conn.dgram_recv_with_timestamp() else { break };
            if index == 31 {
                out.more = true;
            }
            let frame = match Datagram::decode(&data) {
                Some(Datagram::OwdProbe { seq }) => {
                    // Application delivery may have been backpressured. Use
                    // the carrier receive timestamp, not the time of this read.
                    if let Some(received_at) = received_at {
                        self.arrived.push((seq, received_at));
                    }
                    continue;
                }
                Some(Datagram::OwdReport { entries }) => {
                    self.probes.on_report(&entries, now);
                    continue;
                }
                Some(Datagram::Whole(frame)) => frame,
                Some(Datagram::Fragment {
                    packet_id,
                    index,
                    count,
                    chunk,
                }) => match self.reassembler.add(packet_id, index, count, chunk, now) {
                    Some(frame) => {
                        self.counters.frag_reassembled += 1;
                        frame
                    }
                    None => continue,
                },
                None => {
                    tracing::trace!(len = data.len(), "mpquic data plane: reserved or malformed datagram dropped");
                    continue;
                }
            };
            if !is_whole_frame(&frame) {
                tracing::debug!(len = frame.len(), "mpquic data plane: datagram is not one whole frame, dropped");
                continue;
            }
            let class = PipeFrame {
                frame: frame.clone(),
                tag: 0,
                flow_hash: 0,
            }
            .class();
            self.counters.on_rx(class, frame.len());
            datagram_bytes += frame.len();
            out.frames.push(frame);
            if datagram_bytes >= READ_CHUNK {
                out.more = true;
                break;
            }
        }
        Ok(out)
    }

    /// OWD_AUTORATE_PLAN.md 1.1: send the probe that is due, and report the
    /// probes that arrived. A probe goes only to a peer that negotiated
    /// `CAP_OWD_PROBE`; a report is the answer to a probe, which only such a
    /// peer sends.
    pub(super) fn owd_tick(&mut self, conn: &mut tquic::Connection, now: Instant) {
        let enabled = self.negotiated.owd_probe();
        if let Some(seq) = self.probe_schedule.poll(now, enabled, self.last_data_at) {
            self.probes.register(seq, now);
            if conn
                .dgram_send_measurement(
                    Datagram::OwdProbe { seq }.encode(),
                    true,
                    Some(probe_flow(seq)),
                )
                .is_err()
            {
                self.probes.cancel(seq);
            }
        }
        if self.arrived.is_empty() {
            return;
        }
        // A report that does not fit one datagram leaves the rest for the
        // next turn; a backlog older than the senders' expiry is useless.
        const BACKLOG: usize = 4 * OWD_REPORT_MAX_ENTRIES;
        if self.arrived.len() > BACKLOG {
            self.arrived.drain(..self.arrived.len() - BACKLOG);
        }
        let max = conn.dgram_max_writable_len().unwrap_or(0);
        const ENTRY: usize = Datagram::owd_report_len(1) - Datagram::owd_report_len(0);
        let fit = max.saturating_sub(Datagram::owd_report_len(0)) / ENTRY;
        let count = fit.min(OWD_REPORT_MAX_ENTRIES).min(self.arrived.len());
        if count == 0 {
            return;
        }
        let entries = self.arrived.drain(..count).collect();
        // Refused: the probes' senders expire them. A report is no inner
        // flow: it queues with the session's own packets, and like a probe it
        // is not held back by the congestion window or the breaker.
        let _ = conn.dgram_send_measurement(Datagram::OwdReport { entries }.encode(), true, None);
    }

    /// When `owd_tick` next has a probe to send.
    pub(super) fn next_owd_wake(&self) -> Option<Instant> {
        self.probe_schedule
            .next_wake(self.negotiated.owd_probe(), self.last_data_at)
    }

    /// Reassembly timeouts and idle reliable streams, once a second.
    pub(super) fn housekeeping(&mut self, conn: &mut tquic::Connection, now: Instant) {
        if now.saturating_duration_since(self.last_housekeeping) < HOUSEKEEPING_INTERVAL {
            return;
        }
        self.last_housekeeping = now;
        self.probes.expire(now);
        self.counters.frag_timeout += self.reassembler.expire(now) as u64;
        let queues = &self.stream_queues;
        let reaped = self
            .reliable
            .reap_idle(now, |stream_id| Self::in_flight(queues, conn, stream_id));
        self.finishing.extend(reaped);
    }

    /// The ET pipe closed: finish the primary stream and close the
    /// connection so a peer without that stream in use also learns of it.
    pub(super) fn close(&mut self, conn: &mut tquic::Connection) {
        if let Some(primary) = self.primary {
            let _ = conn.stream_write(primary, Bytes::new(), true);
        }
        let _ = conn.close(true, 0, b"easytier pipe closed");
    }

    pub(super) fn status(&self, conn: Option<&tquic::Connection>) -> MpDataPlaneStatus {
        let stats = conn.map(|conn| conn.dgram_stats()).unwrap_or_default();
        status(DataPlaneStatusInput {
            policy: &self.policy,
            negotiated: &self.negotiated,
            max_datagram: conn.and_then(|conn| conn.dgram_max_writable_len()),
            counters: &self.counters,
            open_streams: &|class| self.reliable.open_count_for(class.tag()),
            streams_recycled: self.reliable.recycled,
            dgram_queue_dropped: stats.dropped_outgoing,
            circuit_breaker_trips: stats.bypass_trips,
            stream_aqm_drops: self.drops.aqm,
            stream_overlimit_drops: self.drops.overlimit,
            dgram_aqm_drops: self.dgram_queue.drops().aqm,
            dgram_overlimit_drops: self.dgram_queue.drops().overlimit,
        })
    }
}

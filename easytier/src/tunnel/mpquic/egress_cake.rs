//! One Linux CAKE queue per egress, shared by every mpquic session that sends
//! through it (CAKE_SQM_PLAN.md B3).
//!
//! The queue is the original `sch_cake.c` (`cake-sqm`), one instance per
//! physical NIC, as Linux attaches one qdisc per interface -- never one per
//! peer, per session or per public address behind the NIC. Every packet TQUIC sends is queued
//! here with its length on the wire and the outer UDP addresses; the inner
//! flow TQUIC took the packet from (`PacketSendMeta::flow_hash`, the
//! WireGuard approach) isolates flows inside the one outer tuple. CAKE shapes
//! to the egress's Autorate estimate ([`GovernedCarrier::shaping_rate`]) and
//! signals congestion by dropping or delaying packets, which TQUIC's loss
//! recovery turns into a smaller congestion window.
//!
//! There is no dequeue task. Each driver runs on its own thread and runtime
//! and can end at any time, so every driver with packets in a queue drains
//! it ([`EgressCake::pump`]) whenever it runs and wakes again at the queue's
//! next send time.
//!
//! The wait in the queue is counted in QUIC's round trips (a packet is
//! timestamped when TQUIC sends it to us), which are Autorate's delay signal:
//! every released packet reports its sojourn to the egress
//! (`EgressHandle::record_queue_delay`), and Autorate takes it out again, or
//! an enforced rate would cut itself down. The one-way delay probes
//! (`owd`) need no such correction: they are stamped when they leave this
//! queue (`pump`), not when they enter it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use cake_sqm::{
    Cake, CakeConfig, CakeStats, Dequeued, Diffserv, FlowMode, PacketHeader, PacketMeta,
};
use tokio::sync::mpsc;

use crate::common::egress_quality::EgressHandle;
use crate::proto::api::instance::MpCakeStatus;
use crate::tunnel::datagram_carrier::GovernedCarrier;

use super::PathReceiverEvent;
use super::governed_sender::{CarrierId, on_send_error};
use super::owd::{OwdProbes, owd_clock_us};
use super::stream_queue::{StreamAqm, StreamDrops};

/// The CAKE queue of `egress`, if any packet has used the egress yet.
pub(crate) fn cake_status(egress: &EgressHandle) -> Option<MpCakeStatus> {
    egress.attached_if_present::<EgressCake>().map(|queue| queue.status())
}

/// The egress `carrier` leaves through, as the reliable-stream queues of its
/// session need it: COBALT takes the same rate and timing as the CAKE queue.
pub(super) fn stream_aqm(carrier: &GovernedCarrier) -> StreamAqm {
    let (target, interval) = carrier.bottleneck().cake_timing();
    StreamAqm {
        rate_bytes_per_sec: EgressCake::rate_of(carrier),
        mtu: carrier.mtu() as u32,
        target,
        interval,
    }
}

/// Adds the stream-queue drops of a session on `carrier` to its egress.
pub(super) fn report_stream_drops(carrier: &GovernedCarrier, drops: StreamDrops) {
    if drops != StreamDrops::default() {
        EgressCake::of(carrier).add_stream_drops(drops);
    }
}

/// Retry after the socket's send buffer was full.
const SOCKET_FULL_RETRY: Duration = Duration::from_millis(1);

/// Never shape below 8 kbit/s: CAKE reads a rate of 0 as unlimited, and a
/// paused egress must not become the opposite.
const MIN_RATE_BYTES_PER_SEC: u64 = 1_000;

/// Re-tune CAKE only when the rate moved by at least this fraction.
const RETUNE_FRACTION: f64 = 0.02;

fn cake_config(bytes_per_sec: u64, mtu: u32, (target, rtt): (Duration, Duration)) -> CakeConfig {
    CakeConfig {
        bandwidth: bytes_per_sec,
        rtt,
        target,
        mtu,
        // Lengths are passed in wire bytes, so CAKE adds no overhead of its own.
        overhead: None,
        diffserv: Diffserv::BestEffort,
        flow_mode: FlowMode::Triple,
        // CAKE's own packet memory (4 MB at least). A smaller one overflows
        // under one responsive session's bursts, and every overflow raises
        // BLUE's random drop probability until the queue next runs empty.
        memory_limit: None,
        ..CakeConfig::default()
    }
}

pub(super) struct QueuedPacket {
    /// Weak: a carrier retired while its packets wait drops them.
    pub(super) carrier: Weak<GovernedCarrier>,
    pub(super) id: CarrierId,
    pub(super) buf: Vec<u8>,
    /// Its length on the wire, which CAKE shapes by and the path's queued
    /// bytes (`EgressCake::queued_bytes`) count.
    pub(super) wire_bytes: u64,
    pub(super) local: SocketAddr,
    pub(super) remote: SocketAddr,
    pub(super) event_tx: mpsc::UnboundedSender<PathReceiverEvent>,
    /// The packet carries a one-way delay probe (OWD_AUTORATE_PLAN.md 1.1):
    /// its session's probes and its sequence number. The time it leaves for
    /// the wire, not the time it was queued, is when the probe is sent.
    pub(super) probe: Option<(Arc<OwdProbes>, u32)>,
}

/// Frames the reliable-stream queues of the sessions on this egress dropped
/// on purpose (`stream_queue`), kept beside the CAKE queue they feed.
#[derive(Default)]
struct StreamDropCounters {
    aqm: std::sync::atomic::AtomicU64,
    overlimit: std::sync::atomic::AtomicU64,
}

struct Inner {
    cake: Cake<QueuedPacket>,
    /// Taken off `cake` but the socket was full; goes first.
    head: Option<QueuedPacket>,
    rate_bytes_per_sec: u64,
    timing: (Duration, Duration),
    mtu: u32,
    /// Wire bytes waiting per path (local and remote address), in `cake` or
    /// at `head`: added when a packet is queued, taken off when it is sent,
    /// dropped by CAKE, or dropped from the head.
    queued: HashMap<(SocketAddr, SocketAddr), u64>,
}

impl Inner {
    fn add_queued(&mut self, packet: &QueuedPacket) {
        *self.queued.entry((packet.local, packet.remote)).or_default() += packet.wire_bytes;
    }

    fn sub_queued(&mut self, packet: &QueuedPacket) {
        let key = (packet.local, packet.remote);
        if let Some(bytes) = self.queued.get_mut(&key) {
            *bytes = bytes.saturating_sub(packet.wire_bytes);
            if *bytes == 0 {
                self.queued.remove(&key);
            }
        }
    }

    /// Packets CAKE dropped for its own reasons (AQM, overlimit): they are no
    /// longer queued.
    fn forget_dropped(&mut self, dropped: Vec<QueuedPacket>) {
        for packet in &dropped {
            self.sub_queued(packet);
        }
    }
}

pub(super) struct EgressCake {
    inner: Mutex<Inner>,
    stream_drops: StreamDropCounters,
}

impl EgressCake {
    fn new(rate_bytes_per_sec: u64, mtu: u32, timing: (Duration, Duration)) -> Self {
        // `pump`'s wake-ups are CAKE's watchdog; a late one counts as sojourn.
        #[cfg(windows)]
        crate::arch::windows::raise_timer_resolution();
        let cake = Cake::new(&cake_config(rate_bytes_per_sec, mtu, timing), Instant::now())
            .expect("cake accepts a valid configuration");
        Self {
            inner: Mutex::new(Inner {
                cake,
                head: None,
                rate_bytes_per_sec,
                timing,
                mtu,
                queued: HashMap::new(),
            }),
            stream_drops: StreamDropCounters::default(),
        }
    }

    /// The queue of `carrier`'s bottleneck egress.
    pub(super) fn of(carrier: &GovernedCarrier) -> Arc<EgressCake> {
        let rate = Self::rate_of(carrier);
        let mtu = carrier.mtu() as u32;
        carrier
            .bottleneck()
            .attached(|| EgressCake::new(rate, mtu, carrier.bottleneck().cake_timing()))
            .expect("only the mpquic egress queue is attached to an egress")
    }

    pub(super) fn rate_of(carrier: &GovernedCarrier) -> u64 {
        (carrier.shaping_rate().0 / 8).max(MIN_RATE_BYTES_PER_SEC)
    }

    /// Follow the egress's current shaping rate and `target`/`interval`.
    fn follow(inner: &mut Inner, carrier: &GovernedCarrier, now: Instant) {
        let rate = Self::rate_of(carrier);
        let timing = carrier.bottleneck().cake_timing();
        let moved = rate.abs_diff(inner.rate_bytes_per_sec) as f64;
        if moved < inner.rate_bytes_per_sec as f64 * RETUNE_FRACTION && timing == inner.timing {
            return;
        }
        let cfg = cake_config(rate, inner.mtu, timing);
        if inner.cake.reconfigure(&cfg, now).is_ok() {
            inner.rate_bytes_per_sec = rate;
            inner.timing = timing;
        }
    }

    /// A session on this egress dropped frames in its reliable-stream queues.
    pub(super) fn add_stream_drops(&self, drops: StreamDrops) {
        use std::sync::atomic::Ordering::Relaxed;
        self.stream_drops.aqm.fetch_add(drops.aqm, Relaxed);
        self.stream_drops.overlimit.fetch_add(drops.overlimit, Relaxed);
    }

    pub(super) fn is_empty(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.head.is_none() && inner.cake.is_empty()
    }

    /// The queue as `tc -s qdisc show` would print it.
    fn status(&self) -> MpCakeStatus {
        let inner = self.inner.lock().unwrap();
        let stats: CakeStats = inner.cake.stats();
        let tin = stats.tins.first().copied().unwrap_or_default();
        MpCakeStatus {
            bandwidth_bps: inner.rate_bytes_per_sec.saturating_mul(8),
            target_us: tin.target_us,
            interval_us: tin.interval_us,
            qlen_packets: stats.qlen,
            backlog_bytes: stats.backlog as u64,
            memory_used: stats.memory_now,
            memory_peak: stats.memory_used,
            memory_limit: stats.memory_limit,
            sent_packets: stats.dequeued_packets,
            sent_bytes: stats.dequeued_bytes,
            dropped_packets: tin.dropped_packets as u64,
            overlimit_drops: tin.drop_overlimit as u64,
            peak_delay_us: tin.peak_delay_us,
            avg_delay_us: tin.avg_delay_us,
            base_delay_us: tin.base_delay_us,
            sparse_flows: tin.sparse_flows,
            bulk_flows: tin.bulk_flows,
            unresponsive_flows: tin.unresponsive_flows,
            way_collisions: tin.way_collisions,
            stream_aqm_drops: self.stream_drops.aqm.load(std::sync::atomic::Ordering::Relaxed),
            stream_overlimit_drops: self
                .stream_drops
                .overlimit
                .load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Queue `packet`. `flow_hash` is the inner flow it belongs to, when
    /// TQUIC knows one.
    pub(super) fn enqueue(
        &self,
        carrier: &GovernedCarrier,
        flow_hash: Option<u32>,
        packet: QueuedPacket,
    ) {
        // A probe's flow hash only marks its packet (`OwdProbes::claim`); it
        // is no inner flow. It queues with its path's own packets, in order:
        // as a flow of its own it would overtake them, and the peer's
        // acknowledgment of it would have QUIC declare them lost.
        let flow_hash = if packet.probe.is_some() { None } else { flow_hash };
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        Self::follow(&mut inner, carrier, now);
        let meta = PacketMeta {
            len: packet.wire_bytes.min(u32::MAX as u64) as u32,
            header: PacketHeader::Udp {
                src: packet.local,
                dst: packet.remote,
                dscp: 0,
            },
            flow_hash,
            mark: 0,
        };
        inner.add_queued(&packet);
        // Dropped packets are counted by CAKE itself (`status`); QUIC sees a loss.
        let dropped = inner.cake.enqueue(meta, packet, now);
        inner.forget_dropped(dropped);
    }

    /// Wire bytes of the path (`local`, `remote`) waiting in this queue.
    pub(super) fn queued_bytes(&self, local: SocketAddr, remote: SocketAddr) -> u64 {
        let inner = self.inner.lock().unwrap();
        inner.queued.get(&(local, remote)).copied().unwrap_or(0)
    }

    /// When the queue may next send, for a driver that holds data back until
    /// it does. `None` when nothing waits.
    pub(super) fn next_send(&self) -> Option<Instant> {
        let inner = self.inner.lock().unwrap();
        if inner.head.is_some() {
            Some(Instant::now() + SOCKET_FULL_RETRY)
        } else {
            inner.cake.next_wake()
        }
    }

    /// Sends what CAKE releases. `Some(at)` when packets are left: the next
    /// send can happen at `at`.
    pub(super) fn pump(&self) -> Option<Instant> {
        let mut inner = self.inner.lock().unwrap();
        loop {
            let now = Instant::now();
            let packet = match inner.head.take() {
                Some(packet) => packet,
                None => match inner.cake.dequeue(now) {
                    Dequeued::Packet { item, sojourn } => {
                        let dropped = inner.cake.take_dropped();
                        inner.forget_dropped(dropped);
                        if let Some(carrier) = item.carrier.upgrade() {
                            // Autorate must not read this wait as the link's queue.
                            carrier.bottleneck().record_queue_delay(sojourn);
                        }
                        item
                    }
                    Dequeued::NotBefore(at) => {
                        let dropped = inner.cake.take_dropped();
                        inner.forget_dropped(dropped);
                        return Some(at);
                    }
                    Dequeued::Empty => {
                        let dropped = inner.cake.take_dropped();
                        inner.forget_dropped(dropped);
                        return None;
                    }
                },
            };
            let Some(carrier) = packet.carrier.upgrade() else {
                inner.sub_queued(&packet);
                continue;
            };
            Self::follow(&mut inner, &carrier, now);
            // A probe's wire time is when it leaves this queue: the wait in
            // the queue is ours and no part of the link's delay
            // (OWD_AUTORATE_PLAN.md 1.1). It is read before the socket has
            // the packet, so a stall in the send is delay and cannot make a
            // sample read low (`owd::Base` keeps the lowest).
            let wire_us = packet.probe.as_ref().and_then(|_| owd_clock_us());
            match carrier.send_dequeued(&packet.buf, packet.remote) {
                Ok(_) => {
                    inner.sub_queued(&packet);
                    if let (Some((probes, seq)), Some(wire_us)) = (&packet.probe, wire_us) {
                        probes.on_wire(
                            *seq,
                            wire_us,
                            carrier.bottleneck(),
                            packet.remote,
                            Instant::now(),
                        );
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    inner.head = Some(packet);
                    return Some(now + SOCKET_FULL_RETRY);
                }
                Err(e) => {
                    inner.sub_queued(&packet);
                    on_send_error(&e, packet.id, packet.local, packet.remote, &packet.event_tx);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::egress_inventory::EgressStableId;
    use crate::common::egress_quality::{EgressQualityConfig, EgressQualityManager};
    use crate::common::transport_quality::rate::WireBitrate;
    use crate::common::transport_quality::{EgressDirection, EgressScope};
    use crate::tunnel::datagram_carrier::DatagramCarrier;

    struct Recording {
        local: SocketAddr,
        sent: Mutex<Vec<u8>>,
        /// `owd_clock_us()` at each send, in order.
        sent_us: Mutex<Vec<u64>>,
        full: std::sync::atomic::AtomicBool,
        /// How long a send takes to return after the packet left.
        stall_us: std::sync::atomic::AtomicU64,
    }

    #[async_trait::async_trait]
    impl DatagramCarrier for Recording {
        fn local_addr(&self) -> SocketAddr {
            self.local
        }
        fn try_send_to(&self, payload: &[u8], _remote: SocketAddr) -> std::io::Result<usize> {
            if self.full.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            self.sent.lock().unwrap().push(payload[0]);
            self.sent_us.lock().unwrap().push(owd_clock_us().expect("measurement clock"));
            let stall = self.stall_us.load(std::sync::atomic::Ordering::SeqCst);
            if stall > 0 {
                std::thread::sleep(Duration::from_micros(stall));
            }
            Ok(payload.len())
        }
        async fn recv_from(&self, _buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
        fn per_packet_overhead(&self, _remote: SocketAddr) -> u64 {
            0
        }
    }

    struct Rig {
        raw: Arc<Recording>,
        carrier: Arc<GovernedCarrier>,
        queue: Arc<EgressCake>,
        remote: SocketAddr,
        event_tx: mpsc::UnboundedSender<PathReceiverEvent>,
        _rx: mpsc::UnboundedReceiver<PathReceiverEvent>,
        _manager: Arc<EgressQualityManager>,
    }

    fn rig(ifindex: u32, bits_per_sec: u64) -> Rig {
        let manager = EgressQualityManager::new(EgressQualityConfig::default());
        let handle = manager.handle_for(EgressScope {
            stable_id: EgressStableId::Linux {
                netns_inode: 1,
                ifindex,
            },
            direction: EgressDirection::Egress,
            generation: 1,
        });
        handle.set_budget(Some(WireBitrate(bits_per_sec))).unwrap();
        let raw = Arc::new(Recording {
            local: "10.0.0.1:4000".parse().unwrap(),
            sent: Mutex::new(Vec::new()),
            sent_us: Mutex::new(Vec::new()),
            full: Default::default(),
            stall_us: Default::default(),
        });
        let carrier = Arc::new(GovernedCarrier::new(raw.clone(), handle));
        let queue = EgressCake::of(&carrier);
        let (event_tx, rx) = mpsc::unbounded_channel();
        Rig {
            raw,
            carrier,
            queue,
            remote: "203.0.113.9:443".parse().unwrap(),
            event_tx,
            _rx: rx,
            _manager: manager,
        }
    }

    impl Rig {
        fn push(&self, marker: u8, len: usize, flow: Option<u32>) {
            self.push_with(marker, len, flow, None);
        }

        fn push_with(
            &self,
            marker: u8,
            len: usize,
            flow: Option<u32>,
            probe: Option<(Arc<OwdProbes>, u32)>,
        ) {
            let mut buf = vec![0u8; len];
            buf[0] = marker;
            self.queue.enqueue(
                &self.carrier,
                flow,
                QueuedPacket {
                    carrier: Arc::downgrade(&self.carrier),
                    id: CarrierId(1),
                    buf,
                    wire_bytes: len as u64,
                    local: self.raw.local,
                    remote: self.remote,
                    event_tx: self.event_tx.clone(),
                    probe,
                },
            );
        }

        fn sent(&self) -> Vec<u8> {
            self.raw.sent.lock().unwrap().clone()
        }

        /// Pumps until the queue is empty or `limit` passed.
        async fn drain(&self, limit: Duration) -> Duration {
            let start = Instant::now();
            while start.elapsed() < limit {
                match self.queue.pump() {
                    None => break,
                    Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                }
            }
            start.elapsed()
        }
    }

    /// OWD_AUTORATE_PLAN.md 1.1 (R5): a probe's send time is when it leaves
    /// the queue, so the wait in our own queue is no part of the one-way delay
    /// it measures.
    #[tokio::test]
    async fn a_probes_wait_in_our_queue_is_not_counted() {
        use crate::common::egress_quality::QueueDelaySource;
        use crate::tunnel::mpquic::owd::probe_flow;

        const OFFSET_US: u64 = 10_000_000;
        const LINK_US: u64 = 3_000;
        // 5 kB/s: one 1500 B packet takes 300 ms.
        let rig = rig(11, 40_000);
        let egress = rig.carrier.bottleneck();
        let probes = Arc::new(OwdProbes::new());
        let probe = |seq: u32| Some((probes.clone(), seq));

        // The first probe finds the queue empty and leaves at once.
        probes.register(0, Instant::now());
        assert_eq!(probes.claim(probe_flow(0)), Some(0));
        rig.push_with(100, 100, Some(probe_flow(0)), probe(0));
        rig.queue.pump();
        // A bulk packet leaves; CAKE then holds everything for its 300 ms.
        rig.push(1, 1_500, Some(7));
        rig.push(2, 1_500, Some(7));
        loop {
            let next = rig.queue.pump();
            if rig.sent().contains(&1) {
                break;
            }
            tokio::time::sleep_until(tokio::time::Instant::from_std(next.unwrap())).await;
        }
        // The second probe waits for the shaper.
        let queued_us = owd_clock_us().expect("measurement clock");
        probes.register(1, Instant::now());
        assert_eq!(probes.claim(probe_flow(1)), Some(1));
        rig.push_with(101, 100, Some(probe_flow(1)), probe(1));
        rig.drain(Duration::from_secs(3)).await;

        let sent = rig.sent();
        let sent_us = rig.raw.sent_us.lock().unwrap().clone();
        let at = |marker: u8| sent_us[sent.iter().position(|&m| m == marker).expect("sent")];
        let waited = at(101) - queued_us;
        assert!(
            waited >= 150_000,
            "the probe was meant to wait in the queue, waited {waited} us (sent {sent:?} at {:?} us after the probe was queued)",
            sent_us
                .iter()
                .map(|us| *us as i64 - queued_us as i64)
                .collect::<Vec<_>>()
        );

        // The peer's clock runs OFFSET_US ahead; the link takes LINK_US both times.
        let now = Instant::now();
        probes.on_report(&[(0, at(100) + OFFSET_US + LINK_US)], now);
        let first = egress.publish_at(1_000_000, None, now).unwrap();
        assert_eq!(first.source, QueueDelaySource::OneWay);
        probes.on_report(&[(1, at(101) + OFFSET_US + LINK_US)], now);
        let second = egress.publish_at(1_000_000, None, now).unwrap();
        assert_eq!(second.source, QueueDelaySource::OneWay);
        assert!(
            second.queue_delay_us < 20_000,
            "our own {waited} us of queue was counted as {} us of link queue",
            second.queue_delay_us
        );
    }

    /// A send that returns late (the socket call stalls, or the thread loses
    /// the CPU after it) must not make a probe read less delay than it had:
    /// the base keeps the lowest sample, so one that read 30 ms low stood as
    /// 30 ms of queue on an empty link for the whole history.
    #[tokio::test]
    async fn a_stalled_send_does_not_read_as_less_delay() {
        use crate::common::egress_quality::QueueDelaySource;
        use crate::tunnel::mpquic::owd::probe_flow;

        const OFFSET_US: u64 = 10_000_000;
        const LINK_US: u64 = 3_000;
        let rig = rig(13, 8_000_000);
        let egress = rig.carrier.bottleneck();
        let probes = Arc::new(OwdProbes::new());
        let mut queue_delay = Vec::new();
        for seq in 0..3u32 {
            // The second send returns 30 ms after its packet left.
            let stall = if seq == 1 { 30_000 } else { 0 };
            rig.raw
                .stall_us
                .store(stall, std::sync::atomic::Ordering::SeqCst);
            probes.register(seq, Instant::now());
            assert_eq!(probes.claim(probe_flow(seq)), Some(seq));
            let marker = 100 + seq as u8;
            rig.push_with(marker, 100, Some(probe_flow(seq)), Some((probes.clone(), seq)));
            rig.drain(Duration::from_secs(1)).await;
            let sent = rig.sent();
            let left = rig.raw.sent_us.lock().unwrap()
                [sent.iter().position(|&m| m == marker).expect("sent")];
            let now = Instant::now();
            probes.on_report(&[(seq, left + OFFSET_US + LINK_US)], now);
            let published = egress.publish_at(1_000_000, None, now).unwrap();
            assert_eq!(published.source, QueueDelaySource::OneWay);
            queue_delay.push(published.queue_delay_us);
        }
        assert!(
            queue_delay[2] < 5_000,
            "after a stalled send, an empty link read as {queue_delay:?} us of queue"
        );
    }

    /// Two carriers of one egress share one queue; another egress has its own.
    #[tokio::test]
    async fn one_queue_per_egress() {
        let a = rig(1, 8_000_000);
        let again = EgressCake::of(&a.carrier);
        assert!(Arc::ptr_eq(&a.queue, &again));
        let b = rig(2, 8_000_000);
        assert!(!Arc::ptr_eq(&a.queue, &b.queue));
    }

    /// The queue paces to the shaping rate: 5 x 1000 B at 100 kB/s (800 kbit/s)
    /// takes about 50 ms, not an instant burst. (A longer burst would be
    /// dropped from, by design: CAKE drops a flow whose packets wait more
    /// than four packet times.)
    #[tokio::test]
    async fn releases_packets_at_the_shaping_rate() {
        let rig = rig(3, 800_000);
        for i in 0..5u8 {
            rig.push(i, 1_000, Some(7));
        }
        let first = rig.queue.pump();
        assert!(first.is_some(), "a backlog must leave a wake-up time");
        assert!(rig.sent().len() < 4, "no instant burst, sent {}", rig.sent().len());
        let took = rig.drain(Duration::from_secs(3)).await;
        assert_eq!(rig.sent(), vec![0, 1, 2, 3, 4], "nothing lost, in order");
        assert!(took >= Duration::from_millis(25), "paced, took {took:?}");
        assert!(took <= Duration::from_millis(250), "not slower than the rate, took {took:?}");
        assert!(rig.queue.is_empty());
    }

    /// A sparse flow is served ahead of another flow's backlog: that is what
    /// CAKE's per-flow queueing is for, and the inner flow hash is what tells
    /// the flows apart inside one outer UDP tuple.
    #[tokio::test]
    async fn a_sparse_flow_overtakes_a_bulk_flows_backlog() {
        let rig = rig(4, 800_000);
        for i in 0..30u8 {
            rig.push(i, 1_000, Some(1));
        }
        rig.push(200, 100, Some(2));
        rig.drain(Duration::from_secs(3)).await;
        let sent = rig.sent();
        let position = sent.iter().position(|&m| m == 200).expect("sparse packet sent");
        assert!(position < 5, "the sparse flow waited behind {position} bulk packets");
    }

    /// Without an inner flow hash packets of one outer tuple stay in order.
    #[tokio::test]
    async fn packets_of_one_flow_keep_their_order() {
        let rig = rig(5, 800_000);
        for i in 0..10u8 {
            rig.push(i, 400, None);
        }
        rig.drain(Duration::from_secs(3)).await;
        assert_eq!(rig.sent(), (0..10u8).collect::<Vec<_>>());
    }

    /// A probe leaves after the packets of its path queued before it: the
    /// trace of 2026-10-14 had each probe, a new sparse flow, overtake them,
    /// and QUIC declare them lost when the peer acknowledged the probe first.
    #[tokio::test]
    async fn a_probe_does_not_overtake_its_paths_packets() {
        use crate::tunnel::mpquic::owd::probe_flow;

        let rig = rig(12, 800_000);
        let probes = Arc::new(OwdProbes::new());
        for i in 0..10u8 {
            rig.push(i, 400, None);
        }
        probes.register(0, Instant::now());
        assert_eq!(probes.claim(probe_flow(0)), Some(0));
        rig.push_with(100, 100, Some(probe_flow(0)), Some((probes.clone(), 0)));
        rig.drain(Duration::from_secs(3)).await;
        let mut expected: Vec<u8> = (0..10u8).collect();
        expected.push(100);
        assert_eq!(rig.sent(), expected);
    }

    /// A full socket buffer keeps the packet at the head, nothing is lost or
    /// reordered, and the retry comes soon.
    #[tokio::test]
    async fn a_full_socket_holds_the_head_and_retries() {
        let rig = rig(6, 80_000_000);
        for i in 0..3u8 {
            rig.push(i, 500, None);
        }
        rig.raw.full.store(true, std::sync::atomic::Ordering::SeqCst);
        let retry = rig.queue.pump().expect("a blocked head must be retried");
        assert!(retry <= Instant::now() + Duration::from_millis(5));
        assert!(rig.sent().is_empty());
        rig.raw.full.store(false, std::sync::atomic::Ordering::SeqCst);
        rig.drain(Duration::from_secs(1)).await;
        assert_eq!(rig.sent(), vec![0, 1, 2]);
    }

    /// The shaping rate follows the egress's budget while packets wait.
    #[tokio::test]
    async fn a_new_budget_changes_the_pace() {
        let rig = rig(7, 400_000);
        for i in 0..6u8 {
            rig.push(i, 1_000, Some(3));
        }
        rig.carrier
            .bottleneck()
            .set_budget(Some(WireBitrate(80_000_000)))
            .unwrap();
        rig.push(99, 1_000, Some(3));
        let took = rig.drain(Duration::from_secs(3)).await;
        let status = rig.queue.status();
        assert_eq!(
            rig.sent().len(),
            7,
            "sent {:?}, dropped={} overlimit={} rate={} took {took:?}",
            rig.sent(),
            status.dropped_packets,
            status.overlimit_drops,
            status.bandwidth_bps,
        );
        assert!(took < Duration::from_millis(60), "still paced at the old rate, took {took:?}");
    }

    /// Once a queue exists the pump's timer wakes within a few milliseconds
    /// (tokio itself rounds up to the next one). CAKE's sojourn includes how
    /// late the pump woke: waking a whole Windows clock tick (15.6 ms) late
    /// puts every backlog over COBALT's 5 ms target, and COBALT drops.
    #[tokio::test]
    async fn the_pump_timer_wakes_within_a_few_milliseconds() {
        let _rig = rig(10, 8_000_000);
        let mut late = Vec::new();
        for _ in 0..20 {
            let at = Instant::now() + Duration::from_millis(1);
            tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await;
            late.push(Instant::now() - at);
        }
        late.sort();
        let median = late[late.len() / 2];
        assert!(median < Duration::from_millis(3),"the timer woke {median:?} late (median), {late:?}");
    }

    /// The packet memory is CAKE's own: 4 MB at least, more at high rates.
    #[tokio::test]
    async fn the_packet_memory_is_cakes_default() {
        let slow = rig(8, 1_600_000);
        assert_eq!(slow.queue.status().memory_limit, 4 << 20);
        let fast = rig(9, 10_000_000_000);
        assert!(fast.queue.status().memory_limit > 4 << 20);
    }
}

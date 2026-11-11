use std::{
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use hotpath::instant::Instant;
use rand::{Rng, thread_rng};
use tokio::{
    sync::broadcast,
    task::JoinSet,
    time::{Interval, timeout},
};
use tracing::Instrument;

use crate::{
    common::{PeerId, error::Error},
    peers::{peer_conn_liveness::PeerConnLiveness, traffic_metrics::AggregateTrafficMetrics},
    tunnel::{
        TunnelError,
        mpsc::MpscTunnelSender,
        packet_def::{PacketType, ZCPacket},
        stats::{Throughput, WindowLatency},
    },
};

#[derive(Debug)]
enum PingResponse {
    /// The pong arrived after this many microseconds.
    Pong(u128),
    /// No pong, but the peer echoed the liveness probe on other traffic.
    LivenessEcho,
}

/// A connection is closed only after five consecutive failed round trips
/// that also span this long without any success. Five failures alone are
/// common on a lossy link: at 30% loss each way a round trip fails half the
/// time, and five in a row come up about once a minute at one ping per
/// second. A half-open connection, where no pong ever arrives, still closes.
/// A cellular uplink also stalls outright for 18-60 s and then recovers; 45 s
/// rides out most of those instead of tearing down every connection over it.
/// A connection carried by QUIC multipath follows the same rule: QUIC's idle
/// timer restarts on any packet received, so a session whose one direction
/// is dead never idles out (incident 2026-11-05 21:59, six minutes), while
/// replacing a path takes far less than this. Closing it hands the peer to
/// ET's native relay, which then tries direct again (RFC 7675 §5.1: when
/// consent expires, stop sending on the pair).
#[cfg(not(test))]
const MIN_SILENCE_BEFORE_CLOSE: Duration = Duration::from_secs(45);
/// The pingpong tests run the close rule on a 15 s silence so a test of a
/// dead connection finishes in seconds rather than a minute.
#[cfg(test)]
const MIN_SILENCE_BEFORE_CLOSE: Duration = Duration::from_secs(15);

/// After this many pings in a row went unanswered, the peer's other conns
/// that still answer carry its traffic until this one answers again (RFC 7675
/// consent freshness: only answers to our own checks count, not traffic that
/// merely arrives). The first failure makes the pinger ping every second, so
/// three come about 4 s into a stall; one or two in a row are routine on a
/// lossy link. Closing still waits for `MIN_SILENCE_BEFORE_CLOSE`.
pub(crate) const UNANSWERED_PINGS_BEFORE_AVOIDED: u32 = 3;

/// The idle ping interval backs off 1, 2, 4 ... up to 32 seconds.
pub(crate) const DEFAULT_MAX_PING_INTERVAL: Duration = Duration::from_secs(32);

struct PingIntervalController {
    throughput: Arc<Throughput>,
    loss_counter: Arc<AtomicU32>,

    interval: Interval,
    /// The backoff never stretches the ping interval beyond this.
    max_interval: Duration,

    logic_time: u64,
    last_send_logic_time: u64,

    backoff_idx: i32,
    max_backoff_idx: i32,

    last_throughput: Throughput,
}

impl std::fmt::Debug for PingIntervalController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PingIntervalController")
            .field("throughput", &self.throughput)
            .field("loss_counter", &self.loss_counter)
            .field("logic_time", &self.logic_time)
            .field("last_send_logic_time", &self.last_send_logic_time)
            .field("backoff_idx", &self.backoff_idx)
            .field("max_backoff_idx", &self.max_backoff_idx)
            .field("max_interval", &self.max_interval)
            .field("last_throughput", &self.last_throughput)
            .finish()
    }
}

impl PingIntervalController {
    fn new(
        throughput: Arc<Throughput>,
        loss_counter: Arc<AtomicU32>,
        max_interval: Duration,
    ) -> Self {
        let last_throughput = (*throughput).clone();

        Self {
            throughput,
            loss_counter,
            interval: tokio::time::interval(Duration::from_secs(1)),
            max_interval,
            logic_time: 0,
            last_send_logic_time: 0,

            backoff_idx: 0,
            max_backoff_idx: 5,

            last_throughput,
        }
    }

    async fn tick(&mut self) {
        self.interval.tick().await;
        self.logic_time += 1;
    }

    fn tx_increase(&self) -> bool {
        self.throughput.tx_packets() > self.last_throughput.tx_packets()
    }

    fn rx_increase(&self) -> bool {
        self.throughput.rx_packets() > self.last_throughput.rx_packets()
    }

    fn should_send_ping(&mut self) -> bool {
        if self.loss_counter.load(Ordering::Relaxed) > 0 {
            self.backoff_idx = 0;
        } else if self.tx_increase() && !self.rx_increase() {
            // if tx increase but rx not increase, we should do pingpong more frequently
            self.backoff_idx = 0;
        }

        self.last_throughput = (*self.throughput).clone();

        let send_interval = Duration::from_secs(1 << self.backoff_idx).min(self.max_interval);
        if Duration::from_secs(self.logic_time - self.last_send_logic_time) < send_interval {
            return false;
        }

        self.backoff_idx = std::cmp::min(self.backoff_idx + 1, self.max_backoff_idx);

        // use this makes two peers not pingpong at the same time
        if self.backoff_idx > self.max_backoff_idx - 2 && thread_rng().gen_bool(0.2) {
            self.backoff_idx -= 1;
        }

        self.last_send_logic_time = self.logic_time;
        true
    }
}

pub struct PeerConnPinger {
    my_peer_id: PeerId,
    peer_id: PeerId,
    sink: MpscTunnelSender,
    ctrl_sender: broadcast::Sender<ZCPacket>,
    latency_stats: Arc<WindowLatency>,
    loss_rate_stats: Arc<AtomicU32>,
    throughput_stats: Arc<Throughput>,
    control_metrics: AggregateTrafficMetrics,
    /// Pings in a row that went unanswered, shared with the connection so
    /// conn selection can see it (`UNANSWERED_PINGS_BEFORE_AVOIDED`).
    unanswered_pings: Arc<AtomicU32>,
    max_interval: Duration,
    /// Round-trip proof from echoed data traffic when a pong is lost (see `peer_conn_liveness`).
    liveness: PeerConnLiveness,
    tasks: JoinSet<Result<(), TunnelError>>,
}

impl std::fmt::Debug for PeerConnPinger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConnPinger")
            .field("my_peer_id", &self.my_peer_id)
            .field("peer_id", &self.peer_id)
            .finish()
    }
}

impl PeerConnPinger {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        my_peer_id: PeerId,
        peer_id: PeerId,
        sink: MpscTunnelSender,
        ctrl_sender: broadcast::Sender<ZCPacket>,
        latency_stats: Arc<WindowLatency>,
        loss_rate_stats: Arc<AtomicU32>,
        throughput_stats: Arc<Throughput>,
        control_metrics: AggregateTrafficMetrics,
        unanswered_pings: Arc<AtomicU32>,
        max_interval: Duration,
        liveness: PeerConnLiveness,
    ) -> Self {
        Self {
            my_peer_id,
            peer_id,
            sink,
            liveness,
            tasks: JoinSet::new(),
            latency_stats,
            ctrl_sender,
            loss_rate_stats,
            throughput_stats,
            control_metrics,
            unanswered_pings,
            max_interval,
        }
    }

    fn new_ping_packet(my_node_id: PeerId, peer_id: PeerId, seq: u32) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(&seq.to_le_bytes());
        packet.fill_peer_manager_hdr(my_node_id, peer_id, PacketType::Ping as u8);
        packet
    }

    async fn do_pingpong_once(
        my_node_id: PeerId,
        peer_id: PeerId,
        sink: &MpscTunnelSender,
        control_metrics: &AggregateTrafficMetrics,
        receiver: &mut broadcast::Receiver<ZCPacket>,
        seq: u32,
        liveness: &PeerConnLiveness,
        liveness_token: Option<u8>,
    ) -> Result<PingResponse, Error> {
        // should add seq here. so latency can be calculated more accurately
        let req = Self::new_ping_packet(my_node_id, peer_id, seq);
        let req_len = req.buf_len() as u64;
        sink.send(req).await?;
        control_metrics.record_tx(req_len);

        let now = Instant::now();
        // wait until we get a pong packet in ctrl_resp_receiver
        let wait_for_pong = async {
            loop {
                match receiver.recv().await {
                    Ok(p) => {
                        let payload = p.payload();
                        let Ok(seq_buf) = payload[0..4].try_into() else {
                            tracing::debug!("pingpong recv invalid packet, continue");
                            continue;
                        };
                        let resp_seq = u32::from_le_bytes(seq_buf);
                        if resp_seq == seq {
                            break;
                        }
                    }
                    Err(e) => {
                        return Err(Error::WaitRespError(format!(
                            "wait ping response error: {:?}",
                            e
                        )));
                    }
                }
            }
            Ok(())
        };
        // After a failed ping, a matching echo of the liveness probe is as good as the pong.
        let resp = timeout(Duration::from_secs(2), async {
            if let Some(token) = liveness_token {
                tokio::select! {
                    ret = wait_for_pong => ret.map(|()| PingResponse::Pong(now.elapsed().as_micros())),
                    () = liveness.wait_for_echo(token) => Ok(PingResponse::LivenessEcho),
                }
            } else {
                wait_for_pong
                    .await
                    .map(|()| PingResponse::Pong(now.elapsed().as_micros()))
            }
        })
        .await;

        tracing::trace!(?resp, "wait ping response done");

        if resp.is_err() {
            return Err(Error::WaitRespError(
                "wait ping response timeout".to_owned(),
            ));
        }

        resp.unwrap()
    }

    pub async fn pingpong(&mut self) {
        let sink = self.sink.clone();
        let control_metrics = self.control_metrics.clone();
        let my_node_id = self.my_peer_id;
        let peer_id = self.peer_id;
        let latency_stats = self.latency_stats.clone();

        let (ping_res_sender, mut ping_res_receiver) = tokio::sync::mpsc::channel(100);

        // one with 1% precision
        let loss_rate_stats_1 = WindowLatency::new(100);
        // disconnect the connection if lost 5 pingpong consecutively
        let loss_counter = self.unanswered_pings.clone();

        let stopped = Arc::new(AtomicU32::new(0));

        // generate a pingpong task every 200ms
        let mut pingpong_tasks = JoinSet::new();
        let ctrl_resp_sender = self.ctrl_sender.clone();
        let stopped_clone = stopped.clone();
        let liveness = self.liveness.clone();
        let loss_counter_for_pings = loss_counter.clone();
        let mut controller = PingIntervalController::new(
            self.throughput_stats.clone(),
            loss_counter.clone(),
            self.max_interval,
        );
        self.tasks.spawn(
            async move {
                let mut req_seq = 0;
                loop {
                    controller.tick().await;

                    if stopped_clone.load(Ordering::Relaxed) != 0 {
                        return Ok(());
                    }

                    while pingpong_tasks.len() > 5 {
                        pingpong_tasks.join_next().await;
                    }

                    if !controller.should_send_ping() {
                        continue;
                    }

                    tracing::debug!(
                        "pingpong controller send pingpong task, seq: {}, node_id: {}, controller: {:?}",
                        req_seq,
                        my_node_id,
                        controller,
                    );

                    let sink = sink.clone();
                    let control_metrics = control_metrics.clone();
                    let receiver = ctrl_resp_sender.subscribe();
                    let ping_res_sender = ping_res_sender.clone();
                    // Once a ping has failed, the connection's own traffic carries a probe
                    // token and its echo can stand in for a lost pong.
                    let liveness = liveness.clone();
                    let liveness_token = (loss_counter_for_pings.load(Ordering::Relaxed) > 0)
                        .then(|| liveness.start_probe())
                        .flatten();
                    pingpong_tasks.spawn(async move {
                        let mut receiver = receiver.resubscribe();
                        let pingpong_once_ret = Self::do_pingpong_once(
                            my_node_id,
                            peer_id,
                            &sink,
                            &control_metrics,
                            &mut receiver,
                            req_seq,
                            &liveness,
                            liveness_token,
                        )
                        .await;
                        if let (Ok(_), Some(token)) = (&pingpong_once_ret, liveness_token) {
                            liveness.finish_probe(token);
                        }

                        if let Err(e) = ping_res_sender.send(pingpong_once_ret).await {
                            tracing::info!(?e, "pingpong task send result error, exit..");
                        };
                    });

                    req_seq = req_seq.wrapping_add(1);
                }
            }
            .instrument(tracing::info_span!(
                "pingpong_controller",
                ?my_node_id,
                ?peer_id
            )),
        );

        let mut last_success = Instant::now();
        while let Some(ret) = ping_res_receiver.recv().await {
            if let Ok(response) = &ret {
                // An echo proves the round trip but says nothing about its latency.
                if let PingResponse::Pong(lat) = response {
                    latency_stats.record_latency(*lat as u32);
                }

                loss_rate_stats_1.record_latency(0);
                loss_counter.store(0, Ordering::Relaxed);
                last_success = Instant::now();
            } else {
                loss_rate_stats_1.record_latency(1);
                loss_counter.fetch_add(1, Ordering::Relaxed);
            }

            let loss_rate_1: f64 = loss_rate_stats_1.get_latency_us();

            tracing::trace!(
                ?ret,
                ?self,
                ?loss_rate_1,
                "pingpong task recv pingpong_once result"
            );

            tracing::debug!(
                "loss_counter: {:?}, loss_rate_1: {}, node_id: {}",
                loss_counter,
                loss_rate_1,
                my_node_id
            );

            if loss_counter.load(Ordering::Relaxed) >= 5
                && last_success.elapsed() >= MIN_SILENCE_BEFORE_CLOSE
            {
                tracing::warn!(
                    ?ret,
                    ?self,
                    ?loss_rate_1,
                    ?loss_counter,
                    "too many consecutive pingpong failures, closing the connection",
                );
                break;
            }

            self.loss_rate_stats
                .store((loss_rate_1 * 100.0) as u32, Ordering::Relaxed);
        }

        stopped.store(1, Ordering::Relaxed);
        ping_res_receiver.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::stats_manager::StatsManager,
        tunnel::{mpsc::MpscTunnel, ring::create_ring_tunnel_pair},
    };

    fn pinger_to_silent_peer() -> (PeerConnPinger, Arc<Throughput>, Arc<AtomicU32>) {
        let (local_tunnel, _remote_tunnel) = create_ring_tunnel_pair();
        let tunnel = MpscTunnel::new(local_tunnel, None);
        let (ctrl_sender, _) = broadcast::channel(16);
        let throughput = Arc::new(Throughput::new());
        let unanswered = Arc::new(AtomicU32::new(0));
        let pinger = PeerConnPinger::new(
            1,
            2,
            tunnel.get_sink(),
            ctrl_sender,
            Arc::new(WindowLatency::new(15)),
            Arc::new(AtomicU32::new(0)),
            throughput.clone(),
            AggregateTrafficMetrics::control(Arc::new(StatsManager::new()), "test".to_owned()),
            unanswered.clone(),
            DEFAULT_MAX_PING_INTERVAL,
            PeerConnLiveness::new(),
        );
        // keep the silent far end alive for the whole test
        std::mem::forget(_remote_tunnel);
        std::mem::forget(tunnel);
        (pinger, throughput, unanswered)
    }

    /// One logical second passes without waiting for the interval timer.
    fn advance(controller: &mut PingIntervalController) {
        controller.logic_time += 1;
    }

    #[tokio::test]
    async fn one_second_limit_disables_ping_backoff() {
        let mut controller = PingIntervalController::new(
            Arc::new(Throughput::new()),
            Arc::new(AtomicU32::new(0)),
            Duration::from_secs(1),
        );

        for _ in 0..100 {
            advance(&mut controller);
            assert!(controller.should_send_ping());
            assert!(!controller.should_send_ping());
        }
    }

    #[tokio::test]
    async fn ping_backoff_respects_non_power_of_two_limit() {
        let mut controller = PingIntervalController::new(
            Arc::new(Throughput::new()),
            Arc::new(AtomicU32::new(0)),
            Duration::from_secs(3),
        );

        for tick in 1..=100 {
            advance(&mut controller);
            assert_eq!(controller.should_send_ping(), tick == 1 || tick % 3 == 0);
        }
    }

    #[tokio::test]
    async fn default_limit_preserves_backoff_and_loss_retries() {
        let loss_counter = Arc::new(AtomicU32::new(0));
        let mut controller = PingIntervalController::new(
            Arc::new(Throughput::new()),
            loss_counter.clone(),
            DEFAULT_MAX_PING_INTERVAL,
        );

        for second in 1..=14 {
            advance(&mut controller);
            assert_eq!(controller.should_send_ping(), matches!(second, 1 | 3 | 7));
        }

        loss_counter.store(1, Ordering::Relaxed);
        for _ in 0..3 {
            advance(&mut controller);
            assert!(controller.should_send_ping());
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ingress_traffic_does_not_mask_failed_round_trips() {
        let (mut pinger, throughput, _unanswered) = pinger_to_silent_peer();
        let ingress = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                throughput.record_rx_bytes(1);
            }
        });

        let result = timeout(Duration::from_secs(30), pinger.pingpong()).await;
        ingress.abort();

        assert!(
            result.is_ok(),
            "unrelated ingress traffic kept a failed round-trip alive"
        );
    }

    /// A stalled connection is visible to conn selection seconds into the
    /// stall, long before it may be closed, even while traffic still
    /// arrives on it.
    #[tokio::test(flavor = "current_thread")]
    async fn unanswered_pings_are_counted_seconds_into_a_stall() {
        let (mut pinger, throughput, unanswered) = pinger_to_silent_peer();
        let started = Instant::now();
        let ingress = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                throughput.record_rx_bytes(1);
            }
        });
        let counted = timeout(Duration::from_secs(8), async {
            tokio::select! {
                _ = pinger.pingpong() => panic!("closed before the close rule allows"),
                _ = async {
                    while unanswered.load(Ordering::Relaxed) < UNANSWERED_PINGS_BEFORE_AVOIDED {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                } => {}
            }
        })
        .await;
        ingress.abort();
        assert!(counted.is_ok(), "the stall was not counted within 8 s");
        assert!(started.elapsed() < MIN_SILENCE_BEFORE_CLOSE);
    }
}

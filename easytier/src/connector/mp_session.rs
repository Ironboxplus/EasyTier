use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Instant,
};

use dashmap::DashMap;
use tokio::sync::{Mutex, RwLock};

use crate::{
    common::{
        PeerId,
        config::{gen_default_mp_config, mp_reconnect_fingerprint, validate_mp_config},
        egress_quality::EgressQualityManager,
        transport_quality::{
            CongestionControlProfile,
            budget::{EgressDirection, EgressScope},
            rate::WireBitrate,
        },
    },
    proto::{
        api::instance::MpDataPlaneStatus,
        common::{MpConfig, MpPathPolicy},
    },
    tunnel::{
        Tunnel, TunnelError,
        mp_dataplane::{DataPlanePolicy, OversizePolicy, disabled_status, inner_packet_limit},
    },
};

use super::{
    mp_manual::ManualUdpPathConfig,
    mp_optimizer::{
        BudgetedPath, ResourceCapacity, SelectorPath, prefer_bias_micros, resolve_path_policy,
        select_paths, split_budgets, transport_bias,
    },
    mp_path::{
        CarrierKind, MpCandidateTable, MpPathProvider, MpPathSpec, PathLifecycleState,
        PathMeasurements, ResourceGroupId,
    },
};
use crate::tunnel::mpquic::{
    CarrierId, MpPathEvent, MpPathTarget, MpPathTelemetry, MpQuicSessionConfig, MpSessionHandle,
    PathKey, is_last_open_path, is_no_free_path_slot, session_from_datagram_paths_with_config,
};

/// Read-model snapshot of one physical egress' estimated capacity, keyed by
/// the MP-facing `ResourceGroupId` for RPC/stats compatibility
/// (`instance::instance::mp_egress_status_from_snapshot`). This type used to
/// live in `mp_egress_sqm.rs` alongside its own `LinkSqmEstimator` instance;
/// it now moves here because the estimator itself is a single instance
/// shared through `common::egress_quality::EgressQualityManager`, keyed by
/// `EgressScope` (not `ResourceGroupId` — MP_SQM_PLAN.md §4.3's "复用与红线":
/// the two keys are not necessarily 1:1, so this struct is the explicit,
/// non-collapsing re-keying step from one to the other).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EgressResourceEstimate {
    pub(crate) resource: ResourceGroupId,
    pub(crate) capacity_bps: u64,
    pub(crate) achieved_bps: u64,
    /// Whether `achieved_bps` is the NIC's counter or the paths' sent bytes.
    pub(crate) achieved_source: AchievedSource,
    pub(crate) queue_delay_micros: u64,
    /// Where `queue_delay_micros` came from (OWD_AUTORATE_PLAN.md 1.4).
    pub(crate) queue_delay_source: crate::common::egress_quality::QueueDelaySource,
    /// Public reflectors the tick's delay was taken from
    /// (`MpEgressResourceStatus.reflector_count`).
    pub(crate) reflector_count: u32,
    pub(crate) path_count: usize,
    /// MP_SQM_PLAN.md S2.1 GUI fields (§9 `MpEgressResourceStatus`). Every
    /// resource reaching this struct today came from an `egress_resource`
    /// filtered to `ResourceGroupKind::EgressDevice` (see the `continue`
    /// above this struct's construction site), so `egress_device_name()`
    /// is always `Some` here -- `unwrap_or_default` is defense in depth,
    /// not an expected path.
    pub(crate) egress_device: String,
    pub(crate) ceiling_bps: Option<WireBitrate>,
    pub(crate) ceiling_source: crate::common::egress_quality::CeilingSource,
    /// MP_SQM_PLAN.md S2.5 §9 `MpEgressResourceStatus.autorate_estimate_bps`:
    /// the autorate estimator's current bandwidth estimate for this scope,
    /// before the user's bounds and the static ceiling
    /// (`common::egress_quality::manager`'s `autorate_estimate()`).
    pub(crate) autorate_estimate_bps: Option<u64>,
    /// `MpEgressResourceStatus.autorate_measured`: the estimate is still the
    /// start value until a measurement moves it.
    pub(crate) autorate_measured: bool,
    /// The egress's CAKE queue; `None` until a packet has used the egress.
    pub(crate) cake: Option<crate::proto::api::instance::MpCakeStatus>,
    /// `true` iff this scope's `EgressStableId` is `Fallback` (no real NIC
    /// identity could be resolved) -- never true along the path that
    /// reaches here today (it requires a real `EgressSocketBinding`), kept
    /// as a real, checked value rather than a hardcoded `false` so it stays
    /// correct if a future caller feeds this same struct from a path that
    /// can produce one.
    pub(crate) fallback_scope: bool,
}

/// Per-scope byte-delta bookkeeping for `refresh_all_egress_capacities`.
/// `PathKey` is a `tunnel::mpquic` type, so this state must live on the
/// `connector` side of the boundary; `common::egress_quality` never sees it.
struct EgressSampleState {
    last_update: Instant,
    /// Each path's cumulative sent bytes (`MpPathTelemetry::sent_bytes`).
    last_bytes: HashMap<PathKey, u64>,
    /// The interface's cumulative sent bytes at the last tick, when its
    /// counters could be read.
    last_nic_tx: Option<u64>,
    /// This card's public-reflector prober, shared with every other user of
    /// the same card and reflector list; dropped with the scope.
    reflectors: Option<(
        crate::common::egress_quality::reflectors::ProberKey,
        Arc<crate::common::egress_quality::reflectors::ReflectorProber>,
    )>,
}

/// The public reflectors Autorate probes per `MpSqmConfig`: `None` if
/// disabled, the configured IPv4 addresses (invalid entries are rejected by
/// `validate_mp_config`, skipped here), else the built-in six.
fn reflector_addresses(config: &MpConfig) -> Option<Vec<std::net::Ipv4Addr>> {
    let sqm = config.sqm.as_ref();
    if sqm.is_some_and(|sqm| sqm.reflectors_disabled) {
        return None;
    }
    let configured = sqm
        .map(|sqm| {
            sqm.reflectors
                .iter()
                .filter_map(|reflector| reflector.parse().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Some(if configured.is_empty() {
        crate::common::egress_quality::reflectors::DEFAULT_REFLECTORS.to_vec()
    } else {
        configured
    })
}

/// Where an egress's `achieved_bps` was measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AchievedSource {
    /// The interface's own byte counters: everything leaving the NIC, ours or
    /// not, as cake-autorate measures load.
    NicCounter,
    /// Only the MP paths' sent bytes: no counter reading was available.
    PathSentBytes,
}

impl AchievedSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            AchievedSource::NicCounter => "nic-counter",
            AchievedSource::PathSentBytes => "path-sent-bytes",
        }
    }
}

/// Bytes the egress sent since the previous tick. The NIC counter wins; the
/// paths' sent bytes stand in until two counter readings exist (the first
/// tick, an unreadable interface).
fn egress_sent_delta(
    last_nic_tx: &mut Option<u64>,
    nic_tx: Option<u64>,
    path_sent_delta: u64,
) -> (u64, AchievedSource) {
    let previous = std::mem::replace(last_nic_tx, nic_tx);
    match (previous, nic_tx) {
        (Some(previous), Some(now)) => (
            crate::common::ifcfg::InterfaceCounters::delta(previous, now),
            AchievedSource::NicCounter,
        ),
        _ => (path_sent_delta, AchievedSource::PathSentBytes),
    }
}

/// Stands in for the carrier of a directly connected `mpquic://` session's
/// path in the candidate table. The session's driver owns the real socket;
/// this one is never sent through or read from.
struct AdoptedPath {
    local: std::net::SocketAddr,
}

#[async_trait::async_trait]
impl crate::tunnel::mpquic::MpDatagramPath for AdoptedPath {
    fn local_addr(&self) -> std::net::SocketAddr {
        self.local
    }

    fn try_send_to(&self, _payload: &[u8], _remote: std::net::SocketAddr) -> std::io::Result<usize> {
        Err(std::io::Error::other("the carrier belongs to the session's driver"))
    }

    async fn recv_from(&self, _buf: &mut [u8]) -> std::io::Result<(usize, std::net::SocketAddr)> {
        std::future::pending().await
    }
}

struct Session {
    handle: MpSessionHandle,
    /// The controller is chosen when TQUIC creates the connection and cannot
    /// be replaced by a scheduler-only hot update. Keep the instantiated value
    /// beside the handle so runtime readback never reports a newer desired
    /// config as though it were already active on an older session.
    congestion_control: CongestionControlProfile,
    /// This end accepted the connection. Only the client opens new paths: a
    /// path the server adds is only registered, waiting for the client to
    /// validate it.
    is_server: bool,
}

type SessionSlot = Arc<Mutex<Option<Session>>>;

/// One peer's session establishments in flight. A handshake can take the whole
/// `establishment_timeout`, so none of this runs under the session slot,
/// which the control tick, peer teardown and snapshots take.
///
/// Both ends can punch at once, each as the client of its own carrier. The
/// pair settles on the lower peer id's outgoing session (its client, the
/// higher id's server) and both ends reach that decision from the peer ids
/// alone, whatever the timing -- the rule `duplicate_wan_paths` already uses
/// ("only the lower peer id retires duplicates"), and the deterministic role
/// assignment that simultaneous-open resolution in libp2p and iroh's
/// "the client decides" (`remote_state.rs` `apply_selected_path`) come down to:
///
/// - Every offer starts its handshake at once; none waits for another, so
///   neither end's incoming handshake can queue behind its own outgoing one.
/// - A finished handshake takes the empty slot. The preferred direction
///   replaces a session of the other direction, which is then shut down; any
///   other finished handshake gives its carrier to the session in the slot as
///   another path.
/// - When the preferred session is in the slot, the handshakes still running
///   in the other direction are dropped and their carriers join it as paths.
///
/// A completed session of the other direction is never kept against a
/// preferred one, so both ends end on the same session; when no preferred
/// offer ever comes, the other direction's session stands, and either end
/// alone can still connect the pair.
#[derive(Default)]
struct PeerEstablishment {
    state: std::sync::Mutex<EstablishmentState>,
}

#[derive(Default)]
struct EstablishmentState {
    next_id: u64,
    /// The handshakes in flight: whether each is in the preferred direction,
    /// and how to drop it.
    running: Vec<(u64, bool, Arc<tokio::sync::Notify>)>,
}

impl PeerEstablishment {
    fn in_progress(&self) -> bool {
        !self.state.lock().unwrap().running.is_empty()
    }

    fn begin(&self, preferred: bool, cancel: Arc<tokio::sync::Notify>) -> RunningHandshake<'_> {
        let mut state = self.state.lock().unwrap();
        state.next_id += 1;
        let id = state.next_id;
        state.running.push((id, preferred, cancel));
        RunningHandshake(self, id)
    }

    /// Drops every running handshake of the non-preferred direction.
    fn cancel_non_preferred(&self) {
        for (_, preferred, cancel) in &self.state.lock().unwrap().running {
            if !preferred {
                cancel.notify_one();
            }
        }
    }
}

/// Removes the handshake from `running` when it ends, or when the offer is dropped.
struct RunningHandshake<'a>(&'a PeerEstablishment, u64);

impl Drop for RunningHandshake<'_> {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().running.retain(|(id, ..)| *id != self.1);
    }
}

#[derive(Clone, Copy)]
struct ManagedManualPath {
    peer_id: PeerId,
    key: crate::tunnel::mpquic::PathKey,
}

pub(crate) enum OfferPathResult {
    NewTunnel(Box<dyn Tunnel>),
    PathAdded,
}

/// iroh `open_path_on_conn` retry delay (`remote_state.rs:1081`).
const OPEN_PATH_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(333);

/// What one retried path open came to.
enum OpenAttempt {
    Opened,
    /// The connection still has no free connection ID or path slot.
    NoFreeSlot,
    /// The open is no longer wanted, or failed for good.
    GiveUp,
}

/// Queues a refused open unless its 4-tuple is queued already (iroh checks
/// `pending_open_paths.contains` before `push_back`, `remote_state.rs:1086`).
/// Returns whether it was newly queued.
fn queue_refused_open(
    pending: &DashMap<(PeerId, PathKey), ()>,
    id: (PeerId, PathKey),
) -> bool {
    pending.insert(id, ()).is_none()
}

/// Opens a queued path again every `delay` until the connection takes it, the
/// open is given up, or the entry is removed from `pending` (the peer was
/// forgotten). ET: iroh keeps one timer for its whole queue; here every
/// queued 4-tuple has its own task with the same fixed delay, which behaves
/// the same for the handful of 4-tuples one peer has.
async fn retry_refused_open<F, Fut>(
    pending: Arc<DashMap<(PeerId, PathKey), ()>>,
    id: (PeerId, PathKey),
    delay: std::time::Duration,
    mut attempt: F,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = OpenAttempt>,
{
    loop {
        tokio::time::sleep(delay).await;
        if !pending.contains_key(&id) {
            return;
        }
        match attempt().await {
            OpenAttempt::NoFreeSlot => continue,
            OpenAttempt::Opened | OpenAttempt::GiveUp => break,
        }
    }
    pending.remove(&id);
}

pub(crate) struct ManualPathOffer {
    pub(crate) source: String,
    pub(crate) peer_id: PeerId,
    pub(crate) is_server: bool,
    pub(crate) outcome: OfferPathResult,
}

pub(crate) struct MpSessionManager {
    sessions: DashMap<PeerId, SessionSlot>,
    candidates: DashMap<PeerId, Arc<Mutex<MpCandidateTable>>>,
    optimization_snapshots: DashMap<PeerId, MpOptimizationSnapshot>,
    /// EasyTier ping loss of each relay first hop's connection, refreshed by
    /// the peer manager before every control tick (`set_first_hop_loss`). A
    /// first hop missing here has no live connection and counts as clean:
    /// only a measured loss keeps a path out of the selection.
    first_hop_loss: std::sync::RwLock<HashMap<PeerId, f64>>,
    /// 4-tuples whose open the connection refused for lack of a free path
    /// slot, queued for a retry (iroh `pending_open_paths`,
    /// `remote_state.rs:166`). One entry per 4-tuple: a second refusal of the
    /// same one does not queue it again.
    pending_path_opens: Arc<DashMap<(PeerId, PathKey), ()>>,
    /// The instance-wide physical-egress quality manager (MP_SQM_PLAN.md
    /// §3, §4.3). `MpSessionManager` no longer owns its own SQM
    /// estimator/registry; it only publishes samples/demand into this shared
    /// manager and reads allocation back. Disabling MP must only withdraw
    /// MP's own demand from this manager, never tear the manager itself
    /// down (see `clear_disabled_runtime_state`).
    egress_quality: Arc<EgressQualityManager>,
    egress_sample_state: Mutex<HashMap<EgressScope, EgressSampleState>>,
    egress_snapshots: DashMap<ResourceGroupId, EgressResourceEstimate>,
    manual_paths: DashMap<String, ManagedManualPath>,
    manual_reconcile_lock: Mutex<()>,
    config: RwLock<MpConfig>,
    /// MP_SQM_PLAN.md S1.4: standalone `mpquic://` connections (opened
    /// directly by `MpQuicTunnelConnector`/`MpQuicTunnelListener`, not routed
    /// through this manager's own `offer_path`/`sessions`) registered here by
    /// `peers::peer_manager` once their `PeerConn` handshake yields a
    /// peer_id. Deliberately a separate map from `sessions`: standalone
    /// sessions are observed and still get CC/path targets dispatched, but
    /// are NOT cleared by `clear_disabled_runtime_state` -- the MP on/off
    /// switch governs the optimizer/candidate/TopK machinery, not a plain
    /// point-to-point tunnel that was never subject to it.
    /// MP_SQM_PLAN.md S2.2 follow-up: the `&'static str` alongside each
    /// handle is the real congestion-control profile that standalone tunnel
    /// was built with (`Tunnel::mp_congestion_control`), reported verbatim
    /// as `MpPeerRuntimeSnapshot.effective_congestion_control` instead of a
    /// hardcoded `"unknown"`.
    standalone_sessions: DashMap<PeerId, (MpSessionHandle, &'static str)>,
    /// MP_SQM_PLAN.md S2.2 follow-up: a device-name index over the latest
    /// `EgressInventorySnapshot` `reconcile_egress_bindings` was given,
    /// rebuilt on every call. An MP path's candidate resolves an
    /// `egress_resource` device name via plain interface auto-detection
    /// (`connector::mp_path::UdpMpPathProvider::discover`) but never binds a
    /// real per-NIC socket, so it never gets a real `EgressSocketBinding`
    /// (since MP_SQM_PLAN.md S2.14 only tests build one). Without this index,
    /// `refresh_all_egress_capacities` could report no scope at all, leaving
    /// `MpRuntimeInfo.egress` empty for the ordinary single-egress setup
    /// egress limits/SQM are chiefly for.
    resolved_egress_routes:
        Mutex<HashMap<String, (crate::common::egress_inventory::EgressStableId, u64)>>,
    /// Each card's first IPv4 address and device name, from the latest
    /// inventory snapshot: what its Autorate reflector socket binds to.
    reflector_interfaces: std::sync::Mutex<
        HashMap<crate::common::egress_inventory::EgressStableId, (std::net::Ipv4Addr, String)>,
    >,
    /// The instance's `socket_mark` flag, applied to the reflector sockets.
    reflector_socket_mark: std::sync::Mutex<Option<u32>>,
    /// MP_SQM_PLAN.md S2.4 rate negotiation (consume half): an optional
    /// injected lookup from `peer_id` to that peer's most recently announced
    /// Brutal receive-rate ceiling (`RoutePeerInfo.mp_max_rx_bps`, bits/sec),
    /// or `None` if unknown/not announced. `None` by default (set via
    /// `set_remote_rx_bps_lookup`) so every existing constructor/test call
    /// site is unaffected -- `MpSessionManager` stays decoupled from
    /// `peers::peer_manager`/`PeerMap` by construction; the instance wires
    /// this to a real route-table lookup, tests can inject a fake one.
    remote_rx_bps_lookup: RwLock<Option<Arc<dyn Fn(PeerId) -> Option<u64> + Send + Sync>>>,
    /// MP_SQM_PLAN.md S2.10: the same injection for the peer's announced
    /// `RoutePeerInfo.mp_dataplane_caps`.
    remote_dataplane_caps_lookup:
        RwLock<Option<Arc<dyn Fn(PeerId) -> Option<u32> + Send + Sync>>>,
    /// MP_SQM_PLAN.md S2.10: the enabled data-plane policy, for the
    /// synchronous classifier on `PeerManager`'s send path (`None` = off).
    data_plane_hint: std::sync::RwLock<Option<Arc<DataPlanePolicy>>>,
    /// Largest inner IP packet per peer whose MP session negotiated the
    /// datagram plane with the `icmp_ptb` oversize policy; refreshed every
    /// control tick. `PeerManager` answers bigger packets with ICMP PTB.
    ptb_limits: DashMap<PeerId, usize>,
    /// ICMP PTB answers per peer, reported as `MpDataPlaneStatus.oversize_ptb`.
    ptb_sent: DashMap<PeerId, u64>,
    /// MP_SQM_PLAN.md S2.6: `mp_reconnect_fingerprint` of the config each
    /// live session was built from; a different current fingerprint means
    /// `reconnect_required`.
    session_fingerprints: DashMap<PeerId, String>,
    faketcp_upgrades: DashMap<PeerId, FakeTcpUpgradeRecord>,
    establishing: DashMap<PeerId, Arc<PeerEstablishment>>,
    /// The path each peer's session was established on, to retire when a
    /// preferred session replaces it.
    primary_keys: DashMap<PeerId, PathKey>,
    /// Since when a peer's session slot has been empty with no establishment
    /// running (see `EMPTY_SESSION_GRACE`).
    empty_since: DashMap<PeerId, Instant>,
    /// Punched carriers (per peer and kind) whose paths were dropped after
    /// validation with nothing received; see `PUNCH_DROP_BACKOFF_MS`.
    punch_drops: DashMap<(PeerId, CarrierKind), PunchDropBackoff>,
    /// This node's peer id: when both ends open a session to each other at
    /// once, the lower id's outgoing one wins. 0 = unknown, the incoming one
    /// then always wins.
    local_peer_id: PeerId,
}

/// Consecutive failed FakeTCP upgrades toward a peer after which `auto` mode
/// punches plain TCP to it, for `FAKETCP_FALLBACK_HOLD`.
pub(crate) const FAKETCP_FALLBACK_AFTER_FAILURES: u32 = 2;
pub(crate) const FAKETCP_FALLBACK_HOLD: std::time::Duration = std::time::Duration::from_secs(600);

/// How upgrading TCP-punched carriers to FakeTCP has gone for one peer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FakeTcpUpgradeRecord {
    pub(crate) failures: u64,
    pub(crate) consecutive_failures: u32,
    pub(crate) last_error: String,
    last_failure: Option<std::time::Instant>,
}

impl FakeTcpUpgradeRecord {
    fn record(&mut self, result: Result<(), String>, now: std::time::Instant) {
        match result {
            Ok(()) => self.consecutive_failures = 0,
            Err(error) => {
                self.failures += 1;
                self.consecutive_failures += 1;
                self.last_error = error;
                self.last_failure = Some(now);
            }
        }
    }

    pub(crate) fn plain_tcp_fallback(&self, now: std::time::Instant) -> bool {
        self.consecutive_failures >= FAKETCP_FALLBACK_AFTER_FAILURES
            && self
                .last_failure
                .is_some_and(|at| now.saturating_duration_since(at) < FAKETCP_FALLBACK_HOLD)
    }
}

/// Live punched carriers to one peer, grouped by the WAN (peer-observed
/// public IP) they leave through. See `punch_wan_summary`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PunchWanSummary {
    pub(crate) live: usize,
    /// Live carriers the peer has not (yet) reported an address for; either
    /// still warming up or the peer lacks address discovery.
    pub(crate) unobserved: usize,
    pub(crate) wans: std::collections::BTreeSet<std::net::IpAddr>,
    /// No punch before this: earlier punches of this carrier kind were
    /// dropped after validation without anything arriving on them.
    pub(crate) held_until: Option<std::time::Instant>,
}

/// Wait after punched paths that were validated and then dropped without
/// anything arriving on them, per consecutive such drop. This is the schedule
/// of upstream EasyTier's own punch retries (`udp_hole_punch::BackOff`), run
/// from a first wait of 5 s, doubling to 5 minutes.
const PUNCH_DROP_BACKOFF_MS: [u64; 7] = [5_000, 10_000, 20_000, 40_000, 80_000, 160_000, 300_000];

struct PunchDropBackoff {
    backoff: crate::connector::udp_hole_punch::BackOff,
    held_until: Instant,
}

/// Per-peer progress of MP multi-punching (MP_SQM_PLAN.md S2.14).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MpPunchProgress {
    last_live: usize,
    last_wans: usize,
    stale: u32,
    /// When punching stopped for lack of new WANs; it resumes after `MP_PUNCH_STALE_RETRY`.
    stalled_at: Option<std::time::Instant>,
    /// Slot of the punch task still running for this peer.
    in_flight: Option<u32>,
}

impl MpPunchProgress {
    pub(crate) fn start(&mut self, slot: u32) {
        self.in_flight = Some(slot);
    }

    pub(crate) fn finish(&mut self, slot: u32) {
        if self.in_flight == Some(slot) {
            self.in_flight = None;
        }
    }
}

/// Marks a punch task's slot as running for as long as the guard lives; move
/// it into the task so an abort (even before the first poll) releases it.
pub(crate) struct MpPunchInFlight<D: Send + Sync + 'static> {
    data: Arc<D>,
    progress: fn(&D) -> &DashMap<PeerId, MpPunchProgress>,
    peer_id: PeerId,
    slot: u32,
}

impl<D: Send + Sync + 'static> MpPunchInFlight<D> {
    pub(crate) fn new(
        data: Arc<D>,
        progress: fn(&D) -> &DashMap<PeerId, MpPunchProgress>,
        peer_id: PeerId,
        slot: u32,
    ) -> Self {
        progress(&data).entry(peer_id).or_default().start(slot);
        Self {
            data,
            progress,
            peer_id,
            slot,
        }
    }
}

impl<D: Send + Sync + 'static> Drop for MpPunchInFlight<D> {
    fn drop(&mut self) {
        if let Some(mut progress) = (self.progress)(&self.data).get_mut(&self.peer_id) {
            progress.finish(self.slot);
        }
    }
}

/// Punched paths that duplicate another live path's WAN: same carrier kind,
/// same peer-observed local IP, same remote IP. Of each group an unpaused
/// path that already carries data survives, then the lowest sRTT (unknown
/// sorts last, then lowest local address).
fn duplicate_wan_paths(
    candidates: &MpCandidateTable,
    path_policies: &[MpPathPolicy],
) -> Vec<PathKey> {
    // A paused path is kept only if every duplicate is paused: keeping it
    // over a usable one would leave the peer with no path that carries data.
    // Likewise a path still validating or probing never displaces one that
    // carries data: when both ends punch at once, the other end's carrier
    // joins the session as a second path, and retiring the working one in
    // its favor left the session on a path that was not up yet (S3
    // oversize: pings lost for 9 s, the connection closed).
    let mut groups: HashMap<
        (CarrierKind, std::net::IpAddr, std::net::IpAddr),
        Vec<((bool, bool, u64), PathKey)>,
    > = HashMap::new();
    for (key, candidate) in candidates.iter() {
        if candidate.state == PathLifecycleState::Dead
            || !matches!(
                candidate.spec.carrier_kind,
                CarrierKind::UdpPunch | CarrierKind::FakeTcpPunch
            )
        {
            continue;
        }
        let Some(observed) = candidate.measurements.observed_local_addr else {
            continue;
        };
        let srtt = match candidate.measurements.propagation_rtt_micros {
            0 => u64::MAX,
            srtt => srtt,
        };
        groups
            .entry((
                candidate.spec.carrier_kind,
                observed.ip(),
                key.remote_addr.ip(),
            ))
            .or_default()
            .push((
                (
                    path_is_paused(candidate, key, path_policies),
                    !candidate.state.is_established(),
                    srtt,
                ),
                *key,
            ));
    }
    let mut duplicates = Vec::new();
    for mut group in groups.into_values() {
        group.sort_by_key(|(rank, key)| (*rank, key.local_addr));
        duplicates.extend(group.into_iter().skip(1).map(|(_, key)| key));
    }
    duplicates
}

/// Consecutive new carriers without a new WAN after which MP stops punching.
pub(crate) const MP_PUNCH_STALE_LIMIT: u32 = 2;
/// How long a stop for lack of new WANs lasts. A router balancing connections
/// over its WANs (mwan3) may put several punches in a row on the same one, so
/// stopping for good could leave the peer on one WAN.
pub(crate) const MP_PUNCH_STALE_RETRY: std::time::Duration = std::time::Duration::from_secs(30);

/// Decide whether another native punch should run for a peer, given its live
/// punched carriers. Returns the task slot (stable while the attempt runs) or
/// `None` to skip:
/// - no live carrier: punch (the pre-S2.14 behavior);
/// - some carrier not yet reported by the peer: wait. A peer without address
///   discovery never reports, so it keeps exactly one punch;
/// - distinct WANs reached `target`: stop;
/// - `MP_PUNCH_STALE_LIMIT` new carriers in a row brought no new WAN: pause for
///   `MP_PUNCH_STALE_RETRY`, then try again.
///
/// A punch task that is still running keeps its slot whatever the summary
/// says: its carrier turns live before the EasyTier handshake over it is
/// done, and a changed slot would make the task manager abort it mid-way.
pub(crate) fn next_mp_punch_slot(
    summary: &PunchWanSummary,
    progress: &mut MpPunchProgress,
    target: u32,
) -> Option<u32> {
    next_mp_punch_slot_at(summary, progress, target, std::time::Instant::now())
}

pub(crate) fn next_mp_punch_slot_at(
    summary: &PunchWanSummary,
    progress: &mut MpPunchProgress,
    target: u32,
    now: std::time::Instant,
) -> Option<u32> {
    if let Some(slot) = progress.in_flight {
        return Some(slot);
    }
    if summary.held_until.is_some_and(|until| now < until) {
        return None;
    }
    if summary.live == 0 {
        *progress = MpPunchProgress::default();
        return Some(0);
    }
    if summary.unobserved > 0 {
        return None;
    }
    let wans = summary.wans.len();
    if wans < progress.last_wans {
        // A WAN went away; try to regain it.
        progress.stale = 0;
    } else if summary.live > progress.last_live {
        if wans > progress.last_wans {
            progress.stale = 0;
        } else {
            progress.stale += 1;
        }
    }
    progress.last_live = summary.live;
    progress.last_wans = wans;
    if wans as u32 >= target {
        return None;
    }
    if progress.stale >= MP_PUNCH_STALE_LIMIT {
        let stalled_at = *progress.stalled_at.get_or_insert(now);
        if now.saturating_duration_since(stalled_at) < MP_PUNCH_STALE_RETRY {
            return None;
        }
        progress.stale = 0;
        progress.stalled_at = None;
    }
    Some(summary.live as u32)
}

/// What the last path selection of a session chose and set (see
/// `MpSessionManager::select_active_paths`).
#[derive(Debug, Clone)]
pub(crate) struct MpOptimizationSnapshot {
    /// The paths that carry data; every other established path stands by.
    pub(crate) active_paths: Vec<PathKey>,
    pub(crate) targets: Vec<MpPathTarget>,
    pub(crate) candidate_count: usize,
    pub(crate) eligible_count: usize,
}

/// The single authoritative MP control-cycle result.  `reaped_sessions` is
/// returned with the snapshots so lifecycle consumers cannot observe a closed
/// session being removed without also scheduling the carrier supervisor.
#[derive(Debug, Clone)]
pub(crate) struct MpControlTickResult {
    pub(crate) reaped_sessions: usize,
    pub(crate) snapshots: Vec<MpOptimizationSnapshot>,
}

/// What the selection saw of a path besides its telemetry (MP weak-network
/// plan W4).
#[derive(Debug, Clone, Default)]
pub(crate) struct PathSelectionDiagnostics {
    /// The byte-based loss average of the path itself (`PathCandidate::recent_loss`).
    pub(crate) recent_loss: Option<f64>,
    /// EasyTier ping loss of a relay path's physical first hop.
    pub(crate) first_hop_loss: Option<f64>,
    /// Why the path is no selection candidate: `not-established`, `policy`,
    /// `lossy-path`, `lossy-first-hop`, or empty.
    pub(crate) not_selected_reason: String,
}

#[derive(Debug, Clone)]
pub(crate) struct MpPathRuntimeSnapshot {
    pub(crate) key: crate::tunnel::mpquic::PathKey,
    pub(crate) carrier_kind: super::mp_path::CarrierKind,
    /// Only relay-next-hop carriers have a locally controlled first-hop
    /// identity.  Keep this optional so ordinary direct carriers do not get
    /// a misleading synthetic route label in stats/UI.
    pub(crate) relay_metadata: Option<super::mp_path::RelayPathMetadata>,
    pub(crate) local_resource: super::mp_path::ResourceGroupId,
    pub(crate) remote_resource: super::mp_path::ResourceGroupId,
    pub(crate) state: PathLifecycleState,
    pub(crate) measurements: PathMeasurements,
    pub(crate) telemetry: Option<MpPathTelemetry>,
    pub(crate) target_rate_bps: Option<u64>,
    /// MP_SQM_PLAN.md S2.1's `MpPathStatus.egress_device`: the physical
    /// interface's `platform_name`, or empty when this path has no resolved
    /// `EgressSocketBinding` (e.g. a relay-next-hop virtual path).
    pub(crate) egress_device: String,
    /// MP_SQM_PLAN.md S2.3's `MpPathStatus.user_policy`: the action string
    /// (`pin`/`exclude`/`pause`/`prefer`) of whichever `MpPathPolicy` matched
    /// this path, or empty when none did.
    pub(crate) user_policy: String,
    pub(crate) selection: PathSelectionDiagnostics,
}

#[derive(Debug, Clone)]
pub(crate) struct MpPeerRuntimeSnapshot {
    pub(crate) peer_id: PeerId,
    pub(crate) paths: Vec<MpPathRuntimeSnapshot>,
    pub(crate) optimization: Option<MpOptimizationSnapshot>,
    pub(crate) effective_congestion_control: String,
    /// MP_SQM_PLAN.md S2.6: what `MpConfig.congestion_control` currently
    /// resolves to -- may differ from `effective_congestion_control` when a
    /// live session was built under an older config and hasn't been rebuilt
    /// yet. Always equal to `effective_congestion_control` for a standalone
    /// session (see the `standalone` branch of `runtime_snapshots`: a
    /// standalone session's own captured CC is reported as both, since it
    /// is rebuilt directly on `session_generation` bump rather than going
    /// through a desired/effective divergence + confirm step).
    pub(crate) desired_congestion_control: String,
    /// MP_SQM_PLAN.md S2.6: `true` when a live session exists and its
    /// captured congestion control no longer matches
    /// `desired_congestion_control` -- the user must bump
    /// `MpConfig.session_generation` (not the unrelated secure-datagram
    /// rekey `session_generation` in `peers/secure_datagram.rs`) to rebuild
    /// it. `false` when there is no live session yet (nothing to reconnect)
    /// or the two already agree.
    pub(crate) reconnect_required: bool,
    /// MP_SQM_PLAN.md S1.4: `true` for a standalone `mpquic://` connection
    /// registered via `register_standalone_session` (observed only, not
    /// managed by the candidate/TopK machinery, not cleared by
    /// `clear_disabled_runtime_state`); `false` for an ordinary
    /// `MpSessionManager`-managed session. Stands in for the proto
    /// `MpPeerStatus.standalone` field that lands in S2.0; the instance-level
    /// mapping should read this flag once that field exists.
    pub(crate) standalone: bool,
    /// MP_SQM_PLAN.md S2.4: this peer's local configured Brutal send rate
    /// (`up_mbps`, converted to bits/sec), or `None` when brutal is not the
    /// configured CC.
    pub(crate) brutal_tx_bps: Option<u64>,
    /// MP_SQM_PLAN.md S2.4: this peer's most recently announced Brutal
    /// receive-rate ceiling (via `remote_rx_bps_lookup`), or `None` when
    /// unknown/not announced.
    pub(crate) peer_advertised_rx_bps: Option<u64>,
    /// MP_SQM_PLAN.md S2.10 `MpPeerStatus.data_plane`.
    pub(crate) data_plane: Option<MpDataPlaneStatus>,
    /// `MpPeerStatus.faketcp_upgrade`; `None` when no upgrade was attempted.
    pub(crate) faketcp_upgrade: Option<FakeTcpUpgradeRecord>,
}

/// The configured Brutal send rate (`up_mbps`) in bits/sec, or `None` when
/// Brutal is not the configured CC.
fn configured_brutal_tx_bps(config: &MpConfig) -> Option<u64> {
    let params: serde_json::Value = serde_json::from_str(&config.congestion_control_params_json)
        .unwrap_or(serde_json::Value::Null);
    match crate::tunnel::mp_plugin::MpCcRegistry::with_builtins()
        .resolve(&config.congestion_control, &params)
    {
        Some(Ok(crate::tunnel::mp_plugin::ResolvedCcConfig::Brutal(tunables))) => Some(
            crate::tunnel::mp_plugin::brutal_mbps_to_bits_per_sec(tunables.up_mbps),
        ),
        _ => None,
    }
}

/// The data-plane policy `PeerManager` classifies with, or `None` while MP or
/// its data plane is off.
fn enabled_data_plane_policy(config: &MpConfig) -> Option<Arc<DataPlanePolicy>> {
    Some(DataPlanePolicy::from_mp_config(config))
        .filter(|policy| config.enabled && policy.enabled)
        .map(Arc::new)
}

/// One path of an egress, as the round-trip delay fallback reads it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PathRtt {
    pub(crate) state: PathLifecycleState,
    pub(crate) sample_age_micros: Option<u64>,
    pub(crate) srtt_micros: u64,
    pub(crate) min_rtt_micros: u64,
}

/// The round-trip delay of an egress, for peers that send no one-way delay
/// (OWD_AUTORATE_PLAN.md 1.3): the smallest `srtt - min_rtt` of its active
/// paths whose sample is at most `max_age_micros` old, or `None` when there
/// is none. A standby or relay path gets no new round-trip sample, so its
/// `srtt` stays where it was and says nothing about the egress now (RFC 6817
/// Section 2.5: the current delay sample must not be older than a round
/// trip); the smallest, not the largest, because one path being slow is not
/// the egress being congested.
pub(crate) fn egress_rtt_delay_us(paths: &[PathRtt], max_age_micros: u64) -> Option<u64> {
    paths
        .iter()
        .filter(|path| {
            path.state == PathLifecycleState::AVAILABLE
                && path
                    .sample_age_micros
                    .is_some_and(|age| age <= max_age_micros)
        })
        .map(|path| path.srtt_micros.saturating_sub(path.min_rtt_micros))
        .min()
}

fn path_measurements_from_telemetry(path: &MpPathTelemetry) -> PathMeasurements {
    let sent_bytes = path.sent_bytes.max(1);
    PathMeasurements {
        btlbw: path.bandwidth_model_valid.then_some(path.btlbw).unwrap_or(0),
        delivery_rate: path
            .bandwidth_model_valid
            .then_some(path.delivery_rate)
            .unwrap_or(0),
        propagation_rtt_micros: path.windowed_min_rtt_micros,
        loss_rate: path.lost_bytes as f64 / sent_bytes as f64,
        app_limited: path.app_limited,
        sample_age_micros: path
            .bandwidth_model_valid
            .then_some(path.sample_age_micros)
            .flatten(),
        congestion_control_state: path.congestion_control_state,
        observed_local_addr: path.observed_local_addr,
    }
}

async fn path_telemetry_with_deadline<F>(
    future: F,
    deadline: std::time::Duration,
) -> Result<Vec<MpPathTelemetry>, TunnelError>
where
    F: std::future::Future<Output = Result<Vec<MpPathTelemetry>, TunnelError>>,
{
    tokio::time::timeout(deadline, future)
        .await
        .map_err(|_| TunnelError::InternalError("MP telemetry snapshot timed out".into()))?
}

const RUNTIME_SNAPSHOT_TELEMETRY_DEADLINE: std::time::Duration =
    std::time::Duration::from_millis(250);
const PATH_VALIDATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const PATH_RETIRE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(1);
/// A session slot left empty (its handshake failed, or its driver died while
/// a path was added) with no establishment running is reaped after this long.
const EMPTY_SESSION_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

/// Map TQUIC path-validation state into an accept/reject decision for the
/// EasyTier candidate table.
///
/// `None` means "still in progress, do not change lifecycle yet".
/// `Some(true)` means peer reachability is proven and the path may enter
/// become established. `Some(false)` means permanent failure.
///
/// Relay-next-hop carriers use virtual ULA addresses over EasyTier
/// encapsulation: TQUIC completes PATH_CHALLENGE/RESPONSE (peer address
/// validated → `ValidatingMTU`) but the 1200-byte PMTU probe often cannot
/// complete because the underlay MTU is the PeerConn, not the ULA. Accept
/// `ValidatingMTU` for `RelayNextHop` only.
#[cfg(feature = "mpquic")]
fn path_validation_decision(
    validation_state: tquic::PathState,
    carrier_kind: CarrierKind,
) -> Option<bool> {
    match validation_state {
        tquic::PathState::Validated => Some(true),
        tquic::PathState::ValidatingMTU if carrier_kind == CarrierKind::RelayNextHop => Some(true),
        tquic::PathState::Failed => Some(false),
        _ => None,
    }
}

/// A TQUIC path may only be scheduled after the original transport has
/// resolved a concrete peer endpoint.
fn has_concrete_remote_endpoint(remote: std::net::SocketAddr) -> bool {
    !remote.ip().is_unspecified() && remote.port() != 0
}

/// Manual paths have their own source-keyed reconcile pass, which also drops
/// their `manual_paths` bookkeeping. All auto-discovered carrier kinds are
/// withdrawn as soon as the effective provider set stops admitting them.
fn carrier_is_enabled_by_config(config: &MpConfig, carrier_kind: CarrierKind) -> bool {
    if !config.enabled {
        return false;
    }
    let Some(provider_name) = (match carrier_kind {
        CarrierKind::UdpDirect => Some("udp-direct"),
        CarrierKind::UdpPunch => Some("udp-punch"),
        CarrierKind::FakeTcpPunch => Some("faketcp-punch"),
        CarrierKind::RelayNextHop => Some("relay-next-hop"),
        CarrierKind::Manual => None,
    }) else {
        return true;
    };
    config
        .providers
        .iter()
        .any(|provider| provider == provider_name)
}

/// Rate and standby flag of every path of a session.
///
/// - `pause` and `exclude` hold an established path at a zero target: data
///   stops, but path validation and recovery packets do not (this is a
///   scheduler target rate, not a path removal). So does every unpinned path
///   while a pinned one is selected.
/// - A selected path is available. It gets no target of its own (`None`): its
///   congestion control decides how much it sends. Brutal has no bandwidth
///   estimate, so there the target is the path's share of its egress budget
///   (`split_budgets`).
/// - An established path outside the selection stands by: TQUIC sends data on
///   it only once no selected path is left, not whenever a selected path's
///   window is full (a BACKUP path, draft-ietf-quic-multipath Section 3.3).
///   Under Brutal it is held to its egress budget, so a failover cannot send
///   faster than the egress takes until the next selection.
/// - A path still validating is left alone, and a dead one has no entry.
fn build_path_targets(
    candidates: &MpCandidateTable,
    selected: &[PathKey],
    rate_driven: bool,
    budgets: &[ResourceCapacity],
    path_policies: &[MpPathPolicy],
) -> Vec<MpPathTarget> {
    // S3.2 "pin -> traffic only on that path": while a pinned path is in the
    // selection, every unpinned path is held at zero like `pause`.
    let is_pinned = |key: &PathKey| {
        candidates.get(key).is_some_and(|candidate| {
            resolve_candidate_path_policy(&candidate.spec, key.remote_addr, path_policies)
                .is_some_and(|policy| policy.action == "pin")
        })
    };
    let pin_effective = selected.iter().any(is_pinned);
    let selected_rates = if rate_driven {
        let paths = selected
            .iter()
            .filter_map(|key| Some(budgeted_path(key, candidates.get(key)?)))
            .collect::<Vec<_>>();
        split_budgets(&paths, budgets)
    } else {
        HashMap::new()
    };
    // Without a selection (every candidate excluded) no path can be held on
    // standby: nothing would be left to carry data.
    let managed = !selected.is_empty();
    candidates
        .iter()
        .filter_map(|(key, candidate)| {
            let (rate, standby) = match candidate.state {
                PathLifecycleState::Dead => return None,
                PathLifecycleState::Validating => (None, false),
                PathLifecycleState::Established { .. } => {
                    if path_is_paused(candidate, key, path_policies)
                        || (pin_effective && !is_pinned(key))
                    {
                        (Some(0), false)
                    } else if selected.contains(key) {
                        (selected_rates.get(key).copied(), false)
                    } else if managed {
                        let held = rate_driven
                            .then(|| split_budgets(&[budgeted_path(key, candidate)], budgets))
                            .and_then(|rates| rates.get(key).copied());
                        (held, true)
                    } else {
                        (None, false)
                    }
                }
            };
            Some(MpPathTarget {
                local_addr: key.local_addr,
                remote_addr: key.remote_addr,
                rate,
                standby,
            })
        })
        .collect()
}

/// The budgeted resources a path passes through: the NIC it leaves by (a
/// relay path's first hop included), then the user-declared shared bottlenecks
/// its local and remote resources were moved into, if any.
fn budgeted_path(key: &PathKey, candidate: &super::mp_path::PathCandidate) -> BudgetedPath {
    let mut resources = Vec::new();
    if let Some(nic) = &candidate.spec.egress_resource {
        resources.push(nic.clone());
    }
    for resource in [&candidate.spec.local_resource, &candidate.spec.remote_resource] {
        if resource.kind() == super::mp_path::ResourceGroupKind::SharedBottleneck
            && !resources.contains(resource)
        {
            resources.push(resource.clone());
        }
    }
    BudgetedPath {
        key: *key,
        resources,
    }
}

/// Shared by `build_path_targets` (rate override) and `runtime_snapshots`
/// (the `MpPathStatus.user_policy` readback) -- MP_SQM_PLAN.md §9's matcher
/// convention `(egress_device, carrier_kind, path.remote_addr)`, using the
/// same `debug_name_to_kebab` string the GUI is shown for `carrier_kind`.
fn resolve_candidate_path_policy<'a>(
    spec: &super::mp_path::MpPathSpec,
    remote_addr: std::net::SocketAddr,
    path_policies: &'a [MpPathPolicy],
) -> Option<&'a MpPathPolicy> {
    let egress_device = spec.egress_device_name();
    let carrier_kind = crate::utils::debug_name_to_kebab(spec.carrier_kind);
    let remote_endpoint = remote_addr.to_string();
    resolve_path_policy(path_policies, egress_device, &carrier_kind, &remote_endpoint)
}

/// `pause` and `exclude` both hold a path at a zero scheduler target: the
/// selector never chooses such a path, but a standby path would still carry
/// data once no selected path is left.
fn path_is_paused(
    candidate: &super::mp_path::PathCandidate,
    key: &PathKey,
    path_policies: &[MpPathPolicy],
) -> bool {
    resolve_candidate_path_policy(&candidate.spec, key.remote_addr, path_policies)
        .is_some_and(|policy| policy.action == "pause" || policy.action == "exclude")
}

/// Why an established path is not a selection candidate (`MpPathStatus`
/// `not_selected_reason`).
pub(crate) const LEFT_OUT_POLICY: &str = "policy";
pub(crate) const LEFT_OUT_LOSSY_PATH: &str = "lossy-path";
pub(crate) const LEFT_OUT_LOSSY_FIRST_HOP: &str = "lossy-first-hop";
pub(crate) const LEFT_OUT_UNACKED: &str = "unacked";

/// What the selector chooses from, with the user's path policies.
#[derive(Default)]
struct SelectionInput {
    paths: Vec<SelectorPath>,
    pinned: HashSet<PathKey>,
    /// The established paths kept out of `paths`, and why.
    left_out: HashMap<PathKey, &'static str>,
}

/// The established paths the selector may choose, ranked by their propagation
/// RTT and transport, with the user's policies applied: `exclude` or
/// `pause` takes a path out, `pin` is handed to the selector, `prefer`
/// becomes an RTT advantage. A paused path stays established and gets a zero
/// target rate in `build_path_targets` (so it can resume at once), but it is
/// not a candidate: selecting it would leave the session with no path that
/// carries data. (The Top-K code selected it, so with kmax=1 pausing the
/// selected path starved the session.)
///
/// ET: a lossy path stays out while a clean one is selectable. iroh ignores
/// loss (a direct path beats a relay whatever it loses), and the lowest-RTT
/// path would be used even at 38% loss (MP_WORKLIST.md L108). Only a path
/// that is itself selectable counts as the clean one -- a path the user
/// excluded or paused is no candidate, and letting it keep the lossy paths
/// out left no path at all.
///
/// ET: a relay path also counts as lossy when its physical first hop loses
/// EasyTier pings (`first_hop_loss`), and as unreachable when the first hop
/// answers none: a relay path that carries little cannot gather the byte-based
/// `recent_loss`, yet its first hop is pinged all the time (MP weak-network
/// plan R3). Like the lossy case, a worse class gives way only to a better
/// one: any path that is not unreachable keeps an unreachable one out, so the
/// session never ends up with no path at all.
///
/// ET: a path whose sent bytes get no acknowledgement (`is_unacked`) counts
/// as unreachable too, the way Linux MPTCP stops using a stale subflow while
/// another one is not: TQUIC alone keeps sending on it (see
/// `mp_path::unacked_limit`).
fn selection_input(
    candidates: &MpCandidateTable,
    path_policies: &[MpPathPolicy],
    first_hop_loss: &HashMap<PeerId, f64>,
) -> SelectionInput {
    use super::mp_path::FirstHopHealth;

    let mut input = SelectionInput::default();
    // (path, the worse of its own and its first hop's class, why it gives way)
    let mut selectable = Vec::new();
    for (key, candidate) in candidates.iter() {
        if !candidate.state.is_established() {
            continue;
        }
        let policy = resolve_candidate_path_policy(&candidate.spec, key.remote_addr, path_policies);
        let mut prefer_weight = 1.0;
        if let Some(policy) = policy {
            match policy.action.as_str() {
                "exclude" | "pause" => {
                    input.left_out.insert(*key, LEFT_OUT_POLICY);
                    continue;
                }
                "pin" => {
                    input.pinned.insert(*key);
                }
                "prefer" => prefer_weight = policy.prefer_weight,
                _ => {}
            }
        }
        let (tier, rtt_bias) = transport_bias(candidate.spec.carrier_kind, key.remote_addr);
        let mut path = SelectorPath::new(
            *key,
            tier,
            candidate.measurements.propagation_rtt_micros,
            rtt_bias,
        );
        path.rtt_bias_micros += prefer_bias_micros(path.rtt_micros, prefer_weight);
        let first_hop = candidate
            .spec
            .relay_metadata
            .and_then(|metadata| first_hop_loss.get(&metadata.egress_first_hop_peer_id))
            .map_or(FirstHopHealth::Clean, |&loss| FirstHopHealth::from_loss(loss));
        let (class, reason) = if first_hop == FirstHopHealth::Unreachable {
            (FirstHopHealth::Unreachable, LEFT_OUT_LOSSY_FIRST_HOP)
        } else if candidate.is_unacked() {
            (FirstHopHealth::Unreachable, LEFT_OUT_UNACKED)
        } else if candidate.is_lossy() {
            (FirstHopHealth::Lossy, LEFT_OUT_LOSSY_PATH)
        } else {
            (first_hop, LEFT_OUT_LOSSY_FIRST_HOP)
        };
        selectable.push((path, class, reason));
    }
    let best_class = selectable.iter().map(|(_, class, _)| *class).min();
    for (path, class, reason) in selectable {
        if Some(class) > best_class && !input.pinned.contains(&path.key) {
            input.left_out.insert(path.key, reason);
        } else {
            input.paths.push(path);
        }
    }
    input
}

/// MP_SQM_PLAN.md S2.4 rate negotiation (consume half): cap every target's
/// rate at the peer's announced Brutal receive-rate ceiling, bits/sec,
/// matching `MpPathTarget.rate`'s own unit. A rate left as
/// `None` ("not managed") is capped too: TQUIC schedules such a validated path
/// natively, which for Brutal means at the full `up_mbps` -- -- the
/// common case for a Brutal path, which has no bandwidth model -- while `set_scheduler_target_rate` activates a path for `None` and
/// any positive rate alike. This is applied per-path rather than
/// as a whole-session budget: conservative for a genuinely multi-path
/// session to one peer (each path is independently capped at the peer's
/// *total* announced downlink, so the combined rate could in principle still
/// exceed it), but simple and correct for the common single-active-path
/// case, and this codebase does not otherwise track a cross-path aggregate
/// rate to cap instead. Brutal sends at the installed target (vendor/tquic
/// brutal.rs `effective_bps`): `min(peer down, budget share)`, the share
/// being cut from the egress's autorate budget (`split_budgets`); `up_mbps`
/// is only where a path starts before it has one.
fn clamp_targets_to_peer_rx_cap(
    targets: Vec<MpPathTarget>,
    peer_rx_cap_bps: Option<u64>,
) -> Vec<MpPathTarget> {
    let Some(cap) = peer_rx_cap_bps else {
        return targets;
    };
    targets
        .into_iter()
        .map(|mut target| {
            target.rate = Some(target.rate.map_or(cap, |rate| rate.min(cap)));
            target
        })
        .collect()
}

impl MpSessionManager {
    /// A punched path was dropped after validation without anything having
    /// arrived on it: hold further punches of that kind to the peer for
    /// longer each time in a row.
    fn note_silent_punch_drop(&self, peer_id: PeerId, kind: CarrierKind) {
        let mut entry = self
            .punch_drops
            .entry((peer_id, kind))
            .or_insert_with(|| PunchDropBackoff {
                backoff: crate::connector::udp_hole_punch::BackOff::new(
                    PUNCH_DROP_BACKOFF_MS.to_vec(),
                ),
                held_until: Instant::now(),
            });
        let wait = entry.backoff.next_backoff();
        entry.held_until = Instant::now() + std::time::Duration::from_millis(wait);
        tracing::info!(
            peer_id,
            ?kind,
            wait_ms = wait,
            "punched path dropped after validation without receiving anything, holding further punches"
        );
    }

    async fn apply_path_events(&self, peer_id: PeerId, events: Vec<MpPathEvent>) -> bool {
        let Some(candidate_slot) = self.candidates.get(&peer_id).map(|entry| entry.clone()) else {
            return false;
        };
        let mut candidates = candidate_slot.lock().await;
        let mut changed = false;
        for event in events {
            let MpPathEvent::Down(key) = event;
            let tracked_key =
                candidates.get(&key).is_some().then_some(key).or_else(|| {
                    candidates.resolve_wildcard_remote(key.local_addr, key.remote_addr)
                });
            if let Some(tracked_key) = tracked_key {
                let silent_punch = candidates.get(&tracked_key).is_some_and(|candidate| {
                    matches!(
                        candidate.spec.carrier_kind,
                        CarrierKind::UdpPunch | CarrierKind::FakeTcpPunch
                    ) && candidate.silent_since_validated()
                        && candidate.state != PathLifecycleState::Dead
                });
                let kind = candidates.get(&tracked_key).map(|c| c.spec.carrier_kind);
                // S-I4b: a dead path is no longer a candidate, so the next
                // selection replaces it at once -- the switching threshold only
                // protects a path that is still there.
                if candidates.mark_dead(&tracked_key) {
                    changed = true;
                    if silent_punch && let Some(kind) = kind {
                        self.note_silent_punch_drop(peer_id, kind);
                    }
                }
            }
        }
        changed
    }

    pub(crate) fn new(egress_quality: Arc<EgressQualityManager>) -> Self {
        Self::new_with_config(gen_default_mp_config(), egress_quality)
    }

    pub(crate) fn new_with_config(
        config: MpConfig,
        egress_quality: Arc<EgressQualityManager>,
    ) -> Self {
        let data_plane_hint = enabled_data_plane_policy(&config);
        Self {
            sessions: DashMap::new(),
            candidates: DashMap::new(),
            optimization_snapshots: DashMap::new(),
            first_hop_loss: std::sync::RwLock::new(HashMap::new()),
            pending_path_opens: Arc::new(DashMap::new()),
            egress_quality,
            egress_sample_state: Mutex::new(HashMap::new()),
            egress_snapshots: DashMap::new(),
            manual_paths: DashMap::new(),
            manual_reconcile_lock: Mutex::new(()),
            config: RwLock::new(config),
            standalone_sessions: DashMap::new(),
            resolved_egress_routes: Mutex::new(HashMap::new()),
            reflector_interfaces: std::sync::Mutex::new(HashMap::new()),
            reflector_socket_mark: std::sync::Mutex::new(None),
            remote_rx_bps_lookup: RwLock::new(None),
            remote_dataplane_caps_lookup: RwLock::new(None),
            data_plane_hint: std::sync::RwLock::new(data_plane_hint),
            ptb_limits: DashMap::new(),
            ptb_sent: DashMap::new(),
            session_fingerprints: DashMap::new(),
            faketcp_upgrades: DashMap::new(),
            establishing: DashMap::new(),
            primary_keys: DashMap::new(),
            empty_since: DashMap::new(),
            punch_drops: DashMap::new(),
            local_peer_id: 0,
        }
    }

    /// The `socket_mark` flag (SO_MARK) for the Autorate reflector sockets.
    pub(crate) fn with_reflector_socket_mark(self, mark: Option<u32>) -> Self {
        *self.reflector_socket_mark.lock().unwrap() = mark;
        self
    }

    pub(crate) fn with_local_peer_id(mut self, local_peer_id: PeerId) -> Self {
        self.local_peer_id = local_peer_id;
        self
    }

    /// MP_SQM_PLAN.md S2.4: install (or clear, with `None`) the peer
    /// rx-announcement lookup `select_active_paths` consults every control tick.
    pub(crate) async fn set_remote_rx_bps_lookup(
        &self,
        lookup: Option<Arc<dyn Fn(PeerId) -> Option<u64> + Send + Sync>>,
    ) {
        *self.remote_rx_bps_lookup.write().await = lookup;
    }

    /// MP_SQM_PLAN.md S2.10: install (or clear) the peer caps lookup.
    pub(crate) async fn set_remote_dataplane_caps_lookup(
        &self,
        lookup: Option<Arc<dyn Fn(PeerId) -> Option<u32> + Send + Sync>>,
    ) {
        *self.remote_dataplane_caps_lookup.write().await = lookup;
    }

    async fn peer_dataplane_caps(&self, peer_id: PeerId) -> Option<u32> {
        let lookup = self.remote_dataplane_caps_lookup.read().await.clone()?;
        lookup(peer_id)
    }

    /// MP_SQM_PLAN.md S2.10: the policy `PeerManager` classifies with, or
    /// `None` while the data plane is off. Never blocks, like
    /// `sqm_enabled_hint`.
    pub(crate) fn data_plane_hint(&self) -> Option<Arc<DataPlanePolicy>> {
        self.data_plane_hint
            .read()
            .ok()
            .and_then(|hint| hint.clone())
    }

    /// Inner IP packets to `peer_id` longer than this are answered with ICMP
    /// Packet Too Big instead of being sent (oversize policy `icmp_ptb`).
    pub(crate) fn ptb_limit(&self, peer_id: PeerId) -> Option<usize> {
        self.ptb_limits.get(&peer_id).map(|limit| *limit)
    }

    pub(crate) fn note_ptb_sent(&self, peer_id: PeerId) {
        *self.ptb_sent.entry(peer_id).or_insert(0) += 1;
    }

    /// Send the current policy and the peer's caps to every MP-managed
    /// session and refresh `ptb_limits` from their status.
    async fn push_data_plane_state(&self, config: &MpConfig) {
        let policy = Arc::new(DataPlanePolicy::from_mp_config(config));
        let handles = self
            .sessions
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect::<Vec<_>>();
        let mut live = HashSet::new();
        for (peer_id, slot) in handles {
            let Ok(session) = slot.try_lock() else {
                continue;
            };
            let Some(handle) = session.as_ref().map(|session| session.handle.clone()) else {
                continue;
            };
            drop(session);
            let caps = self.peer_dataplane_caps(peer_id).await;
            if !handle.set_data_plane(policy.clone(), caps) {
                continue;
            }
            if policy.oversize != OversizePolicy::IcmpPtb {
                continue;
            }
            let Ok(Ok(status)) = tokio::time::timeout(
                RUNTIME_SNAPSHOT_TELEMETRY_DEADLINE,
                handle.data_plane_status(),
            )
            .await
            else {
                continue;
            };
            if status.negotiated == "datagram" && status.max_datagram_bytes > 0 {
                self.ptb_limits.insert(
                    peer_id,
                    inner_packet_limit(status.max_datagram_bytes as usize),
                );
                live.insert(peer_id);
            }
        }
        self.ptb_limits.retain(|peer_id, _| live.contains(peer_id));
    }

    /// `peer_id`'s announced Brutal receive-rate ceiling, or `None` when
    /// brutal is not the configured CC, no lookup is installed, or the peer
    /// has not announced one. Re-reads `self.config`/the lookup every call
    /// (cheap `RwLock` reads, no caching) so a hot config change or a
    /// changed announcement applies on the very next control tick, per
    /// MP_SQM_PLAN.md S2.4.
    async fn peer_rx_cap_bps(&self, peer_id: PeerId) -> Option<u64> {
        let congestion_control = self.config.read().await.congestion_control.clone();
        if CongestionControlProfile::parse(&congestion_control) != Ok(CongestionControlProfile::Brutal) {
            return None;
        }
        let lookup = self.remote_rx_bps_lookup.read().await.clone()?;
        lookup(peer_id)
    }

    /// MP_SQM_PLAN.md S2.5: "SQM 开启时即计算 flow hash（当前仅加权 MP 开启才算）"
    /// -- `peers::peer_manager::PeerManager::packet_flow_hash` (a hot,
    /// synchronous packet-send-path function) needs this on every packet, so
    /// it uses `try_read` rather than `self.config.read().await`: a `false`
    /// on lock contention just means this one packet's flow hash is skipped
    /// (the same "best effort, never block the send path" tradeoff
    /// `refresh_all_egress_capacities`'s `try_lock` on session slots already
    /// makes elsewhere in this file), not a correctness issue -- the next
    /// packet tries again.
    pub(crate) fn sqm_enabled_hint(&self) -> bool {
        self.config
            .try_read()
            .map(|config| config.sqm.as_ref().is_some_and(|sqm| sqm.enabled))
            .unwrap_or(false)
    }

    /// MP_SQM_PLAN.md S1.4: register a standalone `mpquic://` connection's
    /// session handle once its `PeerConn` handshake has yielded `peer_id`.
    /// Overwrites any previous entry for the same peer_id (a reconnect).
    ///
    /// With MP enabled the session is adopted instead (S-I19): it joins the
    /// candidate table and the optimizer and is managed like a session MP
    /// built itself (path selection, punching more paths, rate allocation).
    /// It stays standalone when MP is off, or when the peer already has a
    /// live managed session: the one established first is kept.
    pub(crate) async fn register_standalone_session(
        &self,
        peer_id: PeerId,
        handle: MpSessionHandle,
        congestion_control: &'static str,
        is_server: bool,
    ) {
        if self.config.read().await.enabled
            && self
                .adopt_standalone_session(peer_id, &handle, congestion_control, is_server)
                .await
        {
            return;
        }
        self.standalone_sessions
            .insert(peer_id, (handle, congestion_control));
    }

    /// Whether the session was adopted, see `register_standalone_session`.
    async fn adopt_standalone_session(
        &self,
        peer_id: PeerId,
        handle: &MpSessionHandle,
        congestion_control: &'static str,
        is_server: bool,
    ) -> bool {
        let Ok(profile) = CongestionControlProfile::parse(congestion_control) else {
            return false;
        };
        let Ok(Ok(paths)) =
            tokio::time::timeout(RUNTIME_SNAPSHOT_TELEMETRY_DEADLINE, handle.path_telemetry())
                .await
        else {
            return false;
        };
        if paths.is_empty() {
            return false;
        }
        let config = self.config.read().await.clone();
        let slot = self
            .sessions
            .entry(peer_id)
            .or_insert_with(|| Arc::new(Mutex::new(None)))
            .clone();
        let mut session = slot.lock().await;
        if session
            .as_ref()
            .is_some_and(|current| !current.handle.is_closed())
        {
            return false;
        }
        let candidate_slot = self
            .candidates
            .entry(peer_id)
            .or_insert_with(|| Arc::new(Mutex::new(MpCandidateTable::default())))
            .clone();
        {
            let mut candidates = candidate_slot.lock().await;
            for path in &paths {
                let carrier: Arc<dyn crate::tunnel::mpquic::MpDatagramPath> =
                    Arc::new(AdoptedPath {
                        local: path.local_addr,
                    });
                let device =
                    crate::tunnel::common::get_interface_name_by_ip(&path.local_addr.ip());
                let mut spec = device
                    .as_deref()
                    .and_then(|device| {
                        MpPathSpec::with_egress_device(
                            carrier.clone(),
                            path.remote_addr,
                            device,
                            CarrierKind::UdpDirect,
                        )
                        .ok()
                    })
                    .unwrap_or_else(|| {
                        MpPathSpec::with_default_resources(
                            carrier,
                            path.remote_addr,
                            CarrierKind::UdpDirect,
                        )
                    });
                Self::apply_resource_group_overrides(&mut spec, &config);
                let key = spec.key;
                candidates.upsert(spec, Instant::now());
                candidates.begin_validation(&key);
                // A path still validating is left to the control tick.
                if let Some(validated) =
                    path_validation_decision(path.validation_state, CarrierKind::UdpDirect)
                {
                    candidates.record_validation(&key, validated);
                }
            }
        }
        self.session_fingerprints
            .insert(peer_id, mp_reconnect_fingerprint(&config));
        self.empty_since.remove(&peer_id);
        self.standalone_sessions.remove(&peer_id);
        *session = Some(Session {
            handle: handle.clone(),
            congestion_control: profile,
            is_server,
        });
        tracing::info!(peer_id, paths = paths.len(), "adopted a directly connected mpquic session into MP");
        true
    }

    pub(crate) async fn set_config(&self, config: MpConfig) -> Result<(), TunnelError> {
        validate_mp_config(&config)
            .map_err(|error| TunnelError::InternalError(error.to_string()))?;
        let previous = self.config.read().await.clone();
        // MP_SQM_PLAN.md S2.6: `MpConfig.session_generation` (unrelated to
        // the secure-datagram rekey `session_generation` in
        // `peers/secure_datagram.rs`/`peer_conn.rs`/`peer_session.rs`/
        // `relay_peer_map.rs` -- see that proto field's own doc comment) is
        // the user-confirmed trigger to rebuild every mpquic session so
        // `reconnect`-classified field changes (desired congestion control,
        // SQM enable/target/interval, ...) actually take effect. It is
        // independent of `config.enabled`: standalone sessions (S1.4) are
        // plain point-to-point mpquic tunnels, never part of the MP
        // on/off-gated optimizer/candidate machinery, so they must still
        // rebuild on a generation bump even while MP stays disabled.
        let generation_bumped = config.session_generation != previous.session_generation;
        if let Ok(mut hint) = self.data_plane_hint.write() {
            *hint = enabled_data_plane_policy(&config);
        }
        if !config.enabled {
            self.clear_disabled_runtime_state().await;
            *self.config.write().await = config;
            if generation_bumped {
                self.shutdown_all_standalone_sessions().await;
            }
            return Ok(());
        }
        let runtime = Self::quic_config(&config)?;
        let session_slots = self
            .sessions
            .iter()
            .map(|session| session.value().clone())
            .collect::<Vec<_>>();
        for slot in session_slots {
            let handle = {
                let session = slot.lock().await;
                session.as_ref().map(|session| session.handle.clone())
            };
            if let Some(handle) = handle {
                // A session can be mid-teardown (peer removed, generation
                // bump from a previous call, handshake never completed)
                // concurrently with this loop, since `session_slots` is a
                // snapshot taken before any lock is re-acquired. That one
                // session's driver being gone must not abort `set_config`
                // for every other session, nor skip the config persist /
                // autorate bounds wiring / generation-bump teardown below
                // it -- this push is a best-effort hot-apply optimization,
                // not a precondition for the rest of set_config succeeding.
                if let Err(error) = handle.set_scheduler(runtime).await {
                    tracing::debug!(
                        ?error,
                        "set_config: skipped live scheduler push for a session \
                         that is not accepting driver commands (already closing/closed)"
                    );
                }
            }
        }
        self.retire_paths_for_disabled_providers(&config).await?;
        self.reapply_resource_group_overrides(&config).await;
        // MP_SQM_PLAN.md S2.6: the Autorate bounds are hot. Compared against
        // the manager's live state, not the previous config: the first call
        // carries the very config this manager was built from, which the
        // manager has not applied yet.
        let sqm = config.sqm.as_ref();
        let autorate_bounds = sqm.map_or((0, 0), |sqm| (sqm.autorate_min_bps, sqm.autorate_max_bps));
        if autorate_bounds != self.egress_quality.autorate_bounds() {
            self.egress_quality
                .set_autorate_bounds(autorate_bounds.0, autorate_bounds.1);
        }
        // `mp.sqm.target_ms`/`interval_ms` are CAKE's `target` and `rtt`, hot too.
        let (target_ms, interval_ms) =
            sqm.map_or((0, 0), |sqm| (sqm.target_ms, sqm.interval_ms));
        self.egress_quality.set_cake_timing(target_ms, interval_ms);
        *self.config.write().await = config;
        if generation_bumped {
            // MP-managed peers: reuse the existing `forget_peer` teardown
            // (via `forget_all_peers`) -- EasyTier's own peer-liveness
            // reconnect logic recreates the tunnel from the now-current
            // config. Standalone sessions go through their own teardown
            // below since `forget_peer`/`forget_all_peers` never touch
            // `standalone_sessions` (see that field's own doc comment).
            self.forget_all_peers().await;
            self.shutdown_all_standalone_sessions().await;
        }
        Ok(())
    }

    /// MP_SQM_PLAN.md S2.6: the standalone-session half of a
    /// `session_generation` bump. Mirrors `forget_peer`'s shutdown-then-drop
    /// shape, but on `standalone_sessions` (a separate map `forget_peer`/
    /// `forget_all_peers` never touch): shuts each handle down directly and
    /// removes the entry immediately, so a runtime snapshot taken before the
    /// reconnect completes reports nothing rather than a dead handle's stale
    /// congestion control. ET's existing connector reconnect path recreates
    /// the tunnel and calls `register_standalone_session` again once it
    /// succeeds (that method's own doc notes it overwrites any prior entry
    /// for the same peer_id).
    async fn shutdown_all_standalone_sessions(&self) -> usize {
        let peer_ids = self
            .standalone_sessions
            .iter()
            .map(|entry| *entry.key())
            .collect::<Vec<_>>();
        let mut count = 0;
        for peer_id in peer_ids {
            if let Some((_, (handle, _))) = self.standalone_sessions.remove(&peer_id) {
                handle.shutdown();
                count += 1;
            }
        }
        count
    }

    /// Disabling MP is an ownership boundary: no retired candidate, optimizer
    /// decision, or SQM estimate may survive into the runtime API.  Leaving a
    /// dead entry behind is especially misleading because the latest TopK
    /// snapshot can still name it as active until another enabled control tick
    /// runs.  Stop every TQUIC session and clear all derived state atomically
    /// from the manager's point of view.
    async fn clear_disabled_runtime_state(&self) {
        let session_slots = self
            .sessions
            .iter()
            .map(|entry| entry.value().clone())
            .collect::<Vec<_>>();
        for slot in session_slots {
            let handle = {
                let session = slot.lock().await;
                session.as_ref().map(|session| session.handle.clone())
            };
            if let Some(handle) = handle {
                handle.shutdown();
            }
        }

        self.sessions.clear();
        self.session_fingerprints.clear();
        self.faketcp_upgrades.clear();
        self.candidates.clear();
        self.optimization_snapshots.clear();
        self.manual_paths.clear();
        // Only MP's own per-path sample bookkeeping and its re-keyed
        // ResourceGroupId snapshot cache are torn down here. The shared
        // `egress_quality` manager itself is NOT cleared: it is owned by
        // `GlobalCtx`, one per instance, and other consumers (a future
        // non-MP session) must keep seeing the same physical-egress ledger.
        self.egress_sample_state.lock().await.clear();
        self.egress_snapshots.clear();
        self.ptb_limits.clear();
    }

    async fn retire_paths_for_disabled_providers(
        &self,
        config: &MpConfig,
    ) -> Result<usize, TunnelError> {
        let slots = self
            .candidates
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect::<Vec<_>>();
        let mut retired = 0;
        for (peer_id, slot) in slots {
            let keys = slot
                .lock()
                .await
                .iter()
                .filter_map(|(key, candidate)| {
                    (candidate.state != PathLifecycleState::Dead
                        && !carrier_is_enabled_by_config(config, candidate.spec.carrier_kind))
                    .then_some(*key)
                })
                .collect::<Vec<_>>();
            for key in keys {
                retired += usize::from(self.retire_path_unless_last(peer_id, &key).await?);
            }
        }
        Ok(retired)
    }

    async fn reapply_resource_group_overrides(&self, config: &MpConfig) -> usize {
        let slots = self
            .candidates
            .iter()
            .map(|entry| entry.value().clone())
            .collect::<Vec<_>>();
        let mut reclassified = 0;
        for slot in slots {
            let mut candidates = slot.lock().await;
            for (_, candidate) in candidates.iter_mut() {
                let previous = (
                    candidate.spec.local_resource.clone(),
                    candidate.spec.remote_resource.clone(),
                );
                Self::apply_resource_group_overrides(&mut candidate.spec, config);
                if previous
                    != (
                        candidate.spec.local_resource.clone(),
                        candidate.spec.remote_resource.clone(),
                    )
                {
                    reclassified += 1;
                }
            }
        }
        reclassified
    }

    pub(crate) async fn config(&self) -> MpConfig {
        self.config.read().await.clone()
    }

    /// Takes `key` out of the session and marks its candidate dead.
    ///
    /// Fails with [`is_last_open_path`] when it is the last path the session
    /// has: the driver keeps it (noq `ClosePathError::LastOpenPath`) and so
    /// does this, the candidate stays as it was. QUIC decides whether such a
    /// session lives, and the path can carry it again once its first hop or
    /// NIC returns.
    pub(crate) async fn retire_path(
        &self,
        peer_id: PeerId,
        key: &crate::tunnel::mpquic::PathKey,
    ) -> Result<(), TunnelError> {
        let removal = self.remove_path_from_session(peer_id, key).await;
        if let Err(error) = &removal
            && is_last_open_path(error)
        {
            return removal;
        }
        if let Some(candidate_slot) = self.candidates.get(&peer_id).map(|entry| entry.clone()) {
            candidate_slot.lock().await.mark_dead(key);
        }
        removal
    }

    /// [`Self::retire_path`] for a caller that retires many paths and goes on
    /// when one is kept as the session's last: `Ok(false)` then.
    async fn retire_path_unless_last(
        &self,
        peer_id: PeerId,
        key: &crate::tunnel::mpquic::PathKey,
    ) -> Result<bool, TunnelError> {
        match self.retire_path(peer_id, key).await {
            Ok(()) => Ok(true),
            Err(error) if is_last_open_path(&error) => {
                tracing::info!(
                    peer_id,
                    ?key,
                    "kept the session's last path; QUIC decides whether the session lives"
                );
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    async fn remove_path_from_session(
        &self,
        peer_id: PeerId,
        key: &crate::tunnel::mpquic::PathKey,
    ) -> Result<(), TunnelError> {
        let Some(session_slot) = self.sessions.get(&peer_id).map(|entry| entry.clone()) else {
            return Ok(());
        };
        let handle = {
            let session = session_slot.lock().await;
            session.as_ref().map(|session| session.handle.clone())
        };
        if let Some(handle) = handle {
            if let Err(error) = handle.remove_path(key.local_addr, key.remote_addr).await {
                // A peer/tunnel may disappear immediately before a configured
                // path is removed. In that case the driver and every carrier it
                // owned are already gone, so path retirement is complete even
                // though the remove-path acknowledgement cannot be delivered.
                if handle.is_closed() {
                    let mut session = session_slot.lock().await;
                    if session
                        .as_ref()
                        .is_some_and(|session| session.handle.is_closed())
                    {
                        *session = None;
                    }
                } else {
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn remove_manual_path(&self, source: &str) -> Result<(), TunnelError> {
        let Some(tracked) = self.manual_paths.get(source).map(|entry| *entry) else {
            return Ok(());
        };
        if !self
            .retire_path_unless_last(tracked.peer_id, &tracked.key)
            .await?
        {
            // Kept as the session's last path: still tracked, so the next
            // reconcile tries again.
            return Ok(());
        }
        self.manual_paths.remove(source);
        Ok(())
    }

    pub(crate) async fn reconcile_manual_paths(
        &self,
        global_ctx: &crate::common::global_ctx::ArcGlobalCtx,
        my_peer_id: PeerId,
    ) -> Result<Vec<ManualPathOffer>, TunnelError> {
        let Ok(_reconcile_guard) = self.manual_reconcile_lock.try_lock() else {
            return Ok(Vec::new());
        };
        let config = self.config.read().await.clone();
        let enabled = config.enabled && config.providers.iter().any(|p| p == "manual");
        let desired = if enabled {
            config.manual_paths.iter().cloned().collect::<HashSet<_>>()
        } else {
            HashSet::new()
        };

        let stale = self
            .manual_paths
            .iter()
            .filter_map(|entry| (!desired.contains(entry.key())).then(|| entry.key().clone()))
            .collect::<Vec<_>>();
        for source in stale {
            self.remove_manual_path(&source).await?;
        }

        let mut offers = Vec::new();
        for source in desired {
            if self.manual_paths.contains_key(&source) {
                continue;
            }
            let parsed = ManualUdpPathConfig::parse(&source)
                .map_err(|error| TunnelError::InternalError(error.to_string()))?;
            let provider = parsed
                .bind_provider(global_ctx)
                .map_err(|error| TunnelError::InternalError(error.to_string()))?;
            let mut specs = provider
                .discover()
                .await
                .map_err(|error| TunnelError::InternalError(error.to_string()))?;
            if specs.len() != 1 {
                return Err(TunnelError::InternalError(format!(
                    "manual MP provider returned {} paths, expected one",
                    specs.len()
                )));
            }
            let spec = specs.pop().unwrap();
            let key = spec.key;
            let is_server = parsed.is_server(my_peer_id);
            let outcome = self
                .offer_path_spec(
                    parsed.peer_id,
                    is_server,
                    spec,
                    parsed.remote_url(),
                    "mpquic_manual",
                )
                .await?;
            self.manual_paths.insert(
                source.clone(),
                ManagedManualPath {
                    peer_id: parsed.peer_id,
                    key,
                },
            );
            offers.push(ManualPathOffer {
                source,
                peer_id: parsed.peer_id,
                is_server,
                outcome,
            });
        }
        Ok(offers)
    }

    fn quic_config(config: &MpConfig) -> Result<MpQuicSessionConfig, TunnelError> {
        let params: serde_json::Value = serde_json::from_str(&config.scheduler_params_json)
            .map_err(|error| TunnelError::InternalError(error.to_string()))?;
        let resolved = crate::tunnel::mp_plugin::MpSchedulerRegistry::with_builtins()
            .resolve(&config.packet_scheduler, &params)
            .ok_or_else(|| {
                TunnelError::InternalError(format!(
                    "unknown MP packet scheduler {:?}",
                    config.packet_scheduler
                ))
            })?;
        let runtime: MpQuicSessionConfig = resolved.into();
        let mut runtime =
            crate::tunnel::mpquic::apply_congestion_control_from_mp_config(runtime, config)?;
        runtime.establishment_timeout =
            std::time::Duration::from_millis(config.establishment_timeout_ms);
        // MP_SQM_PLAN.md S2.10: fixed for the session (the transport
        // parameter is exchanged in the handshake); the rest of `data_plane`
        // is pushed hot through `push_data_plane_state`.
        let data_plane = config.data_plane.as_ref();
        runtime.data_plane = data_plane.is_some_and(|plane| plane.enabled);
        Ok(runtime)
    }

    fn apply_resource_group_overrides(spec: &mut MpPathSpec, config: &MpConfig) {
        spec.local_resource = spec.base_local_resource.clone();
        spec.remote_resource = spec.base_remote_resource.clone();
        if let Some(device) = spec
            .egress_resource
            .as_ref()
            .and_then(|resource| resource.egress_device_name())
            && let Some(group) = config
                .resource_groups
                .iter()
                .find(|group| group.egress_devices.iter().any(|member| member == device))
        {
            spec.local_resource = super::mp_path::ResourceGroupId::shared_bottleneck(&group.name);
        }
        if let Some(group) = config.resource_groups.iter().find(|group| {
            group.remote_endpoints.iter().any(|endpoint| {
                let endpoint = endpoint.trim();
                endpoint
                    .parse::<std::net::SocketAddr>()
                    .is_ok_and(|addr| addr == spec.key.remote_addr)
                    || endpoint
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip == spec.key.remote_addr.ip())
            })
        }) {
            spec.remote_resource = super::mp_path::ResourceGroupId::shared_bottleneck(&group.name);
        }
    }

    pub(crate) async fn offer_provider(
        &self,
        peer_id: PeerId,
        is_server: bool,
        provider: &dyn MpPathProvider,
        remote_url: url::Url,
        tunnel_type: &str,
    ) -> Result<Vec<OfferPathResult>, TunnelError> {
        let specs = provider
            .discover()
            .await
            .map_err(|error| TunnelError::InternalError(error.to_string()))?;
        if specs.is_empty() {
            return Err(TunnelError::InternalError(format!(
                "{:?} MP path provider returned no candidates",
                provider.kind()
            )));
        }

        let mut results = Vec::with_capacity(specs.len());
        for spec in specs {
            results.push(
                self.offer_path_spec(peer_id, is_server, spec, remote_url.clone(), tunnel_type)
                    .await?,
            );
        }
        Ok(results)
    }

    pub(crate) async fn offer_path_spec(
        &self,
        peer_id: PeerId,
        is_server: bool,
        mut spec: MpPathSpec,
        remote_url: url::Url,
        tunnel_type: &str,
    ) -> Result<OfferPathResult, TunnelError> {
        if !has_concrete_remote_endpoint(spec.key.remote_addr) {
            return Err(TunnelError::InternalError(format!(
                "refusing to schedule MP path with unresolved remote endpoint {}",
                spec.key.remote_addr
            )));
        }
        let config = self.config.read().await.clone();
        Self::apply_resource_group_overrides(&mut spec, &config);
        let key = spec.key;
        let candidate_slot = self
            .candidates
            .entry(peer_id)
            .or_insert_with(|| Arc::new(Mutex::new(MpCandidateTable::default())))
            .clone();
        let already_tracked = {
            let mut candidates = candidate_slot.lock().await;
            let already_tracked = candidates
                .get(&key)
                .is_some_and(|candidate| candidate.state != PathLifecycleState::Dead);
            candidates.upsert(spec.clone(), Instant::now());
            if !already_tracked {
                candidates.begin_validation(&key);
            }
            already_tracked
        };
        let remote = spec.key.remote_addr;
        // Real identity of `path`'s physical egress -- MP_SQM_PLAN.md §4.4
        // (b): this is what lets the MP-managed path's `MpPathRegistry` entry
        // govern it under a real `EgressScope` (the one its egress sampling
        // and per-NIC limits use) instead of `EgressStableId::Fallback`.
        let nic_scope = Self::path_nic_scope(&spec, &*self.resolved_egress_routes.lock().await);
        let path = spec.carrier;
        let slot = self
            .sessions
            .entry(peer_id)
            .or_insert_with(|| Arc::new(Mutex::new(None)))
            .clone();
        // An offer arriving restarts the empty slot's grace period.
        self.empty_since.remove(&peer_id);
        let preferred = self.direction_preferred(peer_id, is_server);
        if let Some((handle, current_is_server)) = Self::session_direction(&slot).await {
            // Only the preferred direction replaces a session of the other
            // one, and only by finishing its own handshake (below).
            if handle.is_closed() || !preferred || self.direction_preferred(peer_id, current_is_server) {
                if already_tracked {
                    return Ok(OfferPathResult::PathAdded);
                }
                return self.add_path_to_session(peer_id, &slot, handle, &candidate_slot, &key, path, remote, nic_scope)
                    .await;
            }
        }

        // No usable session yet. The handshake below can take the whole
        // `establishment_timeout`; it runs without the session slot, and
        // without waiting for another offer (see `PeerEstablishment`).
        let runtime = Self::quic_config(&config)?;
        let data_plane = runtime
            .data_plane
            .then(|| Arc::new(DataPlanePolicy::from_mp_config(&config)));
        let establishment = self.establishing.entry(peer_id).or_default().clone();
        let cancel = Arc::new(tokio::sync::Notify::new());
        let running = establishment.begin(preferred, cancel.clone());
        // Dropping the handshake releases its driver (it is shut down).
        let result = tokio::select! {
            result = session_from_datagram_paths_with_config(
                is_server,
                vec![(path.clone(), nic_scope.clone())],
                remote,
                remote_url.clone(),
                tunnel_type,
                runtime,
                self.egress_quality.clone(),
                data_plane.clone(),
            ) => Some(result),
            _ = cancel.notified() => None,
        };
        drop(running);
        let Some(established) = result else {
            // The preferred session is in the slot: this carrier joins it.
            return match Self::session_handle(&slot).await {
                Some(handle) => {
                    self.add_path_to_session(peer_id, &slot, handle, &candidate_slot, &key, path, remote, nic_scope)
                        .await
                }
                None => Err(TunnelError::InternalError(
                    "MP handshake dropped for a session that is gone".into(),
                )),
            };
        };
        // A failed or superseded handshake condemns its path only when no
        // live session holds the peer: the same carrier 4-tuple is then that
        // session's path (both ends punched it), and a Dead candidate would be
        // pruned into an abandon of the winner's path, on both ends at once.
        let (tunnel, handle) = match established {
            Ok(session) => session,
            Err(error) => {
                if Self::session_handle(&slot).await.is_none() {
                    candidate_slot.lock().await.record_validation(&key, false);
                }
                return Err(error);
            }
        };

        let mut session = slot.lock().await;
        let still_tracked = self
            .sessions
            .get(&peer_id)
            .is_some_and(|current| Arc::ptr_eq(current.value(), &slot));
        if !still_tracked {
            drop(session);
            handle.shutdown();
            candidate_slot.lock().await.record_validation(&key, false);
            return Err(TunnelError::InternalError(
                "MP peer was removed while its session was being established".into(),
            ));
        }
        if let Some(current) = session.as_ref().filter(|c| !c.handle.is_closed()) {
            if !preferred || self.direction_preferred(peer_id, current.is_server) {
                // The session in the slot stays: this carrier joins it.
                let winner = current.handle.clone();
                drop(session);
                handle.shutdown();
                return self.add_path_to_session(peer_id, &slot, winner, &candidate_slot, &key, path, remote, nic_scope)
                    .await;
            }
            // The preferred direction replaces the other one, on both ends.
            current.handle.shutdown();
            if let Some((_, old_key)) = self.primary_keys.remove(&peer_id) {
                candidate_slot.lock().await.record_validation(&old_key, false);
            }
        }
        candidate_slot.lock().await.record_validation(&key, true);
        if let Some(policy) = data_plane {
            handle.set_data_plane(policy, self.peer_dataplane_caps(peer_id).await);
        }
        self.session_fingerprints
            .insert(peer_id, mp_reconnect_fingerprint(&config));
        self.primary_keys.insert(peer_id, key);
        *session = Some(Session {
            handle,
            congestion_control: runtime.congestion_control,
            is_server,
        });
        drop(session);
        if preferred {
            establishment.cancel_non_preferred();
        }
        Ok(OfferPathResult::NewTunnel(tunnel))
    }

    /// Whether `is_server` is the direction both ends of the pair give way
    /// to: the lower peer id's outgoing session. Without a known local id
    /// (unit tests) there is no agreed direction.
    fn direction_preferred(&self, peer_id: PeerId, is_server: bool) -> bool {
        self.local_peer_id != 0 && (self.local_peer_id < peer_id) != is_server
    }

    async fn session_direction(slot: &SessionSlot) -> Option<(MpSessionHandle, bool)> {
        slot.lock()
            .await
            .as_ref()
            .map(|session| (session.handle.clone(), session.is_server))
    }

    async fn session_handle(slot: &SessionSlot) -> Option<MpSessionHandle> {
        slot.lock()
            .await
            .as_ref()
            .map(|session| session.handle.clone())
    }

    /// Port of iroh `open_path_on_conn` (`remote_state.rs:1051-1099`): a
    /// connection that has no free connection ID or path slot refuses the new
    /// path, which is no failure of the path -- it is queued and opened again
    /// every 333 ms (`retry_refused_open`), once per 4-tuple. Before, the
    /// refusal marked the candidate failed and the path was given up on both
    /// ends (MP_WORKLIST.md row 8, defects 21 and 39).
    #[allow(clippy::too_many_arguments)]
    async fn add_path_to_session(
        &self,
        peer_id: PeerId,
        slot: &SessionSlot,
        handle: MpSessionHandle,
        candidate_slot: &Arc<Mutex<MpCandidateTable>>,
        key: &PathKey,
        path: Arc<dyn crate::tunnel::mpquic::MpDatagramPath>,
        remote: std::net::SocketAddr,
        nic_scope: Option<EgressScope>,
    ) -> Result<OfferPathResult, TunnelError> {
        // Validating a new path can take seconds; runtime snapshots only
        // try_lock the slot, so holding it here would hide the live
        // session (no paths, "unknown" CC) for that whole time.
        if let Err(error) = handle.add_path(path.clone(), remote, nic_scope.clone()).await {
            if is_no_free_path_slot(&error) && !handle.is_closed() {
                if queue_refused_open(&self.pending_path_opens, (peer_id, *key)) {
                    let pending = self.pending_path_opens.clone();
                    let candidate_slot = candidate_slot.clone();
                    let key = *key;
                    tokio::spawn(retry_refused_open(
                        pending,
                        (peer_id, key),
                        OPEN_PATH_RETRY_DELAY,
                        move || {
                            let handle = handle.clone();
                            let candidate_slot = candidate_slot.clone();
                            let path = path.clone();
                            let nic_scope = nic_scope.clone();
                            async move {
                                // The candidate was given up on meanwhile
                                // (validation timeout, retired): nothing to open.
                                let wanted = candidate_slot
                                    .lock()
                                    .await
                                    .get(&key)
                                    .is_some_and(|candidate| {
                                        candidate.state == PathLifecycleState::Validating
                                    });
                                if !wanted || handle.is_closed() {
                                    return OpenAttempt::GiveUp;
                                }
                                match handle.add_path(path, remote, nic_scope).await {
                                    Ok(()) => OpenAttempt::Opened,
                                    Err(error) if is_no_free_path_slot(&error) => {
                                        OpenAttempt::NoFreeSlot
                                    }
                                    Err(error) => {
                                        tracing::debug!(?error, ?key, "queued MP path open failed");
                                        candidate_slot.lock().await.record_validation(&key, false);
                                        OpenAttempt::GiveUp
                                    }
                                }
                            }
                        },
                    ));
                }
                return Ok(OfferPathResult::PathAdded);
            }
            // The driver may have died with the peer connection. Let the
            // next punched carrier create a fresh session instead of
            // pinning this peer to a stale handle forever.
            if handle.is_closed() {
                let mut session = slot.lock().await;
                if session
                    .as_ref()
                    .is_some_and(|current| current.handle.same_session(&handle))
                {
                    *session = None;
                }
            }
            candidate_slot.lock().await.record_validation(key, false);
            return Err(error);
        }
        Ok(OfferPathResult::PathAdded)
    }

    /// Kept across `forget_peer`: an upgrade that keeps failing does not take
    /// the relayed peer away, and its record is what explains the fallback.
    pub(crate) fn record_faketcp_upgrade(&self, peer_id: PeerId, result: Result<(), String>) {
        self.faketcp_upgrades
            .entry(peer_id)
            .or_default()
            .record(result, std::time::Instant::now());
    }

    pub(crate) fn faketcp_plain_tcp_fallback(&self, peer_id: PeerId) -> bool {
        self.faketcp_upgrades
            .get(&peer_id)
            .is_some_and(|record| record.plain_tcp_fallback(std::time::Instant::now()))
    }

    /// EasyTier's peer map is the authority for connection liveness.  When it
    /// removes a peer (for example after ping/pong failure), discard every MP
    /// object for that peer and ask the driver to stop.  A later punch must
    /// consequently create a fresh TQUIC tunnel and pass through
    /// `PeerManager::add_*_tunnel` again; it cannot return `PathAdded` against
    /// a session that EasyTier has already declared dead.
    pub(crate) async fn forget_peer(&self, peer_id: PeerId) -> bool {
        let session_slot = self.sessions.remove(&peer_id).map(|(_, slot)| slot);
        self.session_fingerprints.remove(&peer_id);
        self.empty_since.remove(&peer_id);
        if let Some(session_slot) = session_slot.as_ref() {
            let session = session_slot.lock().await;
            if let Some(session) = session.as_ref() {
                session.handle.shutdown();
            }
        }

        self.pending_path_opens.retain(|(id, _), _| *id != peer_id);
        let had_state = session_slot.is_some()
            | self.candidates.remove(&peer_id).is_some()
            | self.optimization_snapshots.remove(&peer_id).is_some();
        self.manual_paths
            .retain(|_, tracked| tracked.peer_id != peer_id);

        if had_state {
            tracing::info!(
                peer_id,
                "EasyTier removed peer; discarded its MP session and candidate state"
            );
        }
        had_state
    }

    /// A lagged lifecycle subscriber cannot identify which `PeerRemoved`
    /// event was lost.  Keep EasyTier authoritative by discarding every MP
    /// session in that exceptional case; normal punch/reconnect logic will
    /// recreate only the still-live peers.
    pub(crate) async fn forget_all_peers(&self) -> usize {
        let mut peer_ids = HashSet::new();
        peer_ids.extend(self.sessions.iter().map(|entry| *entry.key()));
        peer_ids.extend(self.candidates.iter().map(|entry| *entry.key()));
        peer_ids.extend(self.optimization_snapshots.iter().map(|entry| *entry.key()));
        peer_ids.extend(self.manual_paths.iter().map(|entry| entry.value().peer_id));

        let mut forgotten = 0;
        for peer_id in peer_ids {
            forgotten += usize::from(self.forget_peer(peer_id).await);
        }
        forgotten
    }

    /// Peers with a live session, each with whether this end is its server.
    pub(crate) async fn active_sessions(&self) -> Vec<(PeerId, bool)> {
        let slots = self
            .sessions
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect::<Vec<_>>();
        let mut peers = Vec::with_capacity(slots.len());
        for (peer_id, slot) in slots {
            let session = slot.lock().await;
            if let Some(session) = session
                .as_ref()
                .filter(|session| !session.handle.is_closed())
            {
                peers.push((peer_id, session.is_server));
            }
        }
        peers.sort_unstable();
        peers
    }

    /// Retires the path `local`-`remote` of the session with `peer_id`, asking
    /// the session whether it may go; the candidate table is only updated
    /// along, it does not decide. `Ok(false)`: the session refused because it
    /// is the last open path, so it and its carrier stay (see
    /// [`Self::retire_path`]). `Ok(true)`: gone, or there is no session.
    pub(crate) async fn retire_path_by_addresses(
        &self,
        peer_id: PeerId,
        local_addr: std::net::SocketAddr,
        remote_addr: std::net::SocketAddr,
    ) -> Result<bool, TunnelError> {
        let slot = self.candidates.get(&peer_id).map(|entry| entry.clone());
        let keys = match slot {
            Some(slot) => slot
                .lock()
                .await
                .iter()
                .filter_map(|(key, _)| {
                    ((key.local_addr, key.remote_addr) == (local_addr, remote_addr))
                        .then_some(*key)
                })
                .collect::<Vec<_>>(),
            None => Vec::new(),
        };
        if keys.is_empty() {
            // The candidate may long be gone (validation timed out, say) while
            // the session still carries the path: the driver is asked anyway.
            let key = PathKey {
                carrier_id: crate::tunnel::mpquic::CarrierId(0),
                local_addr,
                remote_addr,
            };
            return match self.remove_path_from_session(peer_id, &key).await {
                Ok(()) => Ok(true),
                Err(error) if is_last_open_path(&error) => Ok(false),
                Err(error) => Err(error),
            };
        }
        let mut retired = true;
        for key in keys {
            retired &= self.retire_path_unless_last(peer_id, &key).await?;
        }
        Ok(retired)
    }

    /// A session whose driver refuses every `remove_path` as the last open path.
    #[cfg(test)]
    pub(crate) fn insert_refusing_session_for_test(&self, peer_id: PeerId) {
        self.sessions.insert(
            peer_id,
            Arc::new(Mutex::new(Some(Session {
                handle: MpSessionHandle::refusing_remove_path_for_test(),
                congestion_control: CongestionControlProfile::EngineDefault,
                is_server: false,
            }))),
        );
    }

    pub(crate) async fn retire_paths_for_egress_change(
        &self,
        egress: &crate::common::egress_inventory::EgressStableId,
        current_generation: Option<u64>,
    ) -> Result<usize, TunnelError> {
        let slots = self
            .candidates
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect::<Vec<_>>();
        let mut retired = 0;
        for (peer_id, slot) in slots {
            let keys = slot
                .lock()
                .await
                .iter()
                .filter_map(|(key, candidate)| {
                    let binding = candidate.spec.egress_binding.as_ref()?;
                    (candidate.state != PathLifecycleState::Dead
                        && &binding.egress == egress
                        && current_generation
                            .is_none_or(|generation| binding.generation != generation))
                    .then_some(*key)
                })
                .collect::<Vec<_>>();
            for key in keys {
                retired += usize::from(self.retire_path_unless_last(peer_id, &key).await?);
            }
        }
        Ok(retired)
    }

    /// MP_SQM_PLAN.md S2.14 dedupe: two punched paths of one kind whose peer
    /// reports the same public IP for us, towards the same remote IP, went out
    /// through the same WAN. Keep an unpaused one with the lowest sRTT, retire
    /// the rest.
    ///
    /// Only the lower peer id of the pair decides (the same end whose session
    /// direction wins, see `SessionSlot`): each end measures sRTT itself, so
    /// deciding on both ends can retire a different one of the pair on each
    /// and leave the session without a path both ends still use. The other end
    /// sees the retired path go silent and drops it (`black_hole_paths`).
    pub(crate) async fn retire_duplicate_wan_paths(
        &self,
        path_policies: &[MpPathPolicy],
    ) -> Result<usize, TunnelError> {
        let slots = self
            .candidates
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .filter(|(peer_id, _)| self.local_peer_id == 0 || self.local_peer_id < *peer_id)
            .collect::<Vec<_>>();
        let mut retired = 0;
        for (peer_id, slot) in slots {
            let keys = duplicate_wan_paths(&*slot.lock().await, path_policies);
            for key in keys {
                tracing::info!(peer_id, ?key, "retiring punched path duplicating a WAN");
                retired += usize::from(self.retire_path_unless_last(peer_id, &key).await?);
            }
        }
        Ok(retired)
    }

    /// The NIC-level egress scope of an MP path: both the scope its carrier
    /// is governed by (handed to the driver with the path) and the one its
    /// egress sampling publishes to, so the two can never diverge. SQM state
    /// belongs only to an explicitly identified physical egress device, never
    /// to an address-fallback, remote, or user-defined resource group.
    fn path_nic_scope(
        spec: &MpPathSpec,
        resolved_routes: &HashMap<String, (crate::common::egress_inventory::EgressStableId, u64)>,
    ) -> Option<EgressScope> {
        let resource = spec.egress_resource.as_ref()?;
        if resource.kind() != super::mp_path::ResourceGroupKind::EgressDevice {
            return None;
        }
        // A real `EgressSocketBinding` is only built by tests since
        // MP_SQM_PLAN.md S2.14. The ordinary case resolved a device name via
        // plain interface auto-detection, so fall back to the
        // `resolved_egress_routes` index (MP_SQM_PLAN.md S2.2 follow-up)
        // rather than silently leaving it unscoped.
        if let Some(binding) = &spec.egress_binding {
            return Some(EgressScope::from_binding(binding, EgressDirection::Egress));
        }
        let (stable_id, generation) = resolved_routes
            .get(resource.egress_device_name().unwrap_or_default())
            .cloned()?;
        Some(EgressScope::from_resolved_route(
            stable_id,
            generation,
            EgressDirection::Egress,
        ))
    }

    pub(crate) async fn reconcile_egress_bindings(
        &self,
        snapshot: &crate::common::egress_inventory::EgressInventorySnapshot,
    ) -> Result<usize, TunnelError> {
        // MP_SQM_PLAN.md S2.2 follow-up: refresh the plain-device-name index
        // `refresh_all_egress_capacities` uses for candidates that resolved
        // an `egress_resource` but never got a real `EgressSocketBinding`
        // (see `resolved_egress_routes`'s own doc). A platform can rename an
        // interface without changing its stable identity, so every alias is
        // indexed too, same as `EgressInventorySnapshot::eligible_stable_ids`
        // already treats `platform_name`/`aliases` as equally authoritative
        // names for the same interface.
        *self.reflector_interfaces.lock().unwrap() = snapshot
            .interfaces
            .iter()
            .filter_map(|(stable_id, interface)| {
                let v4 = interface.addresses.iter().filter_map(|a| match a.ip {
                    std::net::IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() => Some(ip),
                    _ => None,
                });
                // A link-local address is only the fallback: it has no route
                // to the public reflectors.
                let addr = v4
                    .clone()
                    .find(|ip| !ip.is_link_local())
                    .or_else(|| v4.clone().next())?;
                Some((stable_id.clone(), (addr, interface.platform_name.clone())))
            })
            .collect();
        let vanished_devices = {
            let mut routes = self.resolved_egress_routes.lock().await;
            let previous = std::mem::take(&mut *routes);
            for (stable_id, interface) in &snapshot.interfaces {
                for name in std::iter::once(&interface.platform_name).chain(&interface.aliases) {
                    routes
                        .entry(name.clone())
                        .or_insert_with(|| (stable_id.clone(), interface.generation));
                }
            }
            previous
                .into_keys()
                .filter(|name| !routes.contains_key(name))
                .collect::<HashSet<_>>()
        };
        let bindings = self
            .candidates
            .iter()
            .map(|entry| entry.value().clone())
            .collect::<Vec<_>>();
        let mut observed = HashSet::new();
        for slot in bindings {
            let candidates = slot.lock().await;
            observed.extend(candidates.iter().filter_map(|(_, candidate)| {
                (candidate.state != PathLifecycleState::Dead)
                    .then(|| candidate.spec.egress_binding.as_ref())
                    .flatten()
                    .map(|binding| (binding.egress.clone(), binding.generation))
            }));
        }

        let mut retired = 0;
        for (egress, generation) in observed {
            let current_generation = snapshot
                .interfaces
                .get(&egress)
                .map(|interface| interface.generation);
            if current_generation != Some(generation) {
                retired += self
                    .retire_paths_for_egress_change(&egress, current_generation)
                    .await?;
            }
        }
        if !vanished_devices.is_empty() {
            retired += self.retire_paths_on_vanished_devices(&vanished_devices).await?;
        }
        Ok(retired)
    }

    /// Paths known only by their NIC's name (no socket binding: auto-detected
    /// UDP paths, relay paths via their first hop's NIC) whose NIC left the
    /// inventory: their packets have nowhere to go. Without this, a session
    /// on them keeps carrying traffic into a dead NIC until EasyTier's ping
    /// timeout closes it, instead of failing over at once.
    async fn retire_paths_on_vanished_devices(
        &self,
        vanished: &HashSet<String>,
    ) -> Result<usize, TunnelError> {
        let slots = self
            .candidates
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect::<Vec<_>>();
        let mut retired = 0;
        for (peer_id, slot) in slots {
            let keys = slot
                .lock()
                .await
                .iter()
                .filter_map(|(key, candidate)| {
                    (candidate.state != PathLifecycleState::Dead
                        && candidate.spec.egress_binding.is_none()
                        && vanished.contains(candidate.spec.egress_device_name()))
                    .then_some(*key)
                })
                .collect::<Vec<_>>();
            // Only a peer that just lost paths to the vanished NIC is
            // considered below; any other peer's session is not this NIC's
            // business.
            if keys.is_empty() {
                continue;
            }
            let mut kept = Vec::new();
            for key in keys {
                tracing::info!(
                    peer_id,
                    ?key,
                    "retiring MP path whose egress NIC disappeared"
                );
                if self.retire_path_unless_last(peer_id, &key).await? {
                    retired += 1;
                } else {
                    kept.push(key);
                }
            }
            // The driver keeps a connection's last path, so a session whose
            // paths all left with the NIC would linger: close it, and
            // EasyTier fails over to its other connections right away. Unlike
            // a first hop that reconnects, nothing brings this NIC back.
            let any_live = slot.lock().await.iter().any(|(key, candidate)| {
                candidate.state != PathLifecycleState::Dead && !kept.contains(key)
            });
            if !any_live && self.sessions.contains_key(&peer_id) {
                tracing::info!(peer_id, "closing MP session: every path left with its NIC");
                self.forget_peer(peer_id).await;
            }
        }
        Ok(retired)
    }

    /// `peer_id`'s established session: its handle, and whether its CC is
    /// rate-driven.
    async fn ready_session(&self, peer_id: PeerId) -> Result<(MpSessionHandle, bool), TunnelError> {
        let session_slot = self
            .sessions
            .get(&peer_id)
            .map(|entry| entry.clone())
            .ok_or_else(|| TunnelError::InternalError("mpquic session not found".into()))?;
        let session = session_slot.lock().await;
        let ready = session.as_ref().map(|session| {
            (
                session.handle.clone(),
                session.congestion_control.is_rate_driven(),
            )
        });
        ready.ok_or_else(|| TunnelError::InternalError("mpquic session is not ready".into()))
    }

    pub(crate) async fn refresh_path_telemetry(
        &self,
        peer_id: PeerId,
    ) -> Result<Vec<MpPathTelemetry>, TunnelError> {
        let (handle, _) = self.ready_session(peer_id).await?;
        let path_events = handle.take_path_events().await?;
        self.apply_path_events(peer_id, path_events).await;
        let telemetry = handle.path_telemetry().await?;
        let candidate_slot = self
            .candidates
            .get(&peer_id)
            .map(|entry| entry.clone())
            .ok_or_else(|| TunnelError::InternalError("mpquic candidates not found".into()))?;
        let mut candidates = candidate_slot.lock().await;

        for path in &telemetry {
            let Some(key) = candidates
                .key_for_addresses(path.local_addr, path.remote_addr)
                .or_else(|| candidates.resolve_wildcard_remote(path.local_addr, path.remote_addr))
            else {
                continue;
            };
            let carrier_kind = candidates
                .get(&key)
                .map(|c| c.spec.carrier_kind)
                .unwrap_or(CarrierKind::Manual);
            match path_validation_decision(path.validation_state, carrier_kind) {
                Some(true) => {
                    if matches!(
                        candidates.get(&key).map(|candidate| candidate.state),
                        Some(PathLifecycleState::Validating)
                    ) {
                        candidates.record_validation(&key, true);
                    }
                }
                Some(false) => {
                    candidates.record_validation(&key, false);
                    continue;
                }
                None => continue,
            }

            candidates.observe_measurements(&key, path_measurements_from_telemetry(path));
            candidates.record_traffic(&key, path.sent_bytes, path.lost_bytes);
            candidates.record_received(&key, path.recv_bytes);
            candidates.record_acks(
                &key,
                path.sent_bytes,
                path.acked_bytes,
                path.srtt_micros,
                Instant::now(),
            );
            if candidates
                .get(&key)
                .is_some_and(|candidate| candidate.heard_since_validated())
            {
                // The peer answers over this kind of punched path: the
                // consecutive-drop count starts over.
                self.punch_drops.remove(&(peer_id, carrier_kind));
            }
        }

        Ok(telemetry)
    }

    /// Refresh every live MP session and aggregate its path counters by actual
    /// egress device. This is intentionally a node-wide snapshot: sampling one
    /// peer at a time would double-count or miss competition between different
    /// peers sharing the same WAN device.
    pub(crate) async fn refresh_all_egress_capacities(
        &self,
        rtt_max_age_micros: u64,
    ) -> Result<Vec<ResourceCapacity>, TunnelError> {
        let session_slots = self
            .sessions
            .iter()
            .map(|session| (*session.key(), session.value().clone()))
            .collect::<Vec<_>>();
        // The user's declared Brutal rate is a capacity statement for every
        // egress a Brutal session sends on (see `raise_autorate_start`).
        let (declared_brutal_bps, reflector_list) = {
            let config = self.config.read().await;
            (configured_brutal_tx_bps(&config), reflector_addresses(&config))
        };
        let reflector_mark = *self.reflector_socket_mark.lock().unwrap();
        let mut samples = Vec::new();
        for (peer_id, slot) in session_slots {
            let rate_driven = match slot.try_lock() {
                Ok(session) if session.is_some() => session
                    .as_ref()
                    .is_some_and(|session| session.congestion_control.is_rate_driven()),
                Ok(_) => {
                    tracing::debug!(
                        peer_id,
                        "skipping egress SQM sampling while an MP session is still establishing"
                    );
                    continue;
                }
                Err(error) => {
                    tracing::debug!(
                        peer_id,
                        ?error,
                        "skipping egress SQM sampling while an MP session slot is busy"
                    );
                    continue;
                }
            };
            let telemetry = match self
                .refresh_path_telemetry(peer_id)
                .await
            {
                Ok(telemetry) => telemetry,
                Err(error) => {
                    tracing::debug!(
                        peer_id,
                        ?error,
                        "skipping egress SQM sampling for an unavailable MP session"
                    );
                    continue;
                }
            };
            let Some(candidate_slot) = self.candidates.get(&peer_id).map(|entry| entry.clone())
            else {
                continue;
            };
            let candidates = candidate_slot.lock().await;
            let resolved_routes = self.resolved_egress_routes.lock().await;
            for path in telemetry {
                let Some(key) = candidates.key_for_addresses(path.local_addr, path.remote_addr)
                else {
                    continue;
                };
                let Some(candidate) = candidates.get(&key) else {
                    continue;
                };
                // SQM state belongs only to an explicitly identified physical
                // egress device, never to an address-fallback, remote, or
                // user-defined resource group.
                let Some(scope) = Self::path_nic_scope(&candidate.spec, &resolved_routes) else {
                    continue;
                };
                let Some(resource) = candidate.spec.egress_resource.clone() else {
                    continue;
                };
                let device = resource.egress_device_name().unwrap_or_default().to_string();
                // Every path is sampled at its NIC, the scope of the one CAKE
                // queue its packets leave through -- direct and relay paths
                // alike, whatever public address the peer sees.
                samples.push((
                    resource,
                    device,
                    scope,
                    key,
                    path.sent_bytes,
                    PathRtt {
                        state: candidate.state,
                        sample_age_micros: path.sample_age_micros,
                        srtt_micros: path.srtt_micros,
                        min_rtt_micros: path.min_rtt_micros,
                    },
                    rate_driven,
                ));
            }
            drop(resolved_routes);
        }

        // Group by the physical-egress `EgressScope`, not `ResourceGroupId`:
        // MP_SQM_PLAN.md §4.3's "复用与红线" is explicit that the two keys
        // are not necessarily 1:1 (a resource group may express a bond/LAG or
        // a logical grouping). A single scope's aggregate sample still
        // carries every `ResourceGroupId` observed for it so the optimizer
        // feed below stays correct even when they diverge.
        let now = Instant::now();
        #[allow(clippy::type_complexity)]
        let mut by_scope: HashMap<
            EgressScope,
            (
                Vec<ResourceGroupId>,
                String,
                Vec<(PathKey, u64, PathRtt)>,
                bool,
            ),
        > = HashMap::new();
        for (resource, device, scope, key, sent_bytes, rtt, rate_driven) in samples {
            let entry = by_scope.entry(scope).or_default();
            if !entry.0.contains(&resource) {
                entry.0.push(resource);
            }
            entry.1 = device;
            entry.2.push((key, sent_bytes, rtt));
            entry.3 |= rate_driven;
        }

        let mut sample_state = self.egress_sample_state.lock().await;
        let live_scopes = by_scope.keys().cloned().collect::<HashSet<_>>();
        sample_state.retain(|scope, _| live_scopes.contains(scope));

        let mut estimates = Vec::new();
        for (scope, (resources, device, paths, carries_rate_driven)) in by_scope {
            let state = sample_state.entry(scope.clone()).or_insert_with(|| {
                EgressSampleState {
                    last_update: now,
                    last_bytes: HashMap::new(),
                    last_nic_tx: None,
                    reflectors: None,
                }
            });
            let dt_micros = now
                .saturating_duration_since(state.last_update)
                .as_micros() as u64;
            let previous_tick = state.last_update;
            state.last_update = now;

            let live_paths = paths.iter().map(|(key, ..)| *key).collect::<HashSet<_>>();
            state.last_bytes.retain(|key, _| live_paths.contains(key));
            let mut sent_delta = 0u64;
            let path_count = paths.len();
            let mut rtts = Vec::with_capacity(path_count);
            for (key, sent_bytes, rtt) in paths {
                if let Some(previous) = state.last_bytes.insert(key, sent_bytes) {
                    sent_delta = sent_delta.saturating_add(sent_bytes.saturating_sub(previous));
                }
                rtts.push(rtt);
            }
            // Sent bytes count every path; the round-trip fallback delay only
            // the active paths with a fresh sample (OWD_AUTORATE_PLAN.md 1.3).
            let rtt_delay_micros = egress_rtt_delay_us(&rtts, rtt_max_age_micros);
            // S-I10: the load is what the interface itself sent, as
            // cake-autorate reads `tx_bytes`; other programs' traffic on the
            // NIC counts toward the estimator's high-load test too.
            let nic_tx = crate::common::ifcfg::interface_counters(&scope.stable_id)
                .map(|counters| counters.tx_bytes);
            let (sent_delta, achieved_source) =
                egress_sent_delta(&mut state.last_nic_tx, nic_tx, sent_delta);
            let achieved_bps = WireBitrate::from_byte_delta_over_micros(sent_delta, dt_micros).0;

            let handle = self.egress_quality.handle_for(scope.clone());
            if carries_rate_driven && let Some(declared) = declared_brutal_bps {
                let _ = handle.raise_autorate_start(WireBitrate(declared));
            }
            // The card's own queue is measured against public reflectors, not
            // only this instance's MP peers (one far end is no basis for
            // "the card's queue": incident 2026-10-26 08:25).
            let reflector_key = reflector_list.as_ref().and_then(|reflectors| {
                let (local, device) = self
                    .reflector_interfaces
                    .lock()
                    .unwrap()
                    .get(&scope.stable_id)
                    .cloned()?;
                Some(crate::common::egress_quality::reflectors::ProberKey {
                    egress: scope.stable_id.clone(),
                    local,
                    device,
                    socket_mark: reflector_mark,
                    reflectors: reflectors.clone(),
                })
            });
            if state.reflectors.as_ref().map(|(key, _)| key) != reflector_key.as_ref() {
                state.reflectors = reflector_key.and_then(|key| {
                    crate::common::egress_quality::reflectors::prober_for(&key)
                        .map(|prober| (key, prober))
                });
            }
            if let Some((_, prober)) = &state.reflectors {
                prober.note_load(
                    achieved_bps,
                    handle.shaping_rate().0,
                    self.egress_quality.active_thr_bps(),
                );
                handle.record_reflector_deltas(prober.tick_deltas(previous_tick, now));
            }
            // The delay is the one-way delay of the data direction when the
            // peer sends it (`tunnel::mpquic::owd`); else the round trip,
            // which is already baseline-normalized per path via
            // SRTT-min_rtt, so a small constant is enough to keep the
            // estimator's internal baseline well-defined (matches the prior
            // `mp_egress_sqm.rs` behavior); else nothing, and the estimate
            // stays (OWD_AUTORATE_PLAN.md 1.2).
            let Ok(published) = handle.publish(
                achieved_bps,
                rtt_delay_micros.map(|delay| delay.saturating_add(1)),
            ) else {
                // A retired-generation handle (NIC removed/re-added mid-tick)
                // just skips this scope for this tick; it is not fatal to the
                // rest of the refresh.
                continue;
            };
            let estimate = published.estimate;
            let queue_delay_micros = published.queue_delay_us;

            // MP_SQM_PLAN.md S2.1 GUI fields: computed once per scope, not
            // once per resource below (every resource in `resources` shares
            // the same physical scope, hence the same ceiling/telemetry).
            let ceiling = self.egress_quality.ceiling_info_for(&scope.stable_id);
            let cake = crate::tunnel::mpquic::cake_status(&handle);
            let fallback_scope = matches!(
                &scope.stable_id,
                crate::common::egress_inventory::EgressStableId::Fallback { .. }
            );
            // MP_SQM_PLAN.md S2.5: `autorate_estimate()` is the estimator's
            // last recorded value (populated by the `publish_sample` call
            // above). What holds the scope is its governor's ceiling: the
            // estimate within the bounds, under the static policy; reported
            // as Autorate's whenever the estimate is the lower of the two.
            // A tick with no delay sample leaves the estimator alone (held);
            // before its first update the estimate reported is its start value.
            let autorate_estimate_bps = handle
                .autorate_estimate()
                .map(|bps| bps.0)
                .or(Some(estimate.est_bw_bps));
            let (ceiling_bps, ceiling_source) = match handle.ceiling() {
                Some(rate) if ceiling.ceiling_bps.is_none_or(|policy| rate < policy) => {
                    (Some(rate), crate::common::egress_quality::CeilingSource::Autorate)
                }
                _ => (ceiling.ceiling_bps, ceiling.source),
            };
            // The allocator's view of this egress (MP_SQM_PLAN.md §3: "path
            // 速率分配 ... Brutal 目标速率走这里"): the estimate within the
            // user's autorate bounds and static ceiling.
            let capacity_bps = handle.budget_for_estimate(WireBitrate(estimate.est_bw_bps)).0;

            for resource in resources {
                estimates.push(EgressResourceEstimate {
                    egress_device: device.clone(),
                    ceiling_bps,
                    ceiling_source,
                    autorate_estimate_bps,
                    autorate_measured: handle.autorate_measured(),
                    cake: cake.clone(),
                    fallback_scope,
                    resource,
                    capacity_bps,
                    achieved_bps,
                    achieved_source,
                    queue_delay_micros,
                    queue_delay_source: published.source,
                    reflector_count: published.reflector_count,
                    path_count,
                });
            }
        }

        self.egress_snapshots.clear();
        for estimate in &estimates {
            self.egress_snapshots
                .insert(estimate.resource.clone(), estimate.clone());
        }
        Ok(estimates
            .into_iter()
            .map(|estimate| ResourceCapacity {
                resource: estimate.resource,
                capacity_bps: estimate.capacity_bps,
            })
            .collect())
    }

    pub(crate) fn egress_resource_snapshots(&self) -> Vec<EgressResourceEstimate> {
        self.egress_snapshots
            .iter()
            .map(|estimate| estimate.clone())
            .collect()
    }

    pub(crate) async fn reap_closed_sessions(&self) -> usize {
        let sessions = self
            .sessions
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect::<Vec<_>>();
        let mut closed_peers = Vec::new();
        let now = Instant::now();
        for (peer_id, slot) in sessions {
            let session = slot.lock().await;
            match session.as_ref() {
                Some(session) if session.handle.is_closed() => closed_peers.push(peer_id),
                Some(_) => {
                    self.empty_since.remove(&peer_id);
                }
                // An empty slot whose handshake failed (or whose driver died
                // while a path was added) would otherwise stay forever: a peer
                // listed with no paths, its candidates and optimizer kept.
                None => {
                    let establishing = self
                        .establishing
                        .get(&peer_id)
                        .is_some_and(|e| e.in_progress());
                    if establishing {
                        self.empty_since.remove(&peer_id);
                        continue;
                    }
                    let since = *self.empty_since.entry(peer_id).or_insert(now);
                    if now.saturating_duration_since(since) >= EMPTY_SESSION_GRACE {
                        closed_peers.push(peer_id);
                    }
                }
            }
        }

        for peer_id in &closed_peers {
            self.empty_since.remove(peer_id);
            self.sessions.remove(peer_id);
            self.candidates.remove(peer_id);
            self.optimization_snapshots.remove(peer_id);
            self.manual_paths
                .retain(|_, tracked| tracked.peer_id != *peer_id);
            tracing::info!(
                peer_id = *peer_id,
                "reaped closed MP session and removed its candidate table"
            );
        }
        // MP_SQM_PLAN.md S1.4: standalone sessions are never touched by
        // `clear_disabled_runtime_state`, so a closed one is only ever
        // reclaimed here, on the same reap cadence as managed sessions.
        self.standalone_sessions
            .retain(|_, (handle, _congestion_control)| !handle.is_closed());
        closed_peers.len()
    }

    async fn prune_failed_and_stale_candidates(&self) -> usize {
        let slots = self
            .candidates
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect::<Vec<_>>();
        let now = Instant::now();
        let mut removed_count = 0;

        for (peer_id, candidate_slot) in slots {
            let removed = candidate_slot
                .lock()
                .await
                .prune_failed_and_stale_validations(now, PATH_VALIDATION_TIMEOUT);
            if removed.is_empty() {
                continue;
            }
            removed_count += removed.len();

            let handle = if let Some(session_slot) =
                self.sessions.get(&peer_id).map(|entry| entry.clone())
            {
                let session = session_slot.lock().await;
                session.as_ref().map(|session| session.handle.clone())
            } else {
                None
            };
            let Some(handle) = handle else {
                continue;
            };

            for key in removed {
                match tokio::time::timeout(
                    PATH_RETIRE_DEADLINE,
                    handle.remove_path(key.local_addr, key.remote_addr),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) if handle.is_closed() => {
                        tracing::debug!(
                            ?peer_id,
                            ?key,
                            ?error,
                            "MP path already closed while pruning"
                        )
                    }
                    Ok(Err(error)) => tracing::debug!(
                        ?peer_id,
                        ?key,
                        ?error,
                        "failed to remove pruned MP path from driver"
                    ),
                    Err(_) => tracing::debug!(
                        ?peer_id,
                        ?key,
                        "timed out removing pruned MP path from driver"
                    ),
                }
            }
        }

        removed_count
    }

    pub(crate) async fn runtime_snapshots(
        &self,
    ) -> Result<Vec<MpPeerRuntimeSnapshot>, TunnelError> {
        let config = self.config.read().await.clone();
        let configured_congestion_control =
            CongestionControlProfile::parse(&config.congestion_control)
                .map(|profile| profile.as_str().to_string())
                .unwrap_or_else(|_| config.congestion_control.clone());
        let path_policies = &config.path_policies;
        let configured_fingerprint = mp_reconnect_fingerprint(&config);
        // MP_SQM_PLAN.md S2.4: `MpPeerStatus.brutal_tx_bps`/
        // `peer_advertised_rx_bps`. `brutal_tx_bps` is session-wide (the same
        // `up_mbps` config applies to every peer), so resolve it once here
        // rather than per peer_id below.
        let brutal_tx_bps = configured_brutal_tx_bps(&config);
        let remote_rx_bps_lookup = self.remote_rx_bps_lookup.read().await.clone();
        let peer_advertised_rx_bps = |peer_id: PeerId| -> Option<u64> {
            remote_rx_bps_lookup
                .as_ref()
                .and_then(|lookup| lookup(peer_id))
        };
        let mut peer_ids = self
            .candidates
            .iter()
            .map(|entry| *entry.key())
            .collect::<HashSet<_>>();
        peer_ids.extend(self.sessions.iter().map(|entry| *entry.key()));
        peer_ids.extend(self.optimization_snapshots.iter().map(|entry| *entry.key()));
        peer_ids.extend(self.faketcp_upgrades.iter().map(|entry| *entry.key()));

        let mut peer_ids = peer_ids.into_iter().collect::<Vec<_>>();
        peer_ids.sort_unstable();

        let mut snapshots = Vec::with_capacity(peer_ids.len());
        for peer_id in peer_ids {
            // MP_SQM_PLAN.md S2.6: `has_live_session` distinguishes "no
            // session yet, nothing to reconnect" from "a live session whose
            // captured CC has drifted from `configured_congestion_control`"
            // -- both cases can otherwise report the same
            // `effective_congestion_control` string, but only the latter
            // should ever set `reconnect_required`.
            let (handle, effective_congestion_control, has_live_session) =
                if let Some(slot) = self.sessions.get(&peer_id).map(|entry| entry.clone()) {
                    match slot.try_lock() {
                        Ok(session) => session
                            .as_ref()
                            .map(|session| {
                                (
                                    Some(session.handle.clone()),
                                    session.congestion_control.as_str().to_string(),
                                    true,
                                )
                            })
                            .unwrap_or_else(|| (None, configured_congestion_control.clone(), false)),
                        Err(error) => {
                            tracing::debug!(
                                ?peer_id,
                                ?error,
                                "MP session is busy; emitting a non-blocking runtime snapshot"
                            );
                            (None, "unknown".to_string(), false)
                        }
                    }
                } else {
                    (None, configured_congestion_control.clone(), false)
                };
            // A session a test built by hand has no fingerprint; the CC
            // comparison still covers it.
            let reconnect_required = has_live_session
                && (effective_congestion_control != configured_congestion_control
                    || self
                        .session_fingerprints
                        .get(&peer_id)
                        .is_some_and(|built| *built != configured_fingerprint));
            let data_plane = match &handle {
                Some(handle) => tokio::time::timeout(
                    RUNTIME_SNAPSHOT_TELEMETRY_DEADLINE,
                    handle.data_plane_status(),
                )
                .await
                .ok()
                .and_then(Result::ok)
                .map(|mut status| {
                    status.oversize_ptb = self.ptb_sent.get(&peer_id).map(|n| *n).unwrap_or(0);
                    status
                }),
                None => None,
            };
            let telemetry = if let Some(handle) = handle {
                match path_telemetry_with_deadline(
                    handle.path_telemetry(),
                    RUNTIME_SNAPSHOT_TELEMETRY_DEADLINE,
                )
                .await
                {
                    Ok(telemetry) => telemetry,
                    Err(error) => {
                        tracing::debug!(
                            ?peer_id,
                            ?error,
                            "failed to sample MP session while building runtime snapshot"
                        );
                        Vec::new()
                    }
                }
            } else {
                Vec::new()
            };
            let telemetry = telemetry
                .into_iter()
                .map(|path| ((path.local_addr, path.remote_addr), path))
                .collect::<std::collections::HashMap<_, _>>();
            let optimization = self
                .optimization_snapshots
                .get(&peer_id)
                .map(|entry| entry.clone());

            let first_hop_loss = self.first_hop_loss_snapshot();
            let mut paths =
                if let Some(slot) = self.candidates.get(&peer_id).map(|entry| entry.clone()) {
                    match slot.try_lock() {
                        Ok(candidates) => {
                            let selection =
                                selection_input(&candidates, path_policies, &first_hop_loss);
                            candidates
                            .iter()
                            .map(|(key, candidate)| {
                                let path_telemetry =
                                    telemetry.get(&(key.local_addr, key.remote_addr)).cloned();
                                let target_rate_bps = optimization
                                    .as_ref()
                                    .and_then(|snapshot| {
                                        snapshot
                                            .targets
                                            .iter()
                                            .find(|target| {
                                                target.local_addr == key.local_addr
                                                    && target.remote_addr == key.remote_addr
                                            })
                                            .and_then(|target| target.rate)
                                    })
                                    .or_else(|| {
                                        path_telemetry
                                            .as_ref()
                                            .and_then(|path| path.scheduler_target_rate_bps)
                                    });
                                let egress_device =
                                    candidate.spec.egress_device_name().to_string();
                                let user_policy = resolve_candidate_path_policy(
                                    &candidate.spec,
                                    key.remote_addr,
                                    path_policies,
                                )
                                .map(|policy| policy.action.clone())
                                .unwrap_or_default();
                                MpPathRuntimeSnapshot {
                                    key: *key,
                                    carrier_kind: candidate.spec.carrier_kind,
                                    relay_metadata: candidate.spec.relay_metadata,
                                    local_resource: candidate.spec.local_resource.clone(),
                                    remote_resource: candidate.spec.remote_resource.clone(),
                                    state: candidate.state,
                                    measurements: candidate.measurements.clone(),
                                    telemetry: path_telemetry,
                                    target_rate_bps,
                                    egress_device,
                                    user_policy,
                                    selection: PathSelectionDiagnostics {
                                        recent_loss: candidate.recent_loss,
                                        first_hop_loss: candidate.spec.relay_metadata.and_then(
                                            |metadata| {
                                                first_hop_loss
                                                    .get(&metadata.egress_first_hop_peer_id)
                                                    .copied()
                                            },
                                        ),
                                        not_selected_reason: if !candidate.state.is_established() {
                                            "not-established"
                                        } else {
                                            selection.left_out.get(key).copied().unwrap_or_default()
                                        }
                                        .to_string(),
                                    },
                                }
                            })
                            .collect::<Vec<_>>()
                        }
                        Err(error) => {
                            tracing::debug!(
                                ?peer_id,
                                ?error,
                                "MP candidate table is busy; omitting paths from runtime snapshot"
                            );
                            Vec::new()
                        }
                    }
                } else {
                    Vec::new()
                };
            paths.sort_by_key(|path| {
                (
                    path.key.local_addr,
                    path.key.remote_addr,
                    path.key.carrier_id.0,
                )
            });
            snapshots.push(MpPeerRuntimeSnapshot {
                peer_id,
                paths,
                optimization,
                effective_congestion_control,
                desired_congestion_control: configured_congestion_control.clone(),
                reconnect_required,
                standalone: false,
                brutal_tx_bps,
                peer_advertised_rx_bps: peer_advertised_rx_bps(peer_id),
                data_plane,
                faketcp_upgrade: self
                    .faketcp_upgrades
                    .get(&peer_id)
                    .map(|record| record.clone()),
            });
        }

        // MP_SQM_PLAN.md S1.4: standalone sessions have no candidate table,
        // optimizer, or desired congestion-control config -- they were never
        // subject to any of that machinery -- so they are reported directly
        // from their own handle's telemetry rather than folded into the loop
        // above. `peer_ids` already only contains managed peers (candidates/
        // sessions/optimization_snapshots), so no dedup is needed here: a
        // peer_id can only be in `standalone_sessions` OR in one of those
        // three maps, never both.
        // Collected into a plain `Vec` before any `.await` below, same as
        // `sessions`/`candidates` above: a `DashMap` iterator holds a shard
        // guard per entry, and `register_standalone_session`'s `.insert()`
        // from another task must never be blocked on it across an await.
        let standalone_sessions = self
            .standalone_sessions
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect::<Vec<_>>();
        for (peer_id, (handle, congestion_control)) in standalone_sessions {
            let telemetry = match path_telemetry_with_deadline(
                handle.path_telemetry(),
                RUNTIME_SNAPSHOT_TELEMETRY_DEADLINE,
            )
            .await
            {
                Ok(telemetry) => telemetry,
                Err(error) => {
                    tracing::debug!(
                        ?peer_id,
                        ?error,
                        "failed to sample standalone MP session while building runtime snapshot"
                    );
                    Vec::new()
                }
            };
            let paths = telemetry
                .iter()
                .map(|path| {
                    let state = match path_validation_decision(
                        path.validation_state,
                        CarrierKind::UdpDirect,
                    ) {
                        Some(true) => PathLifecycleState::AVAILABLE,
                        Some(false) => PathLifecycleState::Dead,
                        None => PathLifecycleState::Validating,
                    };
                    MpPathRuntimeSnapshot {
                        // `carrier_id` is only ever used to disambiguate
                        // multiple candidate-table entries that would
                        // otherwise share a `(local_addr, remote_addr)` key;
                        // a standalone session's paths already have unique
                        // (local_addr, remote_addr) pairs, and no wire-facing
                        // field reads this back (MP_SQM_PLAN.md §9's path
                        // matcher is `(egress_device, carrier_kind,
                        // remote_addr)`), so a fixed placeholder is safe.
                        key: PathKey {
                            local_addr: path.local_addr,
                            remote_addr: path.remote_addr,
                            carrier_id: CarrierId(0),
                        },
                        carrier_kind: CarrierKind::UdpDirect,
                        relay_metadata: None,
                        local_resource: ResourceGroupId::address_fallback(path.local_addr),
                        remote_resource: ResourceGroupId::remote_endpoint(path.remote_addr),
                        state,
                        measurements: path_measurements_from_telemetry(path),
                        telemetry: Some(path.clone()),
                        target_rate_bps: path.scheduler_target_rate_bps,
                        // MP_SQM_PLAN.md S2.3's path_policies are resolved
                        // against the candidate table / optimizer, neither of
                        // which a standalone (S1.4) session has -- it is
                        // never subject to path policies, same as it is
                        // never subject to TopK.
                        egress_device: String::new(),
                        user_policy: String::new(),
                        selection: PathSelectionDiagnostics::default(),
                    }
                })
                .collect::<Vec<_>>();
            snapshots.push(MpPeerRuntimeSnapshot {
                peer_id,
                paths,
                optimization: None,
                effective_congestion_control: congestion_control.to_string(),
                // MP_SQM_PLAN.md S2.6: see the field doc on
                // `desired_congestion_control`/`reconnect_required` -- a
                // standalone session is rebuilt directly on
                // `session_generation` bump, not via a desired/effective
                // divergence the GUI displays and the user confirms, so it
                // always reports its own captured value as both.
                desired_congestion_control: congestion_control.to_string(),
                reconnect_required: false,
                standalone: true,
                // A standalone session was built once, at connect time, from
                // whatever `MpConfig` existed then; `brutal_tx_bps` above is
                // resolved from the *current* config, which may have moved on
                // since. Best-effort: report it only when this session's own
                // captured CC still says brutal (cheap, no per-session
                // up_mbps is stored), rather than either always reporting the
                // current config's value or hard-wiring standalone to `None`.
                brutal_tx_bps: (congestion_control == "brutal")
                    .then_some(brutal_tx_bps)
                    .flatten(),
                peer_advertised_rx_bps: peer_advertised_rx_bps(peer_id),
                // The data plane runs only in MP-managed sessions.
                data_plane: Some(disabled_status("standalone")),
                faketcp_upgrade: None,
            });
        }
        Ok(snapshots)
    }

    pub(crate) async fn run_control_tick(&self) -> Result<MpControlTickResult, TunnelError> {
        let reaped_sessions = self.reap_closed_sessions().await;
        let pruned = self.prune_failed_and_stale_candidates().await;
        if pruned > 0 {
            tracing::debug!(pruned, "pruned failed or stale MP candidates");
        }
        let config = self.config.read().await.clone();
        if !config.enabled {
            return Ok(MpControlTickResult {
                reaped_sessions,
                snapshots: Vec::new(),
            });
        }
        self.push_data_plane_state(&config).await;
        let raw_capacities = self
            .refresh_all_egress_capacities(config.control_interval_ms.saturating_mul(2_000))
            .await?;
        // Telemetry was just refreshed, so every candidate carries the
        // latest peer-observed address.
        let deduped = self.retire_duplicate_wan_paths(&config.path_policies).await?;
        if deduped > 0 {
            tracing::debug!(deduped, "retired punched paths duplicating a WAN");
        }
        let mut capacities = raw_capacities
            .into_iter()
            .map(|capacity| (capacity.resource.clone(), capacity))
            .collect::<std::collections::HashMap<_, _>>();
        for group in &config.resource_groups {
            let group_resource = super::mp_path::ResourceGroupId::shared_bottleneck(&group.name);
            let auto_capacity = group
                .egress_devices
                .iter()
                .filter_map(|device| {
                    super::mp_path::ResourceGroupId::egress_device(device)
                        .ok()
                        .and_then(|resource| capacities.get(&resource))
                        .map(|capacity| capacity.capacity_bps)
                })
                .max()
                .unwrap_or(0);
            capacities.insert(
                group_resource.clone(),
                ResourceCapacity {
                    resource: group_resource,
                    capacity_bps: if group.capacity_bps > 0 {
                        group.capacity_bps
                    } else {
                        auto_capacity
                    },
                },
            );
        }
        let budgets = capacities.into_values().collect::<Vec<_>>();
        let kmax = config.kmax as usize;
        let session_slots = self
            .sessions
            .iter()
            .map(|session| (*session.key(), session.value().clone()))
            .collect::<Vec<_>>();
        let mut peer_ids = Vec::with_capacity(session_slots.len());
        for (peer_id, slot) in session_slots {
            match slot.try_lock() {
                Ok(session) if session.is_some() => peer_ids.push(peer_id),
                Ok(_) => tracing::debug!(
                    peer_id,
                    "skipping MP control tick while a session is still establishing"
                ),
                Err(error) => tracing::debug!(
                    peer_id,
                    ?error,
                    "skipping MP control tick while a session slot is busy"
                ),
            }
        }
        let mut snapshots = Vec::with_capacity(peer_ids.len());
        for peer_id in peer_ids {
            let snapshot = self
                .select_active_paths(peer_id, kmax, &budgets, &config.path_policies)
                .await?;
            snapshots.push(snapshot);
        }
        Ok(MpControlTickResult {
            reaped_sessions,
            snapshots,
        })
    }

    /// Chooses which of `peer_id`'s established paths carry data (at most
    /// `kmax`; the rest stand by) and sets the scheduler targets that follow.
    /// See `mp_optimizer::select_paths`. The incumbents are the paths the last
    /// selection chose, so the choice keeps them unless a challenger is clearly
    /// better; a dead path is no longer a candidate and is replaced at once.
    pub(crate) async fn select_active_paths(
        &self,
        peer_id: PeerId,
        kmax: usize,
        budgets: &[ResourceCapacity],
        path_policies: &[MpPathPolicy],
    ) -> Result<MpOptimizationSnapshot, TunnelError> {
        let (handle, rate_driven) = self.ready_session(peer_id).await?;
        let candidate_slot = self
            .candidates
            .get(&peer_id)
            .map(|entry| entry.clone())
            .ok_or_else(|| TunnelError::InternalError("mpquic candidates not found".into()))?;

        // MP_SQM_PLAN.md S2.3: resolved once per candidate, from the same
        // live `path_policies` every other consumer (`build_path_targets`'s
        // pause override, `runtime_snapshots`'s `user_policy` readback)
        // re-resolves independently -- see `resolve_candidate_path_policy`.
        let (candidate_count, input, incumbents) = {
            let candidates = candidate_slot.lock().await;
            let input = selection_input(&candidates, path_policies, &self.first_hop_loss_snapshot());
            // The incumbents are what the last selection chose, not every
            // path that is `AVAILABLE`: a path that has just been validated is
            // `AVAILABLE` too, and must not count as an incumbent.
            let incumbents = self
                .optimization_snapshots
                .get(&peer_id)
                .map(|snapshot| snapshot.active_paths.clone())
                .unwrap_or_default();
            (candidates.len(), input, incumbents)
        };
        let selected = select_paths(&input.paths, &incumbents, kmax, &input.pinned);
        if selected.iter().collect::<HashSet<_>>() != incumbents.iter().collect::<HashSet<_>>() {
            let describe = |key: &PathKey| format!("{}->{}", key.local_addr, key.remote_addr);
            let candidates = input
                .paths
                .iter()
                .map(|path| {
                    format!(
                        "{} {:?} {} ms",
                        describe(&path.key),
                        path.tier,
                        path.rtt_micros / 1_000
                    )
                })
                .chain(
                    input
                        .left_out
                        .iter()
                        .map(|(key, reason)| format!("{} left out: {reason}", describe(key))),
                )
                .collect::<Vec<_>>();
            tracing::info!(
                peer_id,
                before = ?incumbents.iter().map(describe).collect::<Vec<_>>(),
                after = ?selected.iter().map(describe).collect::<Vec<_>>(),
                ?candidates,
                "MP active path set changed"
            );
        }

        let targets = {
            let candidates = candidate_slot.lock().await;
            build_path_targets(
                &candidates,
                &selected,
                rate_driven,
                budgets,
                path_policies,
            )
        };
        let targets = clamp_targets_to_peer_rx_cap(targets, self.peer_rx_cap_bps(peer_id).await);
        handle.set_path_targets(targets.clone()).await?;

        {
            let mut candidates = candidate_slot.lock().await;
            let keys = candidates.iter().map(|(key, _)| *key).collect::<Vec<_>>();
            for key in keys {
                if candidates
                    .get(&key)
                    .is_some_and(|candidate| candidate.state.is_established())
                {
                    candidates.set_state(
                        &key,
                        if selected.contains(&key) {
                            PathLifecycleState::AVAILABLE
                        } else {
                            PathLifecycleState::STANDBY
                        },
                    );
                }
            }
        }

        let snapshot = MpOptimizationSnapshot {
            active_paths: selected,
            targets,
            candidate_count,
            eligible_count: input.paths.len(),
        };
        self.optimization_snapshots
            .insert(peer_id, snapshot.clone());
        Ok(snapshot)
    }

    /// Replaces the ping loss of each relay first hop's connection, by peer id.
    pub(crate) fn set_first_hop_loss(&self, loss: HashMap<PeerId, f64>) {
        *self.first_hop_loss.write().unwrap() = loss;
    }

    fn first_hop_loss_snapshot(&self) -> HashMap<PeerId, f64> {
        self.first_hop_loss.read().unwrap().clone()
    }

    pub(crate) fn optimization_snapshot(&self, peer_id: PeerId) -> Option<MpOptimizationSnapshot> {
        self.optimization_snapshots
            .get(&peer_id)
            .map(|snapshot| snapshot.clone())
    }

    pub(crate) async fn handle_path_down(
        &self,
        peer_id: PeerId,
        key: &crate::tunnel::mpquic::PathKey,
        kmax: usize,
        budgets: &[ResourceCapacity],
        path_policies: &[MpPathPolicy],
    ) -> Result<MpOptimizationSnapshot, TunnelError> {
        let candidate_slot = self
            .candidates
            .get(&peer_id)
            .map(|entry| entry.clone())
            .ok_or_else(|| TunnelError::InternalError("mpquic candidates not found".into()))?;
        if !candidate_slot.lock().await.mark_dead(key) {
            return Err(TunnelError::InternalError(format!(
                "mpquic path {:?} is not tracked",
                key
            )));
        }

        let (handle, _) = self.ready_session(peer_id).await?;
        handle.remove_path(key.local_addr, key.remote_addr).await?;

        self.select_active_paths(peer_id, kmax, budgets, path_policies)
            .await
    }

    pub(crate) async fn has_live_carrier(
        &self,
        peer_id: PeerId,
        carrier_kind: super::mp_path::CarrierKind,
    ) -> bool {
        let Some(slot) = self.candidates.get(&peer_id).map(|entry| entry.clone()) else {
            return false;
        };
        let candidates = slot.lock().await;
        candidates.live_of_kind(carrier_kind).next().is_some()
    }

    /// The egress device of each of `peer_id`'s live carriers of one kind
    /// (`None` for a carrier without a device) -- `has_live_carrier`, per NIC.
    pub(crate) async fn live_carrier_devices(
        &self,
        peer_id: PeerId,
        carrier_kind: super::mp_path::CarrierKind,
    ) -> Vec<Option<String>> {
        let Some(slot) = self.candidates.get(&peer_id).map(|entry| entry.clone()) else {
            return Vec::new();
        };
        let candidates = slot.lock().await;
        candidates
            .live_of_kind(carrier_kind)
            // `egress_device_name` also survives the move into a WAN group,
            // which drops the device from `egress_resource`.
            .map(|candidate| {
                Some(candidate.spec.egress_device_name())
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned)
            })
            .collect()
    }

    /// Summarise the live punched carriers of one kind to `peer_id` by the WAN each one
    /// leaves through, as reported by the peer (TQUIC OBSERVED_ADDRESS). The
    /// host never probes this itself: under mwan3 the WAN choice is made by
    /// the router per conntrack entry and is invisible locally.
    pub(crate) async fn punch_wan_summary(
        &self,
        peer_id: PeerId,
        carrier_kind: super::mp_path::CarrierKind,
    ) -> PunchWanSummary {
        let held_until = self
            .punch_drops
            .get(&(peer_id, carrier_kind))
            .map(|drop| drop.held_until);
        let Some(slot) = self.candidates.get(&peer_id).map(|entry| entry.clone()) else {
            return PunchWanSummary {
                held_until,
                ..PunchWanSummary::default()
            };
        };
        let candidates = slot.lock().await;
        let mut summary = PunchWanSummary::default();
        // Whether to punch another path depends on the WANs that already have
        // a direct path to this peer over any carrier, not on this kind's alone:
        // a live UDP path already reaches the peer through that WAN.
        for candidate in candidates.live_direct() {
            summary.live += 1;
            match candidate.measurements.observed_local_addr {
                Some(addr) => {
                    summary.wans.insert(addr.ip());
                }
                None => summary.unobserved += 1,
            }
        }
        summary.held_until = self
            .punch_drops
            .get(&(peer_id, carrier_kind))
            .map(|drop| drop.held_until);
        summary
    }

    pub(crate) async fn has_live_relay_egress(
        &self,
        peer_id: PeerId,
        egress_first_hop_peer_id: PeerId,
    ) -> bool {
        let Some(slot) = self.candidates.get(&peer_id).map(|entry| entry.clone()) else {
            return false;
        };
        let candidates = slot.lock().await;
        candidates
            .live_of_kind(super::mp_path::CarrierKind::RelayNextHop)
            .any(|candidate| {
                candidate.spec.relay_metadata.is_some_and(|metadata| {
                    metadata.egress_first_hop_peer_id == egress_first_hop_peer_id
                })
            })
    }

    /// Relay paths to `peer_id` that are not dead and whose physical first hop
    /// does not lose pings. ET: only these use up the relay path budget; a
    /// path over a lossy first hop that kept its place would stop a better
    /// first hop from getting one (MP weak-network plan R2). Such a path is not
    /// torn down here: the selector gives way from it and the idle reaper
    /// removes it.
    pub(crate) async fn live_relay_path_count(&self, peer_id: PeerId) -> usize {
        let Some(slot) = self.candidates.get(&peer_id).map(|entry| entry.clone()) else {
            return 0;
        };
        let first_hop_loss = self.first_hop_loss_snapshot();
        let candidates = slot.lock().await;
        candidates
            .live_of_kind(super::mp_path::CarrierKind::RelayNextHop)
            .filter(|candidate| {
                candidate
                    .spec
                    .relay_metadata
                    .and_then(|metadata| first_hop_loss.get(&metadata.egress_first_hop_peer_id))
                    .map_or(true, |&loss| {
                        super::mp_path::FirstHopHealth::from_loss(loss)
                            == super::mp_path::FirstHopHealth::Clean
                    })
            })
            .count()
    }

    #[cfg(test)]
    pub(crate) fn tracked_peer_count(&self) -> usize {
        self.sessions.len()
    }

    #[cfg(test)]
    pub(crate) async fn tracked_candidate_count(&self, peer_id: PeerId) -> usize {
        let Some(slot) = self.candidates.get(&peer_id).map(|entry| entry.clone()) else {
            return 0;
        };
        let candidates = slot.lock().await;
        candidates.len()
    }

    #[cfg(test)]
    pub(crate) async fn candidate_state(
        &self,
        peer_id: PeerId,
        key: &crate::tunnel::mpquic::PathKey,
    ) -> Option<crate::connector::mp_path::PathLifecycleState> {
        let slot = self.candidates.get(&peer_id).map(|entry| entry.clone())?;
        let candidates = slot.lock().await;
        candidates.get(key).map(|candidate| candidate.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reflector_addresses_follow_the_sqm_config() {
        use crate::common::egress_quality::reflectors::DEFAULT_REFLECTORS;
        let mut config = gen_default_mp_config();
        assert_eq!(reflector_addresses(&config), Some(DEFAULT_REFLECTORS.to_vec()));
        let sqm = config.sqm.as_mut().unwrap();
        sqm.reflectors = vec!["223.5.5.5".into(), "bad".into(), "1.2.4.8".into()];
        assert_eq!(
            reflector_addresses(&config),
            Some(vec![
                std::net::Ipv4Addr::new(223, 5, 5, 5),
                std::net::Ipv4Addr::new(1, 2, 4, 8)
            ])
        );
        config.sqm.as_mut().unwrap().reflectors_disabled = true;
        assert_eq!(reflector_addresses(&config), None);
        config.sqm = None;
        assert_eq!(reflector_addresses(&config), Some(DEFAULT_REFLECTORS.to_vec()));
    }

    /// S-I10: the NIC's counter, not the MP paths' sent bytes, is the load
    /// once two readings exist; before that, and when the NIC cannot be read,
    /// the paths' bytes stand in and the source says so.
    #[test]
    fn egress_load_is_the_nic_counter_when_it_can_be_read() {
        let mut last = None;
        // First tick: no earlier counter reading.
        assert_eq!(
            egress_sent_delta(&mut last, Some(1_000), 70),
            (70, AchievedSource::PathSentBytes)
        );
        // Traffic that is not ours fills the NIC: 5 MB on the counter while
        // our paths sent 70 kB.
        assert_eq!(
            egress_sent_delta(&mut last, Some(5_001_000), 70_000),
            (5_000_000, AchievedSource::NicCounter)
        );
        // The counter vanishes (interface down): back to the paths, and the
        // next reading starts a fresh baseline.
        assert_eq!(
            egress_sent_delta(&mut last, None, 40),
            (40, AchievedSource::PathSentBytes)
        );
        assert_eq!(
            egress_sent_delta(&mut last, Some(9_000_000), 50),
            (50, AchievedSource::PathSentBytes)
        );
        assert_eq!(
            egress_sent_delta(&mut last, Some(9_000_500), 50),
            (500, AchievedSource::NicCounter)
        );
    }

    use crate::{
        common::egress_quality::EgressQualityConfig,
        connector::mp_path::{
            CarrierKind, MpPathProvider, MpPathSpec, PathLifecycleState, PathMeasurements,
            UdpMpPathProvider,
        },
        tunnel::{
            Tunnel, TunnelConnector, TunnelListener,
            mpquic::{MpDatagramPath, MpQuicTunnelConnector, MpQuicTunnelListener},
            packet_def::ZCPacket,
        },
    };
    use futures_util::{SinkExt, StreamExt};
    use std::{
        net::SocketAddr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    fn rtt_path(
        state: PathLifecycleState,
        age_s: Option<u64>,
        srtt_ms: u64,
        min_ms: u64,
    ) -> PathRtt {
        PathRtt {
            state,
            sample_age_micros: age_s.map(|s| s * 1_000_000),
            srtt_micros: srtt_ms * 1_000,
            min_rtt_micros: min_ms * 1_000,
        }
    }

    /// OWD_AUTORATE_PLAN.md 1.3 (R1): a standby path gets no new RTT sample, so
    /// its frozen `srtt` says nothing about the egress now (RFC 6817 Section
    /// 2.5: a delay sample must not be older than a round trip).
    #[test]
    fn a_stale_backup_rtt_is_not_the_egress_delay() {
        const MAX_AGE: u64 = 1_000_000;
        let active = rtt_path(PathLifecycleState::AVAILABLE, Some(0), 21, 20);
        let backup = rtt_path(PathLifecycleState::STANDBY, Some(25), 430, 1);
        assert_eq!(
            egress_rtt_delay_us(&[active, backup], MAX_AGE),
            Some(1_000),
            "the standby path's frozen round trip must not be the egress delay"
        );
        assert_eq!(
            egress_rtt_delay_us(&[backup], MAX_AGE),
            None,
            "no active path with a fresh sample: nothing to feed"
        );
        // An active path whose sample is stale, or has none, does not count either.
        let stale_active = rtt_path(PathLifecycleState::AVAILABLE, Some(25), 430, 1);
        let unsampled = PathRtt {
            sample_age_micros: None,
            ..active
        };
        assert_eq!(
            egress_rtt_delay_us(&[stale_active, unsampled], MAX_AGE),
            None
        );
        // Several fresh active paths: the smallest, not the largest.
        let slow = rtt_path(PathLifecycleState::AVAILABLE, Some(0), 90, 20);
        assert_eq!(egress_rtt_delay_us(&[slow, active], MAX_AGE), Some(1_000));
        assert_eq!(egress_rtt_delay_us(&[], MAX_AGE), None);
    }

    /// Every test that used to construct `MpSessionManager::new(test_egress_quality_manager())`/
    /// `new_with_config()` with no egress-quality argument now needs one; a
    /// fresh manager per call keeps tests independent (mirrors each test
    /// previously getting its own fresh `EgressSqmRegistry`).
    fn test_egress_quality_manager() -> Arc<EgressQualityManager> {
        EgressQualityManager::new(EgressQualityConfig::default())
    }

    struct ChannelPath {
        local: SocketAddr,
        remote: SocketAddr,
        tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        rx: Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>,
        sent: AtomicUsize,
        received: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl MpDatagramPath for ChannelPath {
        fn local_addr(&self) -> SocketAddr {
            self.local
        }

        fn try_send_to(&self, payload: &[u8], remote: SocketAddr) -> std::io::Result<usize> {
            if remote != self.remote {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("channel path targets {}, not {remote}", self.remote),
                ));
            }
            self.tx.send(payload.to_vec()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "channel path peer closed")
            })?;
            self.sent.fetch_add(1, Ordering::Relaxed);
            Ok(payload.len())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            let payload = self.rx.lock().await.recv().await.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "channel path peer closed")
            })?;
            if payload.len() > buf.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "channel path datagram exceeds receive buffer",
                ));
            }
            buf[..payload.len()].copy_from_slice(&payload);
            self.received.fetch_add(1, Ordering::Relaxed);
            Ok((payload.len(), self.remote))
        }
    }

    fn channel_path_pair(a: SocketAddr, b: SocketAddr) -> (Arc<ChannelPath>, Arc<ChannelPath>) {
        let (a_to_b, b_rx) = tokio::sync::mpsc::unbounded_channel();
        let (b_to_a, a_rx) = tokio::sync::mpsc::unbounded_channel();
        (
            Arc::new(ChannelPath {
                local: a,
                remote: b,
                tx: a_to_b,
                rx: Mutex::new(a_rx),
                sent: AtomicUsize::new(0),
                received: AtomicUsize::new(0),
            }),
            Arc::new(ChannelPath {
                local: b,
                remote: a,
                tx: b_to_a,
                rx: Mutex::new(b_rx),
                sent: AtomicUsize::new(0),
                received: AtomicUsize::new(0),
            }),
        )
    }

    fn path_spec(path: Arc<ChannelPath>, remote: SocketAddr) -> MpPathSpec {
        let carrier: Arc<dyn MpDatagramPath> = path;
        MpPathSpec::with_default_resources(carrier, remote, CarrierKind::Manual)
    }

    fn egress_binding(
        egress: crate::common::egress_inventory::EgressStableId,
        platform_name: &str,
        local_addr: SocketAddr,
        target: std::net::IpAddr,
        generation: u64,
    ) -> crate::common::egress_inventory::EgressSocketBinding {
        let runtime_ifindex = match &egress {
            crate::common::egress_inventory::EgressStableId::Linux { ifindex, .. } => *ifindex,
            _ => 0,
        };
        crate::common::egress_inventory::EgressSocketBinding {
            egress: egress.clone(),
            generation,
            inventory_revision: 1,
            runtime_ifindex,
            platform_name: platform_name.into(),
            local_addr,
            route: crate::common::egress_inventory::RouteResolution {
                target,
                requested_egress: Some(egress.clone()),
                selected_egress: Some(egress),
                output_ifindex: runtime_ifindex,
                source: Some(local_addr.ip()),
                gateway: None,
                metric: None,
                table: None,
                inventory_revision: 1,
            },
        }
    }

    fn inventory_interface(
        id: crate::common::egress_inventory::EgressStableId,
        platform_name: &str,
        generation: u64,
        address: std::net::IpAddr,
    ) -> crate::common::egress_inventory::EgressInterfaceSnapshot {
        let runtime_ifindex = match &id {
            crate::common::egress_inventory::EgressStableId::Linux { ifindex, .. } => *ifindex,
            _ => 0,
        };
        crate::common::egress_inventory::EgressInterfaceSnapshot {
            id,
            revision: 2,
            generation,
            platform_name: platform_name.into(),
            display_name: platform_name.into(),
            aliases: vec![platform_name.into()],
            hardware_address: None,
            runtime_ifindex,
            kind: crate::common::egress_inventory::EgressKind::Physical,
            oper_state: crate::common::egress_inventory::OperState::Up,
            addresses: vec![crate::common::egress_inventory::InterfaceAddress {
                ip: address,
                prefix_len: if address.is_ipv4() { 24 } else { 64 },
            }],
            mtu: Some(1500),
            transmit_speed_bps: None,
            receive_speed_bps: None,
            is_eligible: true,
            exclusion_reasons: Vec::new(),
            watch_mode: crate::common::egress_inventory::WatchMode::Native,
        }
    }

    async fn real_udp_egress_spec(
        egress: crate::common::egress_inventory::EgressStableId,
        platform_name: &str,
        generation: u64,
    ) -> (MpPathSpec, tokio::net::UdpSocket) {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let remote = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();
        let remote_addr = remote.local_addr().unwrap();
        let provider = UdpMpPathProvider::new_on_egress(
            CarrierKind::UdpPunch,
            socket,
            remote_addr,
            egress_binding(
                egress,
                platform_name,
                local_addr,
                remote_addr.ip(),
                generation,
            ),
        )
        .unwrap();
        let mut paths = provider.discover().await.unwrap();
        assert_eq!(paths.len(), 1);
        (paths.pop().unwrap(), remote)
    }

    async fn real_udp_legacy_spec() -> (MpPathSpec, tokio::net::UdpSocket) {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let remote = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let provider = UdpMpPathProvider::new(
            CarrierKind::UdpPunch,
            socket,
            remote.local_addr().unwrap(),
            None,
        )
        .unwrap();
        let mut paths = provider.discover().await.unwrap();
        assert_eq!(paths.len(), 1);
        assert!(paths[0].egress_binding.is_none());
        (paths.pop().unwrap(), remote)
    }

    #[tokio::test]
    async fn manager_starts_without_peer_sessions() {
        assert_eq!(MpSessionManager::new(test_egress_quality_manager()).tracked_peer_count(), 0);
    }

    #[test]
    fn mp_session_rejects_an_unspecified_remote_endpoint() {
        assert!(!has_concrete_remote_endpoint("0.0.0.0:0".parse().unwrap()));
        assert!(!has_concrete_remote_endpoint("[::]:0".parse().unwrap()));
        assert!(has_concrete_remote_endpoint(
            "198.51.100.20:443".parse().unwrap()
        ));
    }

    #[tokio::test]
    async fn closed_session_is_reaped_and_its_candidate_table_is_removed() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let (path, _) = channel_path_pair(
            "127.0.0.1:40941".parse().unwrap(),
            "127.0.0.2:40942".parse().unwrap(),
        );
        let spec = path_spec(path, "127.0.0.2:40942".parse().unwrap());
        let key = spec.key;
        let mut candidates = MpCandidateTable::default();
        candidates.upsert(spec, Instant::now());
        candidates.set_state(&key, PathLifecycleState::AVAILABLE);
        manager
            .candidates
            .insert(7, Arc::new(Mutex::new(candidates)));
        manager.sessions.insert(
            7,
            Arc::new(Mutex::new(Some(Session {
                handle: MpSessionHandle::closed_for_test(),
                congestion_control: CongestionControlProfile::EngineDefault,
                is_server: false,
            }))),
        );
        manager.manual_paths.insert(
            "manual://closed".into(),
            ManagedManualPath { peer_id: 7, key },
        );

        let reaped = manager.reap_closed_sessions().await;

        assert_eq!(reaped, 1);
        assert_eq!(manager.tracked_peer_count(), 0);
        assert_eq!(manager.tracked_candidate_count(7).await, 0);
        assert_eq!(manager.candidate_state(7, &key).await, None);
        assert!(!manager.manual_paths.contains_key("manual://closed"));
    }

    #[tokio::test]
    async fn control_tick_reports_each_closed_session_it_reaps() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let (path, _) = channel_path_pair(
            "127.0.0.1:40943".parse().unwrap(),
            "127.0.0.2:40944".parse().unwrap(),
        );
        let spec = path_spec(path, "127.0.0.2:40944".parse().unwrap());
        let key = spec.key;
        let mut candidates = MpCandidateTable::default();
        candidates.upsert(spec, Instant::now());
        candidates.set_state(&key, PathLifecycleState::AVAILABLE);
        manager
            .candidates
            .insert(7, Arc::new(Mutex::new(candidates)));
        manager.sessions.insert(
            7,
            Arc::new(Mutex::new(Some(Session {
                handle: MpSessionHandle::closed_for_test(),
                congestion_control: CongestionControlProfile::EngineDefault,
                is_server: false,
            }))),
        );

        let tick = manager.run_control_tick().await.unwrap();

        assert_eq!(
            tick.reaped_sessions, 1,
            "the control-cycle result must expose every session it actually reaped"
        );
        assert!(tick.snapshots.is_empty());
        assert_eq!(manager.tracked_peer_count(), 0);
        assert_eq!(manager.tracked_candidate_count(7).await, 0);
    }

    #[tokio::test]
    async fn peer_removal_forgets_mp_state_immediately() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let (path, _) = channel_path_pair(
            "127.0.0.1:40951".parse().unwrap(),
            "127.0.0.2:40952".parse().unwrap(),
        );
        let spec = path_spec(path, "127.0.0.2:40952".parse().unwrap());
        let key = spec.key;
        let mut candidates = MpCandidateTable::default();
        candidates.upsert(spec, Instant::now());
        candidates.set_state(&key, PathLifecycleState::AVAILABLE);
        manager
            .candidates
            .insert(7, Arc::new(Mutex::new(candidates)));
        manager.sessions.insert(
            7,
            Arc::new(Mutex::new(Some(Session {
                handle: MpSessionHandle::closed_for_test(),
                congestion_control: CongestionControlProfile::EngineDefault,
                is_server: false,
            }))),
        );
        manager.manual_paths.insert(
            "manual://removed-peer".into(),
            ManagedManualPath { peer_id: 7, key },
        );

        assert!(manager.forget_peer(7).await);

        assert_eq!(manager.tracked_peer_count(), 0);
        assert_eq!(manager.tracked_candidate_count(7).await, 0);
        assert_eq!(manager.candidate_state(7, &key).await, None);
        assert!(!manager.manual_paths.contains_key("manual://removed-peer"));
    }

    #[tokio::test]
    async fn runtime_snapshot_reports_instantiated_cc_not_new_desired_config() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        manager.sessions.insert(
            7,
            Arc::new(Mutex::new(Some(Session {
                handle: MpSessionHandle::closed_for_test(),
                congestion_control: CongestionControlProfile::Bbr,
                is_server: false,
            }))),
        );
        manager.config.write().await.congestion_control = "cubic".into();

        let snapshots = manager.runtime_snapshots().await.unwrap();

        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].effective_congestion_control, "bbr");
        // MP_SQM_PLAN.md S2.6: the same divergence must also surface as
        // `desired_congestion_control`/`reconnect_required` -- this is the
        // exact runtime state the plan's field-effect table promises the
        // GUI before the user confirms a rebuild.
        assert_eq!(snapshots[0].desired_congestion_control, "cubic");
        assert!(
            snapshots[0].reconnect_required,
            "a live session whose captured CC disagrees with the desired config must ask for reconnect"
        );
    }

    /// MP_SQM_PLAN.md S2.6: no live session yet (nothing captured to
    /// diverge from) must never claim `reconnect_required`, even though
    /// `effective_congestion_control` falls back to reporting the currently
    /// configured value in that case (see the field's own doc comment).
    #[tokio::test]
    async fn runtime_snapshot_does_not_require_reconnect_with_no_live_session() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        manager.sessions.insert(7, Arc::new(Mutex::new(None)));
        manager.config.write().await.congestion_control = "cubic".into();

        let snapshots = manager.runtime_snapshots().await.unwrap();

        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].effective_congestion_control, "cubic");
        assert_eq!(snapshots[0].desired_congestion_control, "cubic");
        assert!(!snapshots[0].reconnect_required);
    }

    /// MP_SQM_PLAN.md S2.6: changing a `hot`-classified field (here,
    /// `kmax`, which never participates in session construction at all)
    /// through `set_config` on a live session must never set
    /// `reconnect_required` and must never require a `session_generation`
    /// bump -- the regression this guards against is accidentally routing a
    /// hot field through the same divergence check `congestion_control`
    /// uses.
    #[tokio::test]
    async fn set_config_hot_field_change_never_requires_reconnect() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        manager.sessions.insert(
            7,
            Arc::new(Mutex::new(Some(Session {
                handle: MpSessionHandle::closed_for_test(),
                congestion_control: CongestionControlProfile::EngineDefault,
                is_server: false,
            }))),
        );
        let mut config = gen_default_mp_config();
        config.enabled = true;
        let unchanged_generation = config.session_generation;

        config.kmax += 1;
        manager.set_config(config.clone()).await.unwrap();

        let snapshots = manager.runtime_snapshots().await.unwrap();
        assert_eq!(snapshots.len(), 1);
        assert!(
            !snapshots[0].reconnect_required,
            "a hot field change must never require reconnect"
        );
        assert_eq!(
            manager.config.read().await.session_generation,
            unchanged_generation,
            "set_config must never bump session_generation on its own"
        );
    }

    /// MP_SQM_PLAN.md S2.6: every `reconnect` field of the field-effect
    /// table, not only the congestion control, marks a live session stale.
    #[tokio::test]
    async fn reconnect_field_change_other_than_cc_requires_reconnect() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let mut config = gen_default_mp_config();
        config.enabled = true;
        manager.set_config(config.clone()).await.unwrap();
        manager.sessions.insert(
            7,
            Arc::new(Mutex::new(Some(Session {
                handle: MpSessionHandle::closed_for_test(),
                congestion_control: CongestionControlProfile::EngineDefault,
                is_server: false,
            }))),
        );
        manager
            .session_fingerprints
            .insert(7, mp_reconnect_fingerprint(&config));
        assert!(!manager.runtime_snapshots().await.unwrap()[0].reconnect_required);

        config.sqm.get_or_insert_with(Default::default).enabled = true;
        manager.set_config(config.clone()).await.unwrap();
        assert!(
            manager.runtime_snapshots().await.unwrap()[0].reconnect_required,
            "sqm.enabled is a reconnect field"
        );

        config.sqm.get_or_insert_with(Default::default).enabled = false;
        config.data_plane.get_or_insert_with(Default::default).enabled = true;
        manager.set_config(config).await.unwrap();
        assert!(
            manager.runtime_snapshots().await.unwrap()[0].reconnect_required,
            "data_plane.enabled is a reconnect field"
        );
    }

    /// MP_SQM_PLAN.md S2.6, gray-box: bumping `session_generation` on a live
    /// MP-managed session must tear it down via the existing `forget_peer`
    /// path (not `standalone_sessions`, which `forget_peer` never touches --
    /// see [`forget_all_peers`]/[`MpSessionManager::standalone_sessions`]'s
    /// own doc comment) so EasyTier's own reconnect logic can rebuild it
    /// under the new config. Uses the same `closed_for_test()` shortcut as
    /// the other white-box `Session` tests above: this test is about
    /// `set_config`'s own bookkeeping (does the generation bump reach
    /// `forget_peer`), not about a real TQUIC handshake, which the
    /// standalone gray-box test below already covers for the
    /// desired/effective/payload-continuity path.
    #[tokio::test]
    async fn set_config_generation_bump_forgets_every_mp_managed_peer() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let (path, _) = channel_path_pair(
            "127.0.0.1:40961".parse().unwrap(),
            "127.0.0.2:40962".parse().unwrap(),
        );
        let spec = path_spec(path, "127.0.0.2:40962".parse().unwrap());
        let key = spec.key;
        let mut candidates = MpCandidateTable::default();
        candidates.upsert(spec, Instant::now());
        candidates.set_state(&key, PathLifecycleState::AVAILABLE);
        manager
            .candidates
            .insert(7, Arc::new(Mutex::new(candidates)));
        manager.sessions.insert(
            7,
            Arc::new(Mutex::new(Some(Session {
                handle: MpSessionHandle::closed_for_test(),
                congestion_control: CongestionControlProfile::EngineDefault,
                is_server: false,
            }))),
        );

        let mut config = gen_default_mp_config();
        config.enabled = true;
        // A config change with no generation bump must leave the session alone.
        manager.set_config(config.clone()).await.unwrap();
        assert_eq!(manager.tracked_peer_count(), 1, "no generation bump must not forget anyone");

        config.session_generation += 1;
        manager.set_config(config).await.unwrap();
        assert_eq!(
            manager.tracked_peer_count(),
            0,
            "a session_generation bump must forget every MP-managed peer via forget_peer"
        );
        assert_eq!(manager.tracked_candidate_count(7).await, 0);
    }

    /// MP_SQM_PLAN.md S1.4, grey-box: a real loopback `mpquic://` pair opened
    /// the standalone way (`MpQuicTunnelConnector`/`MpQuicTunnelListener`
    /// directly, exactly how `manual`/`direct`/`dns` connectors dial it --
    /// not through `MpSessionManager::offer_path`) surfaces a real,
    /// telemetry-producing `MpSessionHandle` via `Tunnel::mp_session_handle`.
    /// Registering it must (a) show up in `runtime_snapshots()` tagged
    /// `standalone` with real paths while MP stays disabled (this manager's
    /// own `config` never gets `enabled = true`), (b) survive an MP on/off
    /// toggle that runs `clear_disabled_runtime_state`, and (c) disappear
    /// once the handle actually closes.
    // MP_SQM_PLAN.md S1.4: `flavor = "multi_thread"`, not the bare
    // `#[tokio::test]` default (single-threaded `current_thread`) --
    // every other real-loopback `mpquic://` test in this crate
    // (`tunnel::mpquic::tests::*`) drives its connector/listener pair from
    // a multi-threaded runtime (see that module's `static RUNTIME:
    // LazyLock<Runtime>`) for exactly this reason: a standalone
    // connect()/accept() pair run concurrently via `tokio::spawn` plus a
    // real background driver OS thread, and a single-worker runtime can
    // starve the spawned `accept()` task indefinitely.
    #[tokio::test(flavor = "multi_thread")]
    async fn standalone_mpquic_session_reports_survives_mp_toggle_and_reaps_on_close() {
        let url: url::Url = "mpquic://127.0.0.1:41077".parse().unwrap();
        let mut listener = MpQuicTunnelListener::new(url.clone());
        listener.listen().await.unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let mut connector = MpQuicTunnelConnector::new(url);
        let client_tunnel = connector.connect().await.unwrap();
        // A standalone server's `accept()` only resolves once TQUIC signals
        // `StreamCreated` on ITS side (see `drive()`'s `DrvEvent::
        // StreamCreated` arm) -- and that only fires once the server has
        // actually received a STREAM frame. Opening the client's stream
        // locally (`connect()` already did that, to signal its own ready)
        // never puts a byte on the wire by itself; TQUIC only sends the
        // frame once there is real payload to carry. So a standalone accept
        // needs the client to actually push at least one packet before it
        // will ever unblock -- not a bug in the S1.3/S1.4 remainder, just
        // the same requirement every other real-loopback mpquic test
        // (`_tunnel_pingpong`, `mpquic_loopback_udp_payload_sha_for_default_and_cubic`)
        // already satisfies by sending real payload up front.
        //
        // Deliberately NOT scoped to a block: dropping either half of a
        // `split()` view closes the ET<->driver duplex pipe (the driver
        // exits with "EasyTier application pipe closed"/"remote stream
        // finished" the moment either side goes away), which would tear the
        // whole session down before this test ever gets to exercise
        // `runtime_snapshots()`. These stay alive until the explicit
        // teardown below.
        let (_client_recv, mut client_send) = client_tunnel.split();
        client_send
            .send(ZCPacket::new_with_payload(
                b"MP_SQM_PLAN.md S1.4 standalone-session probe",
            ))
            .await
            .unwrap();
        let server_tunnel = accept.await.unwrap();

        // Both standalone entry points must surface the plumbing -- this is
        // the additive `Tunnel::mp_session_handle` default being overridden,
        // not a managed-session shortcut.
        let client_handle = client_tunnel
            .mp_session_handle()
            .expect("standalone connector must surface its MpSessionHandle");
        assert!(
            server_tunnel.mp_session_handle().is_some(),
            "standalone listener must surface its MpSessionHandle too"
        );
        // MP_SQM_PLAN.md S2.2 follow-up: a standalone session must report
        // the real congestion-control profile it was built with, same as an
        // MP-managed one -- never the literal placeholder string
        // `"unknown"` this used to be hardcoded to.
        let client_congestion_control = client_tunnel
            .mp_congestion_control()
            .expect("standalone connector must surface its congestion-control profile");
        assert_eq!(client_congestion_control, "engine-default");

        let manager = MpSessionManager::new(test_egress_quality_manager());
        assert!(!manager.config.read().await.enabled, "MP must stay off throughout this test");
        manager.register_standalone_session(99, client_handle.clone(), client_congestion_control, false).await;

        let snapshots = manager.runtime_snapshots().await.unwrap();
        let entry = snapshots
            .iter()
            .find(|snapshot| snapshot.peer_id == 99)
            .expect("standalone session must appear in runtime_snapshots()");
        assert!(entry.standalone, "must be tagged standalone, not managed");
        assert!(
            !entry.paths.is_empty(),
            "a real, connected loopback pair must report at least one real path"
        );
        assert_eq!(
            entry.effective_congestion_control, "engine-default",
            "must report the real profile, never the old \"unknown\" placeholder"
        );

        // Toggling MP on then back off runs `clear_disabled_runtime_state`,
        // which must never touch `standalone_sessions`.
        let mut enabled = gen_default_mp_config();
        enabled.enabled = true;
        manager.set_config(enabled).await.unwrap();
        manager.set_config(gen_default_mp_config()).await.unwrap();
        assert!(
            manager
                .runtime_snapshots()
                .await
                .unwrap()
                .iter()
                .any(|snapshot| snapshot.peer_id == 99),
            "an MP on/off toggle must not clear a standalone session"
        );

        // Close the tunnel (the same effect `PeerConn` closing it has) and
        // wait -- bounded, not sleep-and-hope -- for the driver to actually
        // exit and the handle to report closed. Every outstanding split
        // view has to go too, not just the tunnels themselves -- see the
        // note above `client_send`.
        drop(_client_recv);
        drop(client_send);
        drop(client_tunnel);
        drop(server_tunnel);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !client_handle.is_closed() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("driver must exit after both ends of the tunnel are dropped");

        manager.reap_closed_sessions().await;
        assert!(
            !manager
                .runtime_snapshots()
                .await
                .unwrap()
                .iter()
                .any(|snapshot| snapshot.peer_id == 99),
            "a closed standalone session must be reaped"
        );
    }

    /// S-I19: with MP enabled, a directly connected `mpquic://` session that
    /// finished its handshake joins the candidate table and the optimizer and
    /// is reported as managed, not standalone.
    #[tokio::test]
    async fn direct_mpquic_session_is_adopted_into_mp_when_enabled() {
        let url: url::Url = "mpquic://127.0.0.1:41078".parse().unwrap();
        let mut listener = MpQuicTunnelListener::new(url.clone());
        listener.listen().await.unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let mut connector = MpQuicTunnelConnector::new(url);
        let client_tunnel = connector.connect().await.unwrap();
        let (_client_recv, mut client_send) = client_tunnel.split();
        client_send
            .send(ZCPacket::new_with_payload(b"S-I19 adoption probe"))
            .await
            .unwrap();
        let _server_tunnel = accept.await.unwrap();
        let handle = client_tunnel.mp_session_handle().unwrap();
        let congestion_control = client_tunnel.mp_congestion_control().unwrap();

        let manager = MpSessionManager::new(test_egress_quality_manager());
        let mut enabled = gen_default_mp_config();
        enabled.enabled = true;
        manager.set_config(enabled).await.unwrap();
        manager
            .register_standalone_session(77, handle.clone(), congestion_control, false)
            .await;

        assert!(
            manager.standalone_sessions.get(&77).is_none(),
            "an adopted session is managed, not standalone"
        );
        assert_eq!(manager.tracked_candidate_count(77).await, 1);
        let tick = manager.run_control_tick().await.unwrap();
        assert!(!tick.snapshots.is_empty(), "the optimizer ran for the adopted session");
        let snapshots = manager.runtime_snapshots().await.unwrap();
        let entry = snapshots
            .iter()
            .find(|snapshot| snapshot.peer_id == 77)
            .expect("the adopted session is reported");
        assert!(!entry.standalone);
        assert!(entry.optimization.is_some(), "the optimizer manages it");

        // a second session for the peer is not adopted; the first is kept
        manager
            .register_standalone_session(77, handle, congestion_control, false)
            .await;
        assert!(manager.standalone_sessions.get(&77).is_some());
    }

    /// MP_SQM_PLAN.md S2.6, gray-box: a `session_generation` bump must tear
    /// down a *real* standalone session's handle (not `closed_for_test()`),
    /// proving `shutdown_all_standalone_sessions` actually reaches a live
    /// TQUIC connection through `MpSessionHandle::shutdown`, same as
    /// `forget_peer` already does for MP-managed sessions. MP stays
    /// disabled throughout (standalone sessions are independent of it, see
    /// `set_config`'s own doc comment on `generation_bumped`).
    ///
    /// This test stops at "the old handle closes" -- it does not drive a
    /// full reconnect-with-new-CC-and-payload-continuity cycle, because that
    /// reconnect is orchestrated by `peers::peer_manager`'s own connector
    /// retry loop (outside `MpSessionManager`), not by anything in this
    /// file; see the PROJECT_journal.md S2.6 entry for the open question on
    /// where that fuller test belongs.
    #[tokio::test(flavor = "multi_thread")]
    async fn set_config_generation_bump_closes_a_real_standalone_session() {
        // 41078 collides with `standalone_mpquic_session_reports_a_real_
        // target_rate_in_bits_per_sec` further down this file -- picked
        // without checking first; two `#[tokio::test(flavor =
        // "multi_thread")]` tests binding the same UDP port concurrently
        // under `--test-threads=4` hung this test indefinitely (diagnosed
        // via the S2.5-fix gate run getting stuck on it) rather than failing
        // fast. 41090 is free (checked against every hardcoded loopback port
        // in this file and `tunnel/mpquic.rs`).
        let url: url::Url = "mpquic://127.0.0.1:41090".parse().unwrap();
        let mut listener = MpQuicTunnelListener::new(url.clone());
        listener.listen().await.unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let mut connector = MpQuicTunnelConnector::new(url);
        let client_tunnel = connector.connect().await.unwrap();
        let (_client_recv, mut client_send) = client_tunnel.split();
        client_send
            .send(ZCPacket::new_with_payload(
                b"MP_SQM_PLAN.md S2.6 generation-bump probe",
            ))
            .await
            .unwrap();
        let server_tunnel = accept.await.unwrap();
        let client_handle = client_tunnel
            .mp_session_handle()
            .expect("standalone connector must surface its MpSessionHandle");
        let client_congestion_control = client_tunnel
            .mp_congestion_control()
            .expect("standalone connector must surface its congestion-control profile");

        let manager = MpSessionManager::new(test_egress_quality_manager());
        manager.register_standalone_session(99, client_handle.clone(), client_congestion_control, false).await;
        assert!(!client_handle.is_closed(), "sanity: session must start open");

        // No generation bump: the session must survive.
        let unbumped = gen_default_mp_config();
        manager.set_config(unbumped.clone()).await.unwrap();
        assert!(!client_handle.is_closed(), "a config change with no generation bump must not touch it");

        let mut bumped = unbumped;
        bumped.session_generation += 1;
        manager.set_config(bumped).await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !client_handle.is_closed() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a session_generation bump must close the real standalone handle");
        assert!(
            !manager
                .runtime_snapshots()
                .await
                .unwrap()
                .iter()
                .any(|snapshot| snapshot.peer_id == 99),
            "the entry must be gone immediately, not linger reporting a dead handle"
        );

        drop(_client_recv);
        drop(client_send);
        drop(client_tunnel);
        drop(server_tunnel);
    }

    /// MP_SQM_PLAN.md S2.6, gray-box: `mp.packet_scheduler` must
    /// switch live on a real MP-managed session's real TQUIC connection --
    /// `set_config`'s existing (pre-S2.6) scheduler-push loop already calls
    /// `handle.set_scheduler`, which only succeeds against a live
    /// connection, so `set_config` returning `Ok` here is itself the proof
    /// the switch landed. No `session_generation` bump is involved, and
    /// `reconnect_required` must stay `false` throughout, since
    /// `congestion_control` never changes in this test.
    #[tokio::test(flavor = "multi_thread")]
    async fn set_config_switches_packet_scheduler_live_without_reconnect() {
        let url: url::Url = "mpquic://127.0.0.1:41079".parse().unwrap();
        let mut listener = MpQuicTunnelListener::new(url.clone());
        listener.listen().await.unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let mut connector = MpQuicTunnelConnector::new(url);
        let client_tunnel = connector.connect().await.unwrap();
        let (_client_recv, mut client_send) = client_tunnel.split();
        client_send
            .send(ZCPacket::new_with_payload(
                b"MP_SQM_PLAN.md S2.6 packet_scheduler probe",
            ))
            .await
            .unwrap();
        let server_tunnel = accept.await.unwrap();
        let client_handle = client_tunnel
            .mp_session_handle()
            .expect("connector must surface its MpSessionHandle");

        let manager = MpSessionManager::new(test_egress_quality_manager());
        manager.sessions.insert(
            99,
            Arc::new(Mutex::new(Some(Session {
                handle: client_handle.clone(),
                congestion_control: CongestionControlProfile::EngineDefault,
                is_server: false,
            }))),
        );

        let mut config = gen_default_mp_config();
        config.enabled = true;
        assert_eq!(config.packet_scheduler, "sqm-weighted", "sanity: default differs from this test's target");
        config.packet_scheduler = "min-rtt".to_string();

        manager
            .set_config(config)
            .await
            .expect("switching packet_scheduler on a live session must succeed");

        let snapshots = manager.runtime_snapshots().await.unwrap();
        let entry = snapshots
            .iter()
            .find(|snapshot| snapshot.peer_id == 99)
            .expect("MP-managed session must appear in runtime_snapshots()");
        assert!(
            !entry.reconnect_required,
            "a packet_scheduler-only change must never require reconnect"
        );

        drop(_client_recv);
        drop(client_send);
        drop(client_tunnel);
        drop(server_tunnel);
    }

    /// MP_SQM_PLAN.md S2.4 review (second pass): `mpquic.rs`'s
    /// `path_telemetry_from_stats` used to read `tquic::PathStats::
    /// scheduler_target_rate` (bytes/sec) straight into `MpPathTelemetry::
    /// scheduler_target_rate_bps` without the bytes->bits conversion every
    /// other `_bps` field gets, so both the GUI's per-path target rate and
    /// `MpPathRuntimeSnapshot::target_rate_bps`'s telemetry fallback
    /// silently reported 1/8 of the real value. Drives a real loopback
    /// TQUIC path through the actual `set_path_target_rate` call (via
    /// `MpSessionHandle::set_path_targets`, the same command
    /// `mp_session.rs`'s control tick issues) rather than asserting on
    /// `path_telemetry_from_stats` in isolation, so a regression at either
    /// the write side or the read side of that boundary would fail this.
    #[tokio::test(flavor = "multi_thread")]
    async fn standalone_mpquic_session_reports_a_real_target_rate_in_bits_per_sec() {
        let url: url::Url = "mpquic://127.0.0.1:41078".parse().unwrap();
        let mut listener = MpQuicTunnelListener::new(url.clone());
        listener.listen().await.unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let mut connector = MpQuicTunnelConnector::new(url);
        let client_tunnel = connector.connect().await.unwrap();
        let (_client_recv, mut client_send) = client_tunnel.split();
        client_send
            .send(ZCPacket::new_with_payload(
                b"MP_SQM_PLAN.md S2.4 review: target-rate telemetry unit probe",
            ))
            .await
            .unwrap();
        let server_tunnel = accept.await.unwrap();

        let client_handle = client_tunnel
            .mp_session_handle()
            .expect("standalone connector must surface its MpSessionHandle");

        // The connector binds an ephemeral local port, so the real
        // (local_addr, remote_addr) pair TQUIC negotiated has to be
        // discovered from telemetry rather than hardcoded.
        let telemetry = client_handle.path_telemetry().await.unwrap();
        let path = telemetry
            .first()
            .expect("a connected loopback pair must report a path");
        let target_bits_per_sec = 16_000_000u64;
        client_handle
            .set_path_targets(vec![MpPathTarget {
                local_addr: path.local_addr,
                remote_addr: path.remote_addr,
                rate: Some(target_bits_per_sec),
                standby: false,
            }])
            .await
            .unwrap();

        // `SetPathTargets` is applied by the driver asynchronously; poll
        // telemetry (bounded, not a fixed sleep-and-hope) until it reflects
        // the new target.
        let telemetry = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let telemetry = client_handle.path_telemetry().await.unwrap();
                if telemetry
                    .first()
                    .and_then(|path| path.scheduler_target_rate_bps)
                    .is_some()
                {
                    return telemetry;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("driver must apply the target rate");
        let observed_bps = telemetry[0].scheduler_target_rate_bps.unwrap();
        // A units regression (bytes/sec reported as bits/sec) would read
        // back ~2_000_000 (8x low); this tolerance only absorbs the
        // bits/8-then-*8 rounding at the two conversion boundaries.
        assert!(
            observed_bps.abs_diff(target_bits_per_sec) <= 8,
            "expected ~{target_bits_per_sec} bits/sec, got {observed_bps}"
        );

        let manager = MpSessionManager::new(test_egress_quality_manager());
        manager.register_standalone_session(100, client_handle.clone(), "engine-default", false).await;
        let snapshots = manager.runtime_snapshots().await.unwrap();
        let entry = snapshots
            .iter()
            .find(|snapshot| snapshot.peer_id == 100)
            .expect("standalone session must appear in runtime_snapshots()");
        let path_status = entry
            .paths
            .first()
            .expect("a connected loopback pair must report a path");
        assert_eq!(
            path_status.target_rate_bps,
            Some(observed_bps),
            "MpPathRuntimeSnapshot::target_rate_bps must match the telemetry it was read from"
        );

        drop(_client_recv);
        drop(client_send);
        drop(client_tunnel);
        drop(server_tunnel);
        client_handle.shutdown();
    }

    #[tokio::test]
    async fn control_tick_prunes_failed_and_stale_candidates_without_a_session() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let now = Instant::now();
        let (failed_path, _) = channel_path_pair(
            "127.0.0.1:40961".parse().unwrap(),
            "127.0.0.2:40962".parse().unwrap(),
        );
        let failed = path_spec(failed_path, "127.0.0.2:40962".parse().unwrap());
        let failed_key = failed.key;
        let (stale_path, _) = channel_path_pair(
            "127.0.0.1:40963".parse().unwrap(),
            "127.0.0.2:40964".parse().unwrap(),
        );
        let stale = path_spec(stale_path, "127.0.0.2:40964".parse().unwrap());
        let stale_key = stale.key;
        let mut candidates = MpCandidateTable::default();
        candidates.upsert(failed, now);
        candidates.begin_validation(&failed_key);
        candidates.record_validation(&failed_key, false);
        candidates.upsert(
            stale,
            now - PATH_VALIDATION_TIMEOUT - std::time::Duration::from_millis(1),
        );
        candidates.begin_validation(&stale_key);
        manager
            .candidates
            .insert(7, Arc::new(Mutex::new(candidates)));

        let pruned = manager.prune_failed_and_stale_candidates().await;

        assert_eq!(pruned, 2);
        assert_eq!(manager.tracked_candidate_count(7).await, 0);
    }

    #[tokio::test]
    async fn applying_config_retires_paths_for_disabled_providers() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let now = Instant::now();
        let (relay_path, _) = channel_path_pair(
            "127.0.0.1:40971".parse().unwrap(),
            "127.0.0.2:40972".parse().unwrap(),
        );
        let mut relay = path_spec(relay_path, "127.0.0.2:40972".parse().unwrap());
        relay.carrier_kind = CarrierKind::RelayNextHop;
        let relay_key = relay.key;
        let (direct_path, _) = channel_path_pair(
            "127.0.0.1:40973".parse().unwrap(),
            "127.0.0.2:40974".parse().unwrap(),
        );
        let mut direct = path_spec(direct_path, "127.0.0.2:40974".parse().unwrap());
        direct.carrier_kind = CarrierKind::UdpDirect;
        let direct_key = direct.key;
        let mut candidates = MpCandidateTable::default();
        candidates.upsert(relay, now);
        candidates.set_state(&relay_key, PathLifecycleState::AVAILABLE);
        candidates.upsert(direct, now);
        candidates.set_state(&direct_key, PathLifecycleState::AVAILABLE);
        manager
            .candidates
            .insert(7, Arc::new(Mutex::new(candidates)));

        let mut config = gen_default_mp_config();
        config.enabled = true;
        config.providers = vec!["udp-direct".into()];
        manager.set_config(config).await.unwrap();

        assert_eq!(
            manager.candidate_state(7, &relay_key).await,
            Some(PathLifecycleState::Dead),
            "a disabled provider must withdraw its previously active carrier"
        );
        assert_eq!(
            manager.candidate_state(7, &direct_key).await,
            Some(PathLifecycleState::AVAILABLE),
            "an enabled provider must keep its carrier"
        );
    }

    #[tokio::test]
    async fn applying_config_reclassifies_existing_path_resource_groups() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let remote: SocketAddr = "127.0.0.2:40982".parse().unwrap();
        let (path, _) = channel_path_pair("127.0.0.1:40981".parse().unwrap(), remote);
        let carrier: Arc<dyn MpDatagramPath> = path;
        let spec =
            MpPathSpec::with_egress_device(carrier, remote, "Ethernet", CarrierKind::UdpDirect)
                .unwrap();
        let key = spec.key;
        let mut candidates = MpCandidateTable::default();
        candidates.upsert(spec, Instant::now());
        candidates.set_state(&key, PathLifecycleState::AVAILABLE);
        manager
            .candidates
            .insert(7, Arc::new(Mutex::new(candidates)));

        let mut config = gen_default_mp_config();
        config.enabled = true;
        config.resource_groups = vec![crate::proto::common::MpResourceGroupConfig {
            name: "shared-wan".into(),
            egress_devices: vec!["Ethernet".into()],
            remote_endpoints: vec![remote.ip().to_string()],
            capacity_bps: 100_000_000,
        }];
        manager.set_config(config.clone()).await.unwrap();
        {
            let slot = manager.candidates.get(&7).unwrap().clone();
            let candidates = slot.lock().await;
            let candidate = candidates.get(&key).unwrap();
            assert_eq!(
                candidate.spec.local_resource,
                crate::connector::mp_path::ResourceGroupId::shared_bottleneck("shared-wan")
            );
            assert_eq!(
                candidate.spec.remote_resource,
                crate::connector::mp_path::ResourceGroupId::shared_bottleneck("shared-wan")
            );
        }

        config.resource_groups.clear();
        manager.set_config(config).await.unwrap();
        let slot = manager.candidates.get(&7).unwrap().clone();
        let candidates = slot.lock().await;
        let candidate = candidates.get(&key).unwrap();
        assert_eq!(
            candidate.spec.local_resource,
            crate::connector::mp_path::ResourceGroupId::egress_device("Ethernet").unwrap()
        );
        assert_eq!(
            candidate.spec.remote_resource,
            crate::connector::mp_path::ResourceGroupId::remote_endpoint(remote)
        );
    }

    #[tokio::test]
    async fn disabling_mp_clears_active_paths_and_runtime_snapshots() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let remote: SocketAddr = "127.0.0.2:40992".parse().unwrap();
        let (path, _) = channel_path_pair("127.0.0.1:40991".parse().unwrap(), remote);
        let carrier: Arc<dyn MpDatagramPath> = path;
        let spec =
            MpPathSpec::with_egress_device(carrier, remote, "Ethernet", CarrierKind::UdpDirect)
                .unwrap();
        let key = spec.key;
        let mut candidates = MpCandidateTable::default();
        candidates.upsert(spec, Instant::now());
        candidates.set_state(&key, PathLifecycleState::AVAILABLE);
        manager
            .candidates
            .insert(7, Arc::new(Mutex::new(candidates)));

        let mut enabled = gen_default_mp_config();
        enabled.enabled = true;
        manager.set_config(enabled).await.unwrap();
        assert_eq!(manager.runtime_snapshots().await.unwrap().len(), 1);

        let mut disabled = gen_default_mp_config();
        disabled.enabled = false;
        manager.set_config(disabled).await.unwrap();

        assert!(manager.candidates.is_empty());
        assert!(manager.optimization_snapshots.is_empty());
        assert!(manager.runtime_snapshots().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn control_tick_skips_an_unready_session_slot() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let mut config = gen_default_mp_config();
        config.enabled = true;
        manager.set_config(config).await.unwrap();
        manager.sessions.insert(7, Arc::new(Mutex::new(None)));

        let tick = manager.run_control_tick().await;

        assert!(
            tick.is_ok(),
            "a pending punch must not abort control ticks for every peer: {tick:?}"
        );
        assert!(tick.unwrap().snapshots.is_empty());
    }

    /// A slot left empty by a failed handshake is reaped once it stayed
    /// empty for `EMPTY_SESSION_GRACE`, never while a handshake runs.
    #[tokio::test]
    async fn an_empty_session_slot_is_reaped_after_the_grace_period() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        manager.sessions.insert(7, Arc::new(Mutex::new(None)));
        manager
            .candidates
            .insert(7, Arc::new(Mutex::new(MpCandidateTable::default())));
        let long_ago = Instant::now() - EMPTY_SESSION_GRACE - std::time::Duration::from_secs(1);

        assert_eq!(manager.reap_closed_sessions().await, 0, "just emptied");
        assert!(manager.sessions.contains_key(&7));

        let establishment = manager.establishing.entry(7).or_default().clone();
        manager.empty_since.insert(7, long_ago);
        {
            let _handshake = establishment.begin(false, Arc::new(tokio::sync::Notify::new()));
            assert_eq!(manager.reap_closed_sessions().await, 0, "a handshake is running");
        }
        assert!(manager.sessions.contains_key(&7));

        manager.empty_since.insert(7, long_ago);
        assert_eq!(manager.reap_closed_sessions().await, 1);
        assert!(!manager.sessions.contains_key(&7));
        assert!(!manager.candidates.contains_key(&7));
    }

    #[test]
    fn quic_config_uses_the_configured_establishment_deadline() {
        let mut config = gen_default_mp_config();
        config.establishment_timeout_ms = 27_000;

        let runtime = MpSessionManager::quic_config(&config).unwrap();

        assert_eq!(
            runtime.establishment_timeout,
            std::time::Duration::from_millis(27_000),
            "the new-session ready wait must use MpConfig instead of a hidden constant"
        );
    }

    #[tokio::test]
    async fn path_down_event_marks_candidate_dead() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let (path, _) = channel_path_pair(
            "127.0.0.1:40951".parse().unwrap(),
            "127.0.0.2:40952".parse().unwrap(),
        );
        let spec = path_spec(path, "127.0.0.2:40952".parse().unwrap());
        let key = spec.key;
        let mut candidates = MpCandidateTable::default();
        candidates.upsert(spec, Instant::now());
        candidates.set_state(&key, PathLifecycleState::AVAILABLE);
        manager
            .candidates
            .insert(7, Arc::new(Mutex::new(candidates)));

        let changed = manager
            .apply_path_events(7, vec![MpPathEvent::Down(key)])
            .await;

        assert!(changed);
        assert_eq!(
            manager.candidate_state(7, &key).await,
            Some(PathLifecycleState::Dead)
        );
    }

    fn wan_summary(live: usize, unobserved: usize, wans: &[&str]) -> PunchWanSummary {
        PunchWanSummary {
            live,
            unobserved,
            wans: wans.iter().map(|ip| ip.parse().unwrap()).collect(),
            held_until: None,
        }
    }

    #[test]
    fn mp_punch_runs_once_when_the_peer_never_reports_an_address() {
        let mut progress = MpPunchProgress::default();
        assert_eq!(next_mp_punch_slot(&wan_summary(0, 0, &[]), &mut progress, 4), Some(0));
        for _ in 0..5 {
            assert_eq!(
                next_mp_punch_slot(&wan_summary(1, 1, &[]), &mut progress, 4),
                None,
                "without address discovery the single punch must not be repeated"
            );
        }
    }

    #[test]
    fn mp_punch_default_target_keeps_one_carrier() {
        let mut progress = MpPunchProgress::default();
        assert_eq!(
            next_mp_punch_slot(&wan_summary(1, 0, &["198.51.100.1"]), &mut progress, 1),
            None
        );
    }

    #[test]
    fn mp_punch_continues_until_target_distinct_wans() {
        let mut progress = MpPunchProgress::default();
        assert_eq!(next_mp_punch_slot(&wan_summary(0, 0, &[]), &mut progress, 3), Some(0));
        assert_eq!(
            next_mp_punch_slot(&wan_summary(1, 0, &["198.51.100.1"]), &mut progress, 3),
            Some(1)
        );
        assert_eq!(
            next_mp_punch_slot(
                &wan_summary(2, 0, &["198.51.100.1", "203.0.113.1"]),
                &mut progress,
                3
            ),
            Some(2)
        );
        assert_eq!(
            next_mp_punch_slot(
                &wan_summary(3, 0, &["198.51.100.1", "203.0.113.1", "192.0.2.1"]),
                &mut progress,
                3
            ),
            None,
            "target reached"
        );
    }

    #[test]
    fn mp_punch_stops_after_two_attempts_without_a_new_wan() {
        let mut progress = MpPunchProgress::default();
        let one = ["198.51.100.1"];
        assert_eq!(next_mp_punch_slot(&wan_summary(1, 0, &one), &mut progress, 8), Some(1));
        // Attempt 2 lands on the same WAN.
        assert_eq!(next_mp_punch_slot(&wan_summary(2, 0, &one), &mut progress, 8), Some(2));
        // Dedupe retires the duplicate; no progress change.
        assert_eq!(next_mp_punch_slot(&wan_summary(1, 0, &one), &mut progress, 8), Some(1));
        // Attempt 3 lands on the same WAN again: second stale attempt.
        assert_eq!(next_mp_punch_slot(&wan_summary(2, 0, &one), &mut progress, 8), None);
        assert_eq!(next_mp_punch_slot(&wan_summary(1, 0, &one), &mut progress, 8), None);
    }

    #[test]
    fn mp_punch_resumes_a_while_after_stopping_without_a_new_wan() {
        let start = std::time::Instant::now();
        let mut progress = MpPunchProgress::default();
        let one = ["198.51.100.1"];
        let next = |live, progress: &mut MpPunchProgress, at| {
            next_mp_punch_slot_at(&wan_summary(live, 0, &one), progress, 2, at)
        };
        assert_eq!(next(1, &mut progress, start), Some(1));
        assert_eq!(next(2, &mut progress, start), Some(2));
        assert_eq!(next(1, &mut progress, start), Some(1));
        assert_eq!(next(2, &mut progress, start), None, "second attempt without a new WAN");
        let later = start + MP_PUNCH_STALE_RETRY - std::time::Duration::from_secs(1);
        assert_eq!(next(1, &mut progress, later), None);
        assert_eq!(
            next(1, &mut progress, start + MP_PUNCH_STALE_RETRY),
            Some(1),
            "the router may pick the other WAN next time"
        );
        assert_eq!(next(2, &mut progress, start + MP_PUNCH_STALE_RETRY), Some(2));
    }

    #[test]
    fn mp_punch_retries_when_a_wan_is_lost_and_resets_without_carriers() {
        let mut progress = MpPunchProgress::default();
        let two = ["198.51.100.1", "203.0.113.1"];
        assert_eq!(next_mp_punch_slot(&wan_summary(1, 0, &two[..1]), &mut progress, 2), Some(1));
        assert_eq!(next_mp_punch_slot(&wan_summary(2, 0, &two), &mut progress, 2), None);
        assert_eq!(
            next_mp_punch_slot(&wan_summary(1, 0, &two[..1]), &mut progress, 2),
            Some(1),
            "losing a WAN re-arms punching"
        );
        assert_eq!(next_mp_punch_slot(&wan_summary(0, 0, &[]), &mut progress, 2), Some(0));
        assert_eq!(progress, MpPunchProgress::default());
    }

    #[test]
    fn faketcp_upgrade_failures_switch_auto_to_plain_tcp_for_a_while() {
        let start = std::time::Instant::now();
        let mut record = FakeTcpUpgradeRecord::default();
        record.record(Err("timed out".into()), start);
        assert!(!record.plain_tcp_fallback(start), "one failure is not enough");
        record.record(Err("timed out again".into()), start);
        assert!(record.plain_tcp_fallback(start));
        assert!(record.plain_tcp_fallback(start + FAKETCP_FALLBACK_HOLD / 2));
        assert!(
            !record.plain_tcp_fallback(start + FAKETCP_FALLBACK_HOLD),
            "FakeTCP is tried again after the hold"
        );
        assert_eq!(
            (record.failures, record.last_error.as_str()),
            (2, "timed out again")
        );

        record.record(Ok(()), start);
        assert!(!record.plain_tcp_fallback(start));
        assert_eq!(record.failures, 2, "the total keeps counting");
    }

    #[tokio::test]
    async fn faketcp_upgrade_record_shows_up_in_runtime_snapshots() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        manager.record_faketcp_upgrade(9, Err("no route".into()));
        manager.record_faketcp_upgrade(9, Err("no route".into()));
        assert!(manager.faketcp_plain_tcp_fallback(9));
        assert!(!manager.faketcp_plain_tcp_fallback(10));

        let snapshots = manager.runtime_snapshots().await.unwrap();
        let record = snapshots
            .iter()
            .find(|snapshot| snapshot.peer_id == 9)
            .and_then(|snapshot| snapshot.faketcp_upgrade.clone())
            .expect("a peer with only failed upgrades is still reported");
        assert_eq!(record.consecutive_failures, 2);
    }

    #[test]
    fn mp_punch_keeps_the_slot_of_a_running_attempt_until_it_finishes() {
        let mut progress = MpPunchProgress::default();
        assert_eq!(next_mp_punch_slot(&wan_summary(0, 0, &[]), &mut progress, 1), Some(0));
        progress.start(0);
        // Its carrier is live but not yet reported: without the running task
        // this would be `None`, and then `Some(1)` once reported.
        assert_eq!(next_mp_punch_slot(&wan_summary(1, 1, &[]), &mut progress, 1), Some(0));
        assert_eq!(
            next_mp_punch_slot(&wan_summary(1, 0, &["198.51.100.1"]), &mut progress, 2),
            Some(0)
        );
        progress.finish(1);
        assert_eq!(
            next_mp_punch_slot(&wan_summary(1, 0, &["198.51.100.1"]), &mut progress, 2),
            Some(0),
            "finishing another slot must not release this one"
        );
        progress.finish(0);
        assert_eq!(
            next_mp_punch_slot(&wan_summary(1, 0, &["198.51.100.1"]), &mut progress, 1),
            None
        );
    }

    #[tokio::test]
    async fn punch_wan_summary_groups_live_carriers_by_peer_observed_ip() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let (a, _a_remote) = real_udp_legacy_spec().await;
        let (b, _b_remote) = real_udp_legacy_spec().await;
        let (c, _c_remote) = real_udp_legacy_spec().await;
        let (d, _d_remote) = real_udp_legacy_spec().await;
        let (a_key, b_key, c_key, d_key) = (a.key, b.key, c.key, d.key);
        let mut candidates = MpCandidateTable::default();
        for spec in [a, b, c, d] {
            candidates.upsert(spec, Instant::now());
        }
        for key in [&a_key, &b_key, &c_key, &d_key] {
            candidates.set_state(key, PathLifecycleState::AVAILABLE);
        }
        let wan_1: SocketAddr = "198.51.100.1:40001".parse().unwrap();
        let wan_1_other_port: SocketAddr = "198.51.100.1:40777".parse().unwrap();
        let wan_2: SocketAddr = "203.0.113.9:50001".parse().unwrap();
        candidates.get_mut(&a_key).unwrap().measurements.observed_local_addr = Some(wan_1);
        candidates.get_mut(&b_key).unwrap().measurements.observed_local_addr =
            Some(wan_1_other_port);
        candidates.get_mut(&c_key).unwrap().measurements.observed_local_addr = Some(wan_2);
        manager
            .candidates
            .insert(7, Arc::new(Mutex::new(candidates)));

        let summary = manager.punch_wan_summary(7, CarrierKind::UdpPunch).await;
        assert_eq!(summary.live, 4);
        assert_eq!(summary.unobserved, 1, "d has no peer report yet");
        assert_eq!(
            summary.wans.into_iter().collect::<Vec<_>>(),
            vec![wan_1.ip(), wan_2.ip()],
            "two mappings through the same WAN count once"
        );

        manager
            .candidates
            .get(&7)
            .unwrap()
            .lock()
            .await
            .set_state(&c_key, PathLifecycleState::Dead);
        let summary = manager.punch_wan_summary(7, CarrierKind::UdpPunch).await;
        assert_eq!(summary.live, 3);
        assert_eq!(summary.wans.len(), 1, "a dead carrier no longer counts");
        assert_eq!(
            manager.punch_wan_summary(8, CarrierKind::UdpPunch).await,
            PunchWanSummary::default()
        );
    }

    /// S-I26: whether another punch is due looks at the direct paths to the
    /// peer whatever their carrier: a live UDP path already reaches the peer
    /// through its WAN, so FakeTCP does not punch for that WAN again. A relay
    /// path reaches no WAN directly and is not counted.
    #[tokio::test]
    async fn punch_wan_summary_counts_direct_paths_of_every_carrier() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let (udp, _udp_remote) = real_udp_legacy_spec().await;
        let (tcp, _tcp_remote) = real_udp_legacy_spec().await;
        let (relay, _relay_remote) = real_udp_legacy_spec().await;
        let udp_key = udp.key;
        let relay = MpPathSpec {
            carrier_kind: CarrierKind::RelayNextHop,
            ..relay
        };
        let relay_key = relay.key;
        let tcp = MpPathSpec {
            carrier_kind: CarrierKind::FakeTcpPunch,
            ..tcp
        };
        let tcp_key = tcp.key;
        let udp = MpPathSpec {
            carrier_kind: CarrierKind::UdpPunch,
            ..udp
        };
        let mut candidates = MpCandidateTable::default();
        for spec in [udp, tcp, relay] {
            candidates.upsert(spec, Instant::now());
        }
        for key in [&udp_key, &tcp_key, &relay_key] {
            candidates.set_state(key, PathLifecycleState::AVAILABLE);
        }
        let wan: SocketAddr = "198.51.100.1:40001".parse().unwrap();
        candidates.get_mut(&udp_key).unwrap().measurements.observed_local_addr = Some(wan);
        candidates.get_mut(&tcp_key).unwrap().measurements.observed_local_addr = Some(wan);
        manager
            .candidates
            .insert(7, Arc::new(Mutex::new(candidates)));

        let summary = manager.punch_wan_summary(7, CarrierKind::FakeTcpPunch).await;
        assert_eq!(summary.live, 2, "UDP and FakeTCP count, the relay does not");
        assert_eq!(summary.wans.len(), 1);
        let mut progress = MpPunchProgress::default();
        assert_eq!(
            next_mp_punch_slot(&summary, &mut progress, 1),
            None,
            "the one WAN already has a direct path"
        );
    }

    /// S-I26: punched paths validated and then dropped with nothing received
    /// hold the next punches off for longer each time; a path the peer does
    /// answer on starts the count over.
    #[tokio::test]
    async fn silent_punch_drops_back_off_exponentially_until_the_peer_answers() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let mut keys = Vec::new();
        let mut candidates = MpCandidateTable::default();
        for _ in 0..4 {
            let (spec, _remote) = real_udp_legacy_spec().await;
            let spec = MpPathSpec {
                carrier_kind: CarrierKind::FakeTcpPunch,
                ..spec
            };
            keys.push(spec.key);
            candidates.upsert(spec, Instant::now());
        }
        for key in &keys {
            candidates.set_state(key, PathLifecycleState::AVAILABLE);
            candidates.record_received(key, 500);
        }
        // the third path hears the peer after validation
        candidates.record_received(&keys[2], 900);
        let wan: SocketAddr = "198.51.100.1:40001".parse().unwrap();
        for key in &keys {
            candidates.get_mut(key).unwrap().measurements.observed_local_addr = Some(wan);
        }
        manager
            .candidates
            .insert(9, Arc::new(Mutex::new(candidates)));
        let held = |manager: &MpSessionManager| {
            manager
                .punch_drops
                .get(&(9, CarrierKind::FakeTcpPunch))
                .map(|drop| drop.held_until)
        };
        let down = |key: PathKey| vec![MpPathEvent::Down(key)];
        let t0 = Instant::now();

        manager.apply_path_events(9, down(keys[0])).await;
        let first = held(&manager).expect("a silent drop holds punching");
        assert!(first >= t0 + std::time::Duration::from_millis(4_900));
        assert!(first <= Instant::now() + std::time::Duration::from_millis(5_100));

        manager.apply_path_events(9, down(keys[1])).await;
        let second = held(&manager).unwrap();
        assert!(
            second >= t0 + std::time::Duration::from_millis(9_900),
            "the second consecutive drop waits twice as long"
        );

        let summary = manager.punch_wan_summary(9, CarrierKind::FakeTcpPunch).await;
        assert_eq!(summary.held_until, Some(second));
        let mut progress = MpPunchProgress::default();
        assert_eq!(next_mp_punch_slot(&summary, &mut progress, 2), None);
        assert_eq!(
            next_mp_punch_slot_at(&summary, &mut progress, 2, second),
            Some(2),
            "punching resumes when the hold ends"
        );

        // a path the peer answers on is not a silent drop and ends the streak
        {
            let slot = manager.candidates.get(&9).unwrap().clone();
            let mut candidates = slot.lock().await;
            candidates.record_received(&keys[2], 1_200);
            assert!(candidates.get(&keys[2]).unwrap().heard_since_validated());
        }
        manager.apply_path_events(9, down(keys[2])).await;
        assert_eq!(held(&manager), Some(second), "an answered path adds no hold");
    }

    /// MP_SQM_PLAN.md S2.14 dedupe: one punched path per (kind, WAN, remote
    /// IP) survives -- the lowest sRTT among the unpaused ones. A path not yet
    /// reported by the peer, a different WAN or a non-punched carrier is
    /// never a duplicate.
    #[tokio::test]
    async fn duplicate_wan_paths_keeps_one_usable_path_per_wan() {
        let (a, _a_remote) = real_udp_legacy_spec().await;
        let (b, _b_remote) = real_udp_legacy_spec().await;
        let (c, _c_remote) = real_udp_legacy_spec().await;
        let (d, _d_remote) = real_udp_legacy_spec().await;
        let (e, _e_remote) = real_udp_legacy_spec().await;
        let (a_key, b_key, c_key, d_key) = (a.key, b.key, c.key, d.key);
        let mut candidates = MpCandidateTable::default();
        for spec in [a, b, c, d] {
            candidates.upsert(spec, Instant::now());
        }
        let manual = MpPathSpec {
            carrier_kind: CarrierKind::Manual,
            ..e
        };
        let manual_key = manual.key;
        candidates.upsert(manual, Instant::now());
        let wan_1: SocketAddr = "198.51.100.1:40001".parse().unwrap();
        let wan_2: SocketAddr = "203.0.113.9:50001".parse().unwrap();
        for (key, observed, srtt) in [
            (&a_key, Some(wan_1), 30_000),
            (&b_key, Some(wan_1), 10_000),
            (&c_key, Some(wan_2), 5_000),
            (&d_key, None, 1_000),
            (&manual_key, Some(wan_1), 1_000),
        ] {
            candidates.set_state(key, PathLifecycleState::AVAILABLE);
            let measurements = &mut candidates.get_mut(key).unwrap().measurements;
            measurements.observed_local_addr = observed;
            measurements.propagation_rtt_micros = srtt;
        }

        assert_eq!(duplicate_wan_paths(&candidates, &[]), vec![a_key]);

        // The lower-sRTT path is paused by the user: keep the usable one.
        let pause_b = crate::proto::common::MpPathPolicy {
            match_remote_endpoint: b_key.remote_addr.to_string(),
            ..wildcard_policy("pause")
        };
        assert_eq!(
            duplicate_wan_paths(&candidates, std::slice::from_ref(&pause_b)),
            vec![b_key]
        );

        // Everything paused: still one survivor per WAN, by sRTT.
        assert_eq!(
            duplicate_wan_paths(&candidates, &[wildcard_policy("pause")]),
            vec![a_key]
        );

        // The lower-sRTT path has only just joined (the other end's
        // simultaneous punch) and is still validating: the working one stays.
        candidates.set_state(&b_key, PathLifecycleState::Validating);
        assert_eq!(duplicate_wan_paths(&candidates, &[]), vec![b_key]);
    }

    /// Both ends measure sRTT themselves, so only the lower peer id of the
    /// pair retires WAN duplicates; otherwise each end could keep a different
    /// one and the session would be left without a shared path.
    #[tokio::test]
    async fn only_the_lower_peer_id_retires_wan_duplicates() {
        let manager =
            MpSessionManager::new(test_egress_quality_manager()).with_local_peer_id(5);
        let wan: SocketAddr = "198.51.100.1:40001".parse().unwrap();
        for peer_id in [3, 9] {
            let (a, _a_remote) = real_udp_legacy_spec().await;
            let (b, _b_remote) = real_udp_legacy_spec().await;
            let (a_key, b_key) = (a.key, b.key);
            let mut candidates = MpCandidateTable::default();
            candidates.upsert(a, Instant::now());
            candidates.upsert(b, Instant::now());
            for (key, srtt) in [(&a_key, 30_000), (&b_key, 10_000)] {
                candidates.set_state(key, PathLifecycleState::AVAILABLE);
                let measurements = &mut candidates.get_mut(key).unwrap().measurements;
                measurements.observed_local_addr = Some(wan);
                measurements.propagation_rtt_micros = srtt;
            }
            manager
                .candidates
                .insert(peer_id, Arc::new(Mutex::new(candidates)));
        }

        assert_eq!(manager.retire_duplicate_wan_paths(&[]).await.unwrap(), 1);
        let untouched = manager.candidates.get(&3).unwrap().clone();
        assert!(
            untouched
                .lock()
                .await
                .iter()
                .all(|(_, candidate)| candidate.state == PathLifecycleState::AVAILABLE),
            "the higher peer id leaves the choice to the lower one"
        );
    }

    #[tokio::test]
    async fn egress_change_retires_only_removed_or_stale_generations() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let wan_a_id = crate::common::egress_inventory::EgressStableId::Linux {
            netns_inode: 1,
            ifindex: 21,
        };
        let wan_b_id = crate::common::egress_inventory::EgressStableId::Linux {
            netns_inode: 1,
            ifindex: 22,
        };
        let (wan_a_old, _wan_a_old_remote) =
            real_udp_egress_spec(wan_a_id.clone(), "wan-a", 1).await;
        let (wan_a_current, _wan_a_current_remote) =
            real_udp_egress_spec(wan_a_id.clone(), "wan-a-renamed", 2).await;
        let (wan_b, _wan_b_remote) = real_udp_egress_spec(wan_b_id.clone(), "wan-b", 1).await;
        let (legacy, _legacy_remote) = real_udp_legacy_spec().await;
        let wan_a_old_key = wan_a_old.key;
        let wan_a_current_key = wan_a_current.key;
        let wan_b_key = wan_b.key;
        let legacy_key = legacy.key;
        let mut candidates = MpCandidateTable::default();
        for path in [wan_a_old, wan_a_current, wan_b, legacy] {
            let key = path.key;
            candidates.upsert(path, Instant::now());
            candidates.set_state(&key, PathLifecycleState::AVAILABLE);
        }
        manager
            .candidates
            .insert(7, Arc::new(Mutex::new(candidates)));

        let current_wan_a = inventory_interface(
            wan_a_id.clone(),
            "wan-a-renamed",
            2,
            "127.0.0.1".parse().unwrap(),
        );
        let snapshot = crate::common::egress_inventory::EgressInventorySnapshot {
            revision: 2,
            observed_at_unix_ms: 2,
            interfaces: std::collections::BTreeMap::from([(wan_a_id.clone(), current_wan_a)]),
        };
        assert_eq!(
            manager.reconcile_egress_bindings(&snapshot).await.unwrap(),
            2
        );
        assert_eq!(
            manager.candidate_state(7, &wan_a_old_key).await,
            Some(PathLifecycleState::Dead)
        );
        assert_eq!(
            manager.candidate_state(7, &wan_a_current_key).await,
            Some(PathLifecycleState::AVAILABLE)
        );
        assert_eq!(
            manager.candidate_state(7, &wan_b_key).await,
            Some(PathLifecycleState::Dead)
        );
        assert_eq!(
            manager.candidate_state(7, &legacy_key).await,
            Some(PathLifecycleState::AVAILABLE),
            "legacy carriers without inventory ownership must remain untouched"
        );
        assert_eq!(
            manager.reconcile_egress_bindings(&snapshot).await.unwrap(),
            0,
            "reconciliation against the same snapshot must be idempotent"
        );
    }

    #[tokio::test]
    async fn direct_first_hop_disconnect_retires_only_its_relay_candidates() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let (via_first_hop, _) = channel_path_pair(
            "127.0.0.1:40971".parse().unwrap(),
            "127.0.0.2:40972".parse().unwrap(),
        );
        let (via_other_hop, _) = channel_path_pair(
            "127.0.0.1:40973".parse().unwrap(),
            "127.0.0.2:40974".parse().unwrap(),
        );
        let mut first = path_spec(via_first_hop, "127.0.0.2:40972".parse().unwrap());
        first.carrier_kind = CarrierKind::RelayNextHop;
        first.relay_metadata = Some(super::super::mp_path::RelayPathMetadata {
            first_hop_peer_id: 31,
            egress_first_hop_peer_id: 31,
            route_generation: 1,
        });
        let first_key = first.key;
        let mut other = path_spec(via_other_hop, "127.0.0.2:40974".parse().unwrap());
        other.carrier_kind = CarrierKind::RelayNextHop;
        other.relay_metadata = Some(super::super::mp_path::RelayPathMetadata {
            first_hop_peer_id: 32,
            egress_first_hop_peer_id: 32,
            route_generation: 1,
        });
        let other_key = other.key;
        let mut candidates = MpCandidateTable::default();
        candidates.upsert(first, Instant::now());
        candidates.upsert(other, Instant::now());
        candidates.set_state(&first_key, PathLifecycleState::AVAILABLE);
        candidates.set_state(&other_key, PathLifecycleState::AVAILABLE);
        manager
            .candidates
            .insert(7, Arc::new(Mutex::new(candidates)));

        assert!(manager.has_live_relay_egress(7, 31).await);
        assert!(manager.has_live_relay_egress(7, 32).await);

        assert!(manager
            .retire_path_by_addresses(
                7,
                "127.0.0.1:40971".parse().unwrap(),
                "127.0.0.2:40972".parse().unwrap()
            )
            .await
            .unwrap());
        assert_eq!(
            manager.candidate_state(7, &first_key).await,
            Some(PathLifecycleState::Dead)
        );
        assert_eq!(
            manager.candidate_state(7, &other_key).await,
            Some(PathLifecycleState::AVAILABLE)
        );
        assert!(!manager.has_live_relay_egress(7, 31).await);
        assert!(manager.has_live_relay_egress(7, 32).await);
    }

    /// The first hop of the session's only relay path goes down: the path is
    /// kept (QUIC decides whether the connection lives), not given up with the
    /// first hop's TCP connection.
    #[tokio::test]
    async fn first_hop_disconnect_keeps_the_relay_path_the_session_is_left_with() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let (only_path, _) = channel_path_pair(
            "127.0.0.1:40981".parse().unwrap(),
            "127.0.0.2:40982".parse().unwrap(),
        );
        let mut only = path_spec(only_path, "127.0.0.2:40982".parse().unwrap());
        only.carrier_kind = CarrierKind::RelayNextHop;
        only.relay_metadata = Some(super::super::mp_path::RelayPathMetadata {
            first_hop_peer_id: 31,
            egress_first_hop_peer_id: 31,
            route_generation: 1,
        });
        let only_key = only.key;
        let mut candidates = MpCandidateTable::default();
        candidates.upsert(only, Instant::now());
        candidates.set_state(&only_key, PathLifecycleState::AVAILABLE);
        manager
            .candidates
            .insert(7, Arc::new(Mutex::new(candidates)));
        manager.sessions.insert(
            7,
            Arc::new(Mutex::new(Some(Session {
                handle: MpSessionHandle::refusing_remove_path_for_test(),
                congestion_control: CongestionControlProfile::EngineDefault,
                is_server: false,
            }))),
        );

        let retired = manager
            .retire_path_by_addresses(
                7,
                "127.0.0.1:40981".parse().unwrap(),
                "127.0.0.2:40982".parse().unwrap(),
            )
            .await
            .unwrap();

        assert!(!retired, "the driver keeps the session's last path");
        assert_eq!(
            manager.candidate_state(7, &only_key).await,
            Some(PathLifecycleState::AVAILABLE),
            "the session's last path stays a live candidate"
        );
        assert!(manager.has_live_relay_egress(7, 31).await);
    }

    /// S-I4b: when the selected path dies, the remaining established path
    /// takes over at once. The dead path is no longer a candidate, so the
    /// switching threshold that protects an incumbent cannot hold it, and no
    /// confirmation rounds are involved (the old `pending_hard_failures`
    /// side channel is gone).
    #[test]
    fn a_dead_selected_path_is_replaced_at_once_by_the_remaining_hop() {
        let (path_h1, _) = channel_path_pair(
            "127.0.0.1:41901".parse().unwrap(),
            "127.0.0.1:41902".parse().unwrap(),
        );
        let (path_h2, _) = channel_path_pair(
            "127.0.0.1:41903".parse().unwrap(),
            "127.0.0.1:41904".parse().unwrap(),
        );
        let mut h1 = path_spec(path_h1, "127.0.0.1:41902".parse().unwrap());
        h1.carrier_kind = CarrierKind::RelayNextHop;
        h1.relay_metadata = Some(super::super::mp_path::RelayPathMetadata {
            first_hop_peer_id: 11,
            egress_first_hop_peer_id: 11,
            route_generation: 1,
        });
        let mut h2 = path_spec(path_h2, "127.0.0.1:41904".parse().unwrap());
        h2.carrier_kind = CarrierKind::RelayNextHop;
        h2.relay_metadata = Some(super::super::mp_path::RelayPathMetadata {
            first_hop_peer_id: 12,
            egress_first_hop_peer_id: 12,
            route_generation: 1,
        });
        let h1_key = h1.key;
        let h2_key = h2.key;

        let mut candidates = MpCandidateTable::default();
        candidates.upsert(h1, Instant::now());
        candidates.upsert(h2, Instant::now());
        candidates.set_state(&h1_key, PathLifecycleState::AVAILABLE);
        candidates.set_state(&h2_key, PathLifecycleState::STANDBY);
        candidates.get_mut(&h1_key).unwrap().measurements.propagation_rtt_micros = 20_000;
        candidates.get_mut(&h2_key).unwrap().measurements.propagation_rtt_micros = 60_000;

        let input = selection_input(&candidates, &[], &HashMap::new());
        assert_eq!(select_paths(&input.paths, &[], 1, &input.pinned), vec![h1_key]);

        // H1 hard-failed (first hop gone).
        candidates.mark_dead(&h1_key);
        let input = selection_input(&candidates, &[], &HashMap::new());
        assert_eq!(
            input.paths.iter().map(|path| path.key).collect::<Vec<_>>(),
            vec![h2_key],
            "only the remaining hop H2 is a candidate"
        );
        let selected = select_paths(&input.paths, &[h1_key], 1, &input.pinned);
        assert_eq!(selected, vec![h2_key]);

        let targets = build_path_targets(&candidates, &selected, false, &[], &[]);
        assert_eq!(targets.len(), 1, "the dead first hop gets no target");
        assert_eq!(targets[0].remote_addr, h2_key.remote_addr);
        assert!(!targets[0].standby, "the remaining hop must carry data");
        assert_eq!(targets[0].rate, None);
    }

    #[test]
    fn remote_endpoint_resource_group_override_merges_matching_paths() {
        let (path, _) = channel_path_pair(
            "127.0.0.1:40931".parse().unwrap(),
            "127.0.0.2:40932".parse().unwrap(),
        );
        let mut spec = path_spec(path, "127.0.0.2:40932".parse().unwrap());
        let mut config = gen_default_mp_config();
        config.resource_groups = vec![crate::proto::common::MpResourceGroupConfig {
            name: "remote-wan".into(),
            remote_endpoints: vec!["127.0.0.2".into()],
            ..Default::default()
        }];

        MpSessionManager::apply_resource_group_overrides(&mut spec, &config);

        assert_eq!(
            spec.remote_resource,
            crate::connector::mp_path::ResourceGroupId::shared_bottleneck("remote-wan")
        );
    }

    #[test]
    fn wildcard_remote_promotion_survives_resource_override_reapplication() {
        let wildcard_remote: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let concrete_remote: SocketAddr = "198.51.100.42:45678".parse().unwrap();
        let (path, _) = channel_path_pair("127.0.0.1:40941".parse().unwrap(), wildcard_remote);
        let wildcard = path_spec(path, wildcard_remote);
        let wildcard_key = wildcard.key;
        let mut candidates = MpCandidateTable::default();
        candidates.upsert(wildcard, Instant::now());

        let resolved_key = candidates
            .resolve_wildcard_remote(wildcard_key.local_addr, concrete_remote)
            .expect("the server-side wildcard path must learn its concrete endpoint");
        let mut promoted = candidates
            .get(&resolved_key)
            .expect("promoted candidate must remain in the table")
            .spec
            .clone();

        assert_eq!(
            promoted.base_remote_resource,
            crate::connector::mp_path::ResourceGroupId::remote_endpoint(concrete_remote),
            "wildcard resolution must persist the learned endpoint as the immutable override base"
        );

        let config = gen_default_mp_config();
        MpSessionManager::apply_resource_group_overrides(&mut promoted, &config);

        assert_eq!(
            promoted.remote_resource,
            crate::connector::mp_path::ResourceGroupId::remote_endpoint(concrete_remote),
            "a config refresh must restore the learned concrete remote endpoint, never the wildcard"
        );
    }

    /// `count` validated paths on distinct loopback addresses (they stay
    /// `AVAILABLE`, which is what `record_validation` makes of a validated path).
    fn established_paths(first_port: u16, count: usize) -> (MpCandidateTable, Vec<PathKey>) {
        let mut candidates = MpCandidateTable::default();
        let mut keys = Vec::new();
        for index in 0..count as u16 {
            let local = format!("127.0.0.1:{}", first_port + 2 * index).parse().unwrap();
            let remote = format!("127.0.0.1:{}", first_port + 2 * index + 1).parse().unwrap();
            let (path, _) = channel_path_pair(local, remote);
            let spec = path_spec(path, remote);
            let key = spec.key;
            candidates.upsert(spec, Instant::now());
            candidates.begin_validation(&key);
            candidates.record_validation(&key, true);
            keys.push(key);
        }
        (candidates, keys)
    }

    fn target_of(targets: &[MpPathTarget], key: &PathKey) -> MpPathTarget {
        *targets
            .iter()
            .find(|target| target.local_addr == key.local_addr && target.remote_addr == key.remote_addr)
            .expect("the path has a target")
    }

    /// P4-A: a selected path is available with no target of its own (its
    /// congestion control decides), the other established paths stand by, and
    /// a path still validating is left alone. Red on the Top-K code: the
    /// unselected paths got the 32 kbit/s bootstrap allowance and the
    /// selected one the optimizer's allocation.
    #[test]
    fn target_plan_makes_the_selected_path_available_and_holds_the_rest_on_standby() {
        let (mut candidates, keys) = established_paths(40901, 3);
        let (path_a4, _) = channel_path_pair(
            "127.0.0.1:40907".parse().unwrap(),
            "127.0.0.1:40908".parse().unwrap(),
        );
        let validating = path_spec(path_a4, "127.0.0.1:40908".parse().unwrap());
        let validating_key = validating.key;
        candidates.upsert(validating, Instant::now());
        candidates.begin_validation(&validating_key);

        let targets = build_path_targets(&candidates, &[keys[0]], false, &[], &[]);

        assert_eq!(targets.len(), 4);
        let selected = target_of(&targets, &keys[0]);
        assert_eq!(selected.rate, None);
        assert!(!selected.standby);
        for key in &keys[1..] {
            let target = target_of(&targets, key);
            assert!(target.standby, "{key:?} is established but not selected");
            assert_eq!(target.rate, None, "a standby path is not given a rate");
        }
        let target = target_of(&targets, &validating_key);
        assert!(!target.standby);
        assert_eq!(target.rate, None);
    }

    /// A user-declared shared bottleneck on the remote side bounds the paths
    /// that end in it, as the max-flow graph's remote resources did: its
    /// capacity is split among the selected paths that pass through it.
    #[test]
    fn target_plan_splits_a_declared_remote_bottleneck_among_brutal_paths() {
        let (mut candidates, keys) = established_paths(40961, 2);
        let group = ResourceGroupId::shared_bottleneck("remote-wan");
        for key in &keys {
            candidates.get_mut(key).unwrap().spec.remote_resource = group.clone();
        }
        let budgets = [ResourceCapacity {
            resource: group,
            capacity_bps: 60_000_000,
        }];

        let targets = build_path_targets(&candidates, &keys, true, &budgets, &[]);

        for key in &keys {
            assert_eq!(target_of(&targets, key).rate, Some(30_000_000));
        }
    }

    /// With nothing selected (every candidate excluded, or none established)
    /// no path is held on standby: nothing would be left to carry data. Only
    /// `pause` and `exclude` still hold a path at zero.
    #[test]
    fn target_plan_leaves_paths_unmanaged_when_nothing_is_selected() {
        let (candidates, _keys) = established_paths(40931, 1);

        let empty = build_path_targets(&candidates, &[], false, &[], &[]);
        assert_eq!(empty[0].rate, None);
        assert!(!empty[0].standby);

        let paused = build_path_targets(&candidates, &[], false, &[], &[wildcard_policy("pause")]);
        assert_eq!(paused[0].rate, Some(0), "pause still holds an unmanaged path");
    }

    /// The incident behind the old bootstrap floor: a path whose only
    /// bandwidth sample came from Ping/Pong and the EasyTier handshake had a
    /// tiny positive BtlBw, and capping the path by it delayed the first user
    /// TCP packet until the application timed out. Now no sample caps
    /// anything: red on the Top-K code, which still returned
    /// `Some(BOOTSTRAP_PATH_TARGET_RATE_BPS)` here.
    #[test]
    fn target_plan_never_caps_a_path_by_its_own_bandwidth_sample() {
        let (mut candidates, keys) = established_paths(40913, 1);
        candidates.observe_measurements(
            &keys[0],
            PathMeasurements {
                btlbw: 174,
                delivery_rate: 172,
                propagation_rtt_micros: 313_000,
                loss_rate: 0.0,
                app_limited: true,
                sample_age_micros: Some(1_000),
                congestion_control_state: tquic::CongestionControlState::ProbeBandwidth,
                observed_local_addr: None,
            },
        );

        let targets = build_path_targets(&candidates, &[keys[0]], false, &[], &[]);

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].rate, None);
    }

    /// P4-A Brutal: the Autorate budget of a NIC is split evenly among the
    /// selected paths that leave through it; a standby path is held to its
    /// NIC's budget so a failover cannot send faster than the egress takes;
    /// any other congestion control gets no rate. Red: there was no such
    /// split -- the max-flow graph had one WAN resource and Brutal's 50 Mbit/s
    /// went past the 31.6 Mbit/s the NIC could take (PROJECT_journal.md:2045).
    #[test]
    fn target_plan_splits_a_nics_budget_among_its_selected_brutal_paths() {
        let (mut candidates, keys) = established_paths(40941, 3);
        let eth0 = ResourceGroupId::egress_device("eth0").unwrap();
        let eth1 = ResourceGroupId::egress_device("eth1").unwrap();
        for (key, nic) in [(keys[0], &eth0), (keys[1], &eth0), (keys[2], &eth1)] {
            candidates.get_mut(&key).unwrap().spec.egress_resource = Some(nic.clone());
        }
        let budgets = [ResourceCapacity {
            resource: eth0.clone(),
            capacity_bps: 90_000_000,
        }];

        let targets = build_path_targets(&candidates, &[keys[0], keys[1]], true, &budgets, &[]);
        for key in &keys[..2] {
            let target = target_of(&targets, key);
            assert_eq!(target.rate, Some(45_000_000));
            assert!(!target.standby);
        }
        let held = target_of(&targets, &keys[2]);
        assert!(held.standby);
        assert_eq!(held.rate, None, "eth1 has no budget: Brutal's own rate applies");

        let targets = build_path_targets(&candidates, &[keys[0]], true, &budgets, &[]);
        assert_eq!(target_of(&targets, &keys[0]).rate, Some(90_000_000));
        let standby = target_of(&targets, &keys[1]);
        assert!(standby.standby);
        assert_eq!(standby.rate, Some(90_000_000), "a standby path is held to its NIC budget");

        let targets = build_path_targets(&candidates, &[keys[0], keys[1]], false, &budgets, &[]);
        assert!(
            targets.iter().all(|target| target.rate.is_none()),
            "only Brutal is given a rate"
        );
    }

    fn wildcard_policy(action: &str) -> crate::proto::common::MpPathPolicy {
        crate::proto::common::MpPathPolicy {
            match_egress_device: String::new(),
            match_carrier_kind: String::new(),
            match_remote_endpoint: String::new(),
            action: action.to_string(),
            prefer_weight: 1.0,
            enabled: true,
            note: String::new(),
        }
    }

    /// P4-C (iroh `open_path_on_conn`, `remote_state.rs:1081-1090`): a
    /// refused open is queued once per 4-tuple and opened again until the
    /// connection takes it. Red: the refusal marked the candidate failed and
    /// nothing was ever retried (`queue_refused_open`/`retry_refused_open` did
    /// not exist).
    #[tokio::test]
    async fn a_refused_path_open_is_queued_once_and_retried_until_it_opens() {
        let pending = Arc::new(DashMap::new());
        let (_candidates, keys) = established_paths(41101, 2);
        let id = (5, keys[0]);
        assert!(queue_refused_open(&pending, id));
        assert!(!queue_refused_open(&pending, id), "the same 4-tuple is queued once");
        assert!(queue_refused_open(&pending, (5, keys[1])), "another 4-tuple queues too");

        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = attempts.clone();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            retry_refused_open(
                pending.clone(),
                id,
                std::time::Duration::from_millis(5),
                move || {
                    let counter = counter.clone();
                    async move {
                        if counter.fetch_add(1, Ordering::SeqCst) < 2 {
                            OpenAttempt::NoFreeSlot
                        } else {
                            OpenAttempt::Opened
                        }
                    }
                },
            ),
        )
        .await
        .expect("the retry loop ends once the open succeeds");

        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        assert!(!pending.contains_key(&id), "an opened path leaves the queue");
        assert!(pending.contains_key(&(5, keys[1])), "the other entry is untouched");
    }

    /// A queued open whose peer was forgotten is dropped without another
    /// attempt, and `forget_peer` empties the peer's part of the queue.
    #[tokio::test]
    async fn a_queued_path_open_stops_when_the_peer_is_forgotten() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let (_candidates, keys) = established_paths(41111, 2);
        let id = (7, keys[0]);
        assert!(queue_refused_open(&manager.pending_path_opens, id));
        assert!(queue_refused_open(&manager.pending_path_opens, (7, keys[1])));
        assert!(queue_refused_open(&manager.pending_path_opens, (8, keys[0])));

        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = attempts.clone();
        let task = tokio::spawn(retry_refused_open(
            manager.pending_path_opens.clone(),
            id,
            std::time::Duration::from_millis(20),
            move || {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    OpenAttempt::NoFreeSlot
                }
            },
        ));
        manager.forget_peer(7).await;
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("the retry loop ends when its entry is gone")
            .unwrap();

        assert_eq!(attempts.load(Ordering::SeqCst), 0);
        assert!(!manager.pending_path_opens.contains_key(&(7, keys[1])));
        assert!(manager.pending_path_opens.contains_key(&(8, keys[0])), "other peers keep theirs");
    }

    /// A lossy path and a clean one, both measured and established.
    fn lossy_and_clean_paths() -> (MpCandidateTable, PathKey, PathKey) {
        let mut candidates = MpCandidateTable::default();
        let mut add = |local: &str, remote: &str| {
            let (path, _) = channel_path_pair(local.parse().unwrap(), remote.parse().unwrap());
            let spec = path_spec(path, remote.parse().unwrap());
            let key = spec.key;
            candidates.upsert(spec, Instant::now());
            candidates.set_state(&key, PathLifecycleState::AVAILABLE);
            let candidate = candidates.get_mut(&key).unwrap();
            candidate.measurements.btlbw = 20_000_000;
            candidate.measurements.propagation_rtt_micros = 20_000;
            key
        };
        let lossy = add("127.0.0.1:40931", "127.0.0.1:40932");
        let clean = add("127.0.0.1:40933", "127.0.0.1:40934");
        candidates.record_traffic(&lossy, 100_000, 40_000);
        assert!(candidates.get(&lossy).unwrap().is_lossy());
        (candidates, lossy, clean)
    }

    fn input_keys(input: &SelectionInput) -> Vec<PathKey> {
        input.paths.iter().map(|path| path.key).collect()
    }

    /// A lossy path gives way only to a clean path that can carry data: a
    /// clean path the user excluded or paused must not keep it out.
    #[test]
    fn an_excluded_clean_path_does_not_keep_a_lossy_one_out() {
        let (candidates, lossy, clean) = lossy_and_clean_paths();
        let input = |policies: &[MpPathPolicy]| input_keys(&selection_input(&candidates, policies, &HashMap::new()));
        assert_eq!(input(&[]), vec![clean]);
        let clean_only = |action: &str| crate::proto::common::MpPathPolicy {
            match_remote_endpoint: "127.0.0.1:40934".to_string(),
            ..wildcard_policy(action)
        };
        assert_eq!(input(&[clean_only("exclude")]), vec![lossy]);
        assert_eq!(input(&[clean_only("pause")]), vec![lossy]);
        assert_eq!(input(&[clean_only("prefer")]), vec![clean]);
    }

    /// The incident 2026-11-05: the selected path kept getting data while
    /// none of it was acknowledged, and TQUIC never backed off. It gives way
    /// to any path that still gets acknowledgements, even a lossy one; it is
    /// kept when nothing else is left, and any acknowledgement brings it back.
    #[test]
    fn a_path_whose_data_gets_no_acks_gives_way_to_one_that_does() {
        let (mut candidates, lossy, clean) = lossy_and_clean_paths();
        let start = Instant::now();
        let at = |ms: u64| start + std::time::Duration::from_millis(ms);
        candidates.record_acks(&clean, 10_000, 9_000, 20_000, at(0));
        candidates.record_acks(&clean, 30_000, 9_000, 20_000, at(500));
        assert!(!candidates.get(&clean).unwrap().is_unacked(), "500 ms is within the limit");
        candidates.record_acks(&clean, 40_000, 9_000, 20_000, at(1_600));
        assert!(candidates.get(&clean).unwrap().is_unacked());

        let input = selection_input(&candidates, &[], &HashMap::new());
        assert_eq!(input_keys(&input), vec![lossy]);
        assert_eq!(input.left_out.get(&clean), Some(&LEFT_OUT_UNACKED));

        let lossy_out = crate::proto::common::MpPathPolicy {
            match_remote_endpoint: "127.0.0.1:40932".to_string(),
            ..wildcard_policy("exclude")
        };
        assert_eq!(
            input_keys(&selection_input(&candidates, &[lossy_out], &HashMap::new())),
            vec![clean],
            "the only path left keeps carrying data"
        );

        candidates.record_acks(&clean, 41_000, 9_500, 20_000, at(1_700));
        assert!(!candidates.get(&clean).unwrap().is_unacked());
        assert_eq!(
            input_keys(&selection_input(&candidates, &[], &HashMap::new())),
            vec![clean]
        );
    }

    /// An idle path is not unacked the moment it sends again: the clock
    /// starts at the first unacknowledged send, not at the last ack.
    #[test]
    fn an_idle_path_is_not_unacked_when_it_sends_again() {
        let (mut candidates, _lossy, clean) = lossy_and_clean_paths();
        let start = Instant::now();
        let at = |ms: u64| start + std::time::Duration::from_millis(ms);
        candidates.record_acks(&clean, 10_000, 10_000, 20_000, at(0));
        candidates.record_acks(&clean, 10_000, 10_000, 20_000, at(60_000));
        candidates.record_acks(&clean, 11_000, 10_000, 20_000, at(60_500));
        assert!(!candidates.get(&clean).unwrap().is_unacked());
        // A new TQUIC path behind the same key starts over.
        candidates.record_acks(&clean, 500, 0, 20_000, at(62_000));
        assert!(!candidates.get(&clean).unwrap().is_unacked());
    }

    /// The incident on a lossy mobile uplink under Brutal: both punched paths
    /// lost ~30% and the only clean path was a relay that had carried
    /// nothing. A clean path the selector cannot use must not keep the lossy
    /// ones out, and a relay path is budgeted by its NIC (its own resource,
    /// `relay-next-hop:..`, has no budget).
    #[test]
    fn a_relay_path_is_budgeted_by_its_nic_and_an_unselectable_clean_path_keeps_no_lossy_one_out() {
        let (mut candidates, lossy, clean) = lossy_and_clean_paths();
        let wan = ResourceGroupId::wan("198.51.100.7".parse().unwrap());
        let nic = ResourceGroupId::egress_device("eth0").unwrap();
        for (key, local) in [
            (lossy, wan.clone()),
            (clean, ResourceGroupId::new("relay-next-hop:7:1")),
        ] {
            let spec = &mut candidates.get_mut(&key).unwrap().spec;
            spec.local_resource = local;
            spec.egress_resource = Some(nic.clone());
        }
        assert_eq!(input_keys(&selection_input(&candidates, &[], &HashMap::new())), vec![clean]);
        for key in [lossy, clean] {
            assert_eq!(
                budgeted_path(&key, candidates.get(&key).unwrap()).resources,
                vec![nic.clone()]
            );
        }

        // The clean path is paused: it is no candidate, so it cannot keep the
        // lossy one out, and the lossy one takes the whole NIC budget.
        let pause_clean = crate::proto::common::MpPathPolicy {
            match_remote_endpoint: clean.remote_addr.to_string(),
            ..wildcard_policy("pause")
        };
        let input = selection_input(&candidates, &[pause_clean.clone()], &HashMap::new());
        let selected = select_paths(&input.paths, &[], 1, &input.pinned);
        assert_eq!(selected, vec![lossy]);
        let budgets = [ResourceCapacity {
            resource: nic,
            capacity_bps: 50_000_000,
        }];
        let targets = build_path_targets(&candidates, &selected, true, &budgets, &[pause_clean]);
        assert_eq!(target_of(&targets, &lossy).rate, Some(50_000_000));
        assert_eq!(target_of(&targets, &clean).rate, Some(0));
    }

    /// Two established relay paths over first hops 11 (20 ms) and 12 (60 ms),
    /// neither with a byte-based loss sample (they carry next to nothing).
    fn two_relay_paths() -> (MpCandidateTable, PathKey, PathKey) {
        let mut candidates = MpCandidateTable::default();
        let mut add = |local: &str, remote: &str, first_hop: PeerId, rtt_micros: u64| {
            let (path, _) = channel_path_pair(local.parse().unwrap(), remote.parse().unwrap());
            let mut spec = path_spec(path, remote.parse().unwrap());
            spec.carrier_kind = CarrierKind::RelayNextHop;
            spec.relay_metadata = Some(super::super::mp_path::RelayPathMetadata {
                first_hop_peer_id: first_hop,
                egress_first_hop_peer_id: first_hop,
                route_generation: 1,
            });
            let key = spec.key;
            candidates.upsert(spec, Instant::now());
            candidates.set_state(&key, PathLifecycleState::AVAILABLE);
            candidates.get_mut(&key).unwrap().measurements.propagation_rtt_micros = rtt_micros;
            key
        };
        let near = add("127.0.0.1:41911", "127.0.0.1:41912", 11, 20_000);
        let far = add("127.0.0.1:41913", "127.0.0.1:41914", 12, 60_000);
        (candidates, near, far)
    }

    /// MP weak-network plan R3, E2/E3: the relay path over the first hop that
    /// answers no ping has no byte-based loss sample and the better RTT, and
    /// was selected. Its first hop's ping loss now keeps it out while another
    /// path can carry, and never leaves the session without a path.
    #[test]
    fn a_relay_path_over_a_first_hop_losing_pings_gives_way() {
        let (candidates, near, far) = two_relay_paths();
        let chosen = |loss: &[(PeerId, f64)], policies: &[MpPathPolicy]| {
            let input = selection_input(&candidates, policies, &loss.iter().copied().collect());
            select_paths(&input.paths, &[], 1, &input.pinned)
        };
        // Without first-hop loss the lower RTT wins (the old behaviour).
        assert_eq!(chosen(&[], &[]), vec![near]);
        // Every ping to the near hop is lost, or a third of them.
        assert_eq!(chosen(&[(11, 1.0)], &[]), vec![far]);
        assert_eq!(chosen(&[(11, 0.3)], &[]), vec![far]);
        // Below the lossy threshold nothing changes.
        assert_eq!(chosen(&[(11, 0.05)], &[]), vec![near]);
        // Both are worse: a lossy hop that still answers beats one that does not.
        assert_eq!(chosen(&[(11, 1.0), (12, 0.3)], &[]), vec![far]);
        assert_eq!(chosen(&[(11, 0.3), (12, 1.0)], &[]), vec![near]);
        // Neither answers: still a path to try, by RTT.
        assert_eq!(chosen(&[(11, 1.0), (12, 1.0)], &[]), vec![near]);
        // Both lossy: same class, by RTT.
        assert_eq!(chosen(&[(11, 0.3), (12, 0.4)], &[]), vec![near]);
        // A pin is the user's decision.
        let pin_near = crate::proto::common::MpPathPolicy {
            match_remote_endpoint: near.remote_addr.to_string(),
            ..wildcard_policy("pin")
        };
        assert_eq!(chosen(&[(11, 1.0)], &[pin_near]), vec![near]);
    }

    /// The reason is kept for the path status.
    #[test]
    fn a_path_left_out_for_its_first_hop_says_so() {
        let (mut candidates, near, far) = two_relay_paths();
        let loss = HashMap::from([(11, 1.0)]);
        let input = selection_input(&candidates, &[], &loss);
        assert_eq!(input.left_out.get(&near), Some(&LEFT_OUT_LOSSY_FIRST_HOP));
        assert!(!input.left_out.contains_key(&far));

        // Its own byte-based loss comes first.
        candidates.record_traffic(&near, 100_000, 40_000);
        let input = selection_input(&candidates, &[], &HashMap::from([(11, 0.3)]));
        assert_eq!(input.left_out.get(&near), Some(&LEFT_OUT_LOSSY_PATH));
    }

    /// MP weak-network plan W2: a relay path over a first hop that loses pings
    /// does not use up the relay path budget, so the better first hop can get
    /// a path.
    #[tokio::test]
    async fn a_relay_path_over_a_lossy_first_hop_does_not_use_the_relay_path_budget() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let (candidates, _near, _far) = two_relay_paths();
        manager
            .candidates
            .insert(7, Arc::new(Mutex::new(candidates)));
        assert_eq!(manager.live_relay_path_count(7).await, 2);

        manager.set_first_hop_loss(HashMap::from([(11, 1.0)]));
        assert_eq!(manager.live_relay_path_count(7).await, 1);
        manager.set_first_hop_loss(HashMap::from([(11, 0.3), (12, 0.2)]));
        assert_eq!(manager.live_relay_path_count(7).await, 0);
        manager.set_first_hop_loss(HashMap::from([(11, 0.05)]));
        assert_eq!(manager.live_relay_path_count(7).await, 2);
    }

    /// S-I4: the selector ranks a path by its propagation delay (the 300 s
    /// windowed minimum of its round trips), not the smoothed RTT, which
    /// carries the queue our own traffic built (and on a standby path stays
    /// where its last load left it). Red if the smoothed RTT is used: the
    /// path would rank at 500 ms.
    #[test]
    fn selection_ranks_by_the_windowed_minimum_not_the_smoothed_rtt() {
        let telemetry = MpPathTelemetry {
            local_addr: "127.0.0.1:40931".parse().unwrap(),
            remote_addr: "127.0.0.1:40932".parse().unwrap(),
            validation_state: tquic::PathState::Validated,
            bandwidth_model_valid: true,
            btlbw: 20_000_000,
            delivery_rate: 20_000_000,
            app_limited: false,
            sample_age_micros: Some(1_000),
            congestion_control_state: tquic::CongestionControlState::ProbeBandwidth,
            scheduler_target_rate_bps: None,
            min_rtt_micros: 15_000,
            windowed_min_rtt_micros: 20_000,
            backed_off: false,
            srtt_micros: 500_000,
            sent_bytes: 1_000,
            recv_bytes: 1_000,
            lost_bytes: 0,
            acked_bytes: 1_000,
            max_inflight_bytes: 1_000,
            cwnd_bytes: 10_000,
            pacing_rate_bps: 1_000_000,
            observed_local_addr: None,
        };
        let measured = path_measurements_from_telemetry(&telemetry);
        assert_eq!(measured.propagation_rtt_micros, 20_000);

        let (mut candidates, _lossy, clean) = lossy_and_clean_paths();
        candidates.get_mut(&clean).unwrap().measurements = measured;
        let input = selection_input(&candidates, &[], &HashMap::new());
        let path = input.paths.iter().find(|path| path.key == clean).unwrap();
        assert_eq!(path.rtt_micros, 20_000);
    }

    /// S-I14 / P4-B: a validated path that has carried only keepalives (no
    /// sample of any kind yet) is selectable at once, ranked at the 333 ms
    /// initial RTT (draft-ietf-quic-multipath Section 5.5). Red on the 9-state
    /// machine: it sat in `ProbingBw` and the optimizer skipped it.
    #[test]
    fn a_validated_path_without_any_sample_is_selectable() {
        let (mut candidates, keys) = established_paths(40951, 1);
        let candidate = candidates.get_mut(&keys[0]).unwrap();
        candidate.measurements = PathMeasurements::default();
        assert!(candidate.state.is_established());
        let input = selection_input(&candidates, &[], &HashMap::new());
        assert_eq!(input_keys(&input), vec![keys[0]]);
        assert_eq!(
            input.paths[0].rtt_micros,
            crate::connector::mp_optimizer::UNMEASURED_RTT_MICROS
        );
        assert_eq!(
            select_paths(&input.paths, &[], 1, &input.pinned),
            vec![keys[0]]
        );
    }

    /// S-I8: one CAKE and one autorate per NIC. A direct path and a relay
    /// path that leave through the same NIC resolve to one scope, whatever
    /// their carrier or WAN resource; another NIC is another scope.
    #[tokio::test]
    async fn paths_of_one_nic_share_one_egress_scope() {
        use crate::common::egress_inventory::EgressStableId;
        let (direct, _direct_remote) = real_udp_legacy_spec().await;
        let (relay, _relay_remote) = real_udp_legacy_spec().await;
        let (other_nic, _other_remote) = real_udp_legacy_spec().await;
        let eth0 = ResourceGroupId::egress_device("eth0").unwrap();
        let eth1 = ResourceGroupId::egress_device("eth1").unwrap();
        let mut direct = direct;
        direct.carrier_kind = CarrierKind::UdpPunch;
        direct.egress_resource = Some(eth0.clone());
        direct.local_resource = ResourceGroupId::wan("198.51.100.7".parse().unwrap());
        let mut relay = relay;
        relay.carrier_kind = CarrierKind::RelayNextHop;
        relay.egress_resource = Some(eth0);
        relay.local_resource = ResourceGroupId::new("relay-next-hop:7:1");
        let mut other_nic = other_nic;
        other_nic.egress_resource = Some(eth1);
        let routes = HashMap::from([
            (
                "eth0".to_string(),
                (EgressStableId::Linux { netns_inode: 1, ifindex: 2 }, 1),
            ),
            (
                "eth1".to_string(),
                (EgressStableId::Linux { netns_inode: 1, ifindex: 3 }, 1),
            ),
        ]);
        let scope = |spec: &MpPathSpec| MpSessionManager::path_nic_scope(spec, &routes);
        assert!(scope(&direct).is_some());
        assert_eq!(scope(&direct), scope(&relay), "one NIC, one scope");
        assert_ne!(scope(&direct), scope(&other_nic));
    }

    /// MP_SQM_PLAN.md S2.3: a `pause` policy holds a path at the `Some(0)`
    /// scheduler target -- data stops, but (unlike `Dead`) the path keeps a
    /// target so validation/recovery traffic is unaffected.
    #[test]
    fn build_path_targets_zeroes_the_rate_for_a_path_matched_by_a_pause_policy() {
        let (candidates, keys) = established_paths(40915, 1);
        let key = keys[0];

        let unpaused = build_path_targets(&candidates, &[key], false, &[], &[]);
        assert_eq!(
            unpaused[0].rate, None,
            "sanity: without a policy the selected path is left to its congestion control"
        );

        let excluded = build_path_targets(&candidates, &[], false, &[], &[wildcard_policy("exclude")]);
        assert_eq!(excluded[0].rate, Some(0), "an excluded path carries no data either");

        let policies = [wildcard_policy("pause")];
        let paused = build_path_targets(&candidates, &[], false, &[], &policies);

        assert_eq!(paused.len(), 1);
        assert_eq!(
            paused[0].rate,
            Some(0),
            "a paused path must get a zero scheduler target, not None (which would mean not managed)"
        );
        let paused_selected = build_path_targets(&candidates, &[key], false, &[], &policies);
        assert_eq!(paused_selected[0].rate, Some(0));
    }

    /// MP_SQM_PLAN.md S3.2 "pin -> traffic only on that path": once the
    /// pinned path is selected, every other path's target is zero.
    #[test]
    fn build_path_targets_zeroes_unpinned_paths_while_a_pin_is_selected() {
        let (candidates, keys) = established_paths(40921, 2);
        let pin = crate::proto::common::MpPathPolicy {
            match_remote_endpoint: keys[1].remote_addr.to_string(),
            ..wildcard_policy("pin")
        };

        let pinned = build_path_targets(&candidates, &[keys[1]], false, &[], &[pin.clone()]);
        assert_eq!(target_of(&pinned, &keys[0]).rate, Some(0));
        assert_eq!(target_of(&pinned, &keys[1]).rate, None);

        // The pinned path not selected: nothing is held back.
        let pending = build_path_targets(&candidates, &[keys[0]], false, &[], &[pin]);
        assert_eq!(target_of(&pending, &keys[0]).rate, None);
        assert!(!target_of(&pending, &keys[0]).standby);
    }

    /// A disabled policy must never pause a path, and a policy whose action
    /// is not `pause` (e.g. `pin`) must not zero the rate either -- only an
    /// enabled, matching `pause` policy does.
    #[test]
    fn build_path_targets_ignores_disabled_or_non_pause_policies() {
        let (candidates, keys) = established_paths(40917, 1);

        let mut disabled_pause = wildcard_policy("pause");
        disabled_pause.enabled = false;
        let policies = [disabled_pause, wildcard_policy("pin")];

        let targets = build_path_targets(&candidates, &[keys[0]], false, &[], &policies);

        assert_eq!(targets.len(), 1);
        assert_eq!(
            targets[0].rate, None,
            "a disabled pause and a non-pause pin must not affect the rate"
        );
    }

    /// Pausing the only selected path with kmax=1 must not leave the session
    /// without a path that carries data: the paused path is no candidate, the
    /// next best validated path is selected and not standby, and the paused
    /// one keeps a zero target. Red on the Top-K code (and on the first cut of
    /// the selector): `pause` did not affect the choice, so the paused path
    /// stayed selected at a zero rate and the other one stayed on standby.
    #[test]
    fn pausing_the_only_selected_path_selects_the_next_best_one() {
        let (mut candidates, keys) = established_paths(40971, 2);
        candidates.get_mut(&keys[0]).unwrap().measurements.propagation_rtt_micros = 10_000;
        candidates.get_mut(&keys[1]).unwrap().measurements.propagation_rtt_micros = 50_000;
        let input = selection_input(&candidates, &[], &HashMap::new());
        let selected = select_paths(&input.paths, &[], 1, &input.pinned);
        assert_eq!(selected, vec![keys[0]]);

        let pause_first = crate::proto::common::MpPathPolicy {
            match_remote_endpoint: keys[0].remote_addr.to_string(),
            ..wildcard_policy("pause")
        };
        let policies = [pause_first];
        let input = selection_input(&candidates, &policies, &HashMap::new());
        let selected = select_paths(&input.paths, &selected, 1, &input.pinned);
        assert_eq!(selected, vec![keys[1]]);

        let targets = build_path_targets(&candidates, &selected, false, &[], &policies);
        let paused = target_of(&targets, &keys[0]);
        assert_eq!(paused.rate, Some(0));
        assert!(!paused.standby);
        let next = target_of(&targets, &keys[1]);
        assert_eq!(next.rate, None);
        assert!(!next.standby, "the next best path must carry data");
    }

    /// A standby path carries data only when no selected path is left
    /// (draft-ietf-quic-multipath Section 3.3): however busy the selected
    /// path is, the unselected one stays on standby. A standby probe used to
    /// hand it the busiest path's allocation for 3 s every minute, and the
    /// GUI showed a Backup path sending 11 Mbit/s.
    #[test]
    fn an_unselected_path_stays_on_standby_while_the_selected_path_is_busy() {
        let (mut candidates, keys) = established_paths(40921, 2);
        let (selected, unselected) = (keys[0], keys[1]);
        for key in [selected, unselected] {
            let candidate = candidates.get_mut(&key).unwrap();
            candidate.measurements.btlbw = 60_000_000;
            candidate.measurements.delivery_rate = 60_000_000;
            candidate.measurements.app_limited = false;
        }

        let targets = build_path_targets(&candidates, &[selected], false, &[], &[]);

        assert!(!target_of(&targets, &selected).standby);
        assert!(target_of(&targets, &unselected).standby);
    }

    /// MP_SQM_PLAN.md S2.4 rate negotiation (consume half), unit-level: the
    /// min(local up, peer down) rule as applied to `MpPathTarget.rate`.
    #[test]
    fn clamp_targets_to_peer_rx_cap_only_ever_lowers_a_rate() {
        let local = "127.0.0.1:41001".parse().unwrap();
        let remote = "127.0.0.1:41002".parse().unwrap();
        let managed = MpPathTarget {
            local_addr: local,
            remote_addr: remote,
            rate: Some(60_000_000),
            standby: false,
        };
        let unmanaged = MpPathTarget {
            local_addr: local,
            remote_addr: remote,
            rate: None,
            standby: false,
        };

        // No peer cap known: unchanged.
        assert_eq!(
            clamp_targets_to_peer_rx_cap(vec![managed], None),
            vec![managed]
        );

        // Peer cap below the allocated rate: clamped down to it.
        let clamped = clamp_targets_to_peer_rx_cap(vec![managed], Some(10_000_000));
        assert_eq!(clamped[0].rate, Some(10_000_000));

        // Peer cap above the allocated rate: never raised.
        let unraised = clamp_targets_to_peer_rx_cap(vec![managed], Some(200_000_000));
        assert_eq!(unraised[0].rate, Some(60_000_000));

        // An unmanaged path (`rate: None`) sends at Brutal's own `up_mbps`,
        // so the cap applies to it too: a Brutal path the optimizer cannot
        // manage (its egress has no budget, e.g. a relay path with no NIC
        // scope) would otherwise ignore the peer's announced downlink.
        let capped = clamp_targets_to_peer_rx_cap(vec![unmanaged], Some(10_000_000));
        assert_eq!(capped[0].rate, Some(10_000_000));

        // A paused/draining path (`Some(0)`) stays at zero.
        let paused = MpPathTarget { rate: Some(0), ..managed };
        assert_eq!(clamp_targets_to_peer_rx_cap(vec![paused], Some(10_000_000))[0].rate, Some(0));
    }

    #[tokio::test]
    async fn runtime_snapshot_exposes_candidate_measurements_state_and_target_rate() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let (path, _) = channel_path_pair(
            "127.0.0.1:40921".parse().unwrap(),
            "127.0.0.1:40922".parse().unwrap(),
        );
        let spec = path_spec(path, "127.0.0.1:40922".parse().unwrap());
        let key = spec.key;
        let mut candidates = MpCandidateTable::default();
        candidates.upsert(spec, Instant::now());
        candidates.set_state(&key, PathLifecycleState::AVAILABLE);
        candidates.observe_measurements(
            &key,
            PathMeasurements {
                btlbw: 80_000_000,
                delivery_rate: 72_000_000,
                propagation_rtt_micros: 12_000,
                loss_rate: 0.01,
                app_limited: false,
                sample_age_micros: Some(250_000),
                congestion_control_state: tquic::CongestionControlState::ProbeBandwidth,
                observed_local_addr: None,
            },
        );
        manager
            .candidates
            .insert(7, Arc::new(Mutex::new(candidates)));
        manager.optimization_snapshots.insert(
            7,
            MpOptimizationSnapshot {
                active_paths: vec![key],
                targets: vec![MpPathTarget {
                    local_addr: key.local_addr,
                    remote_addr: key.remote_addr,
                    rate: Some(60_000_000),
                    standby: false,
                }],
                candidate_count: 1,
                eligible_count: 1,
            },
        );

        let snapshots = manager.runtime_snapshots().await.unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].peer_id, 7);
        assert_eq!(snapshots[0].paths.len(), 1);
        let path = &snapshots[0].paths[0];
        assert_eq!(path.state, PathLifecycleState::AVAILABLE);
        assert_eq!(path.measurements.btlbw, 80_000_000);
        assert_eq!(path.measurements.delivery_rate, 72_000_000);
        assert_eq!(path.target_rate_bps, Some(60_000_000));
        assert_eq!(
            snapshots[0].optimization.as_ref().unwrap().active_paths,
            vec![key]
        );
    }

    #[tokio::test]
    async fn runtime_snapshot_telemetry_has_a_bounded_deadline() {
        let stalled = std::future::pending::<Result<Vec<MpPathTelemetry>, TunnelError>>();
        let bounded = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            path_telemetry_with_deadline(stalled, std::time::Duration::from_millis(10)),
        )
        .await;

        let result = bounded.expect("snapshot helper must enforce its own deadline");
        let error = result.expect_err("stalled telemetry must report a timeout");
        assert!(error.to_string().contains("telemetry snapshot timed out"));
    }

    #[tokio::test]
    async fn runtime_snapshot_does_not_wait_for_a_busy_session_slot() {
        let manager = MpSessionManager::new(test_egress_quality_manager());
        let slot = Arc::new(Mutex::new(None));
        manager.sessions.insert(7, slot.clone());
        let _busy = slot.lock().await;

        let bounded = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            manager.runtime_snapshots(),
        )
        .await;

        let snapshots = bounded
            .expect("runtime observability must not wait for session establishment")
            .unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].peer_id, 7);
        assert!(snapshots[0].paths.is_empty());
    }

    #[tokio::test]
    async fn runtime_snapshot_still_sees_the_live_session_while_a_path_is_added() {
        let manager = Arc::new(MpSessionManager::new(test_egress_quality_manager()));
        let (handle, _driver) = MpSessionHandle::unanswered_for_test();
        manager.sessions.insert(
            7,
            Arc::new(Mutex::new(Some(Session {
                handle,
                congestion_control: CongestionControlProfile::Cubic,
                is_server: false,
            }))),
        );
        let a: SocketAddr = "127.0.0.1:41101".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:41102".parse().unwrap();
        let (path_a, _path_b) = channel_path_pair(a, b);
        let offering = tokio::spawn({
            let manager = manager.clone();
            async move {
                manager
                    .offer_path_spec(
                        7,
                        false,
                        path_spec(path_a, b),
                        "mpquic://127.0.0.1:41102".parse().unwrap(),
                        "mpquic_test",
                    )
                    .await
            }
        });
        // The driver never answers AddPath, so the offer stays in flight.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!offering.is_finished());

        let snapshots = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            manager.runtime_snapshots(),
        )
        .await
        .expect("snapshot must not wait for the in-flight path")
        .unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].effective_congestion_control, "cubic");
        offering.abort();
    }

    #[tokio::test]
    async fn manager_reuses_one_session_for_a_second_path() {
        let manager_a = Arc::new(MpSessionManager::new(test_egress_quality_manager()));
        let manager_b = Arc::new(MpSessionManager::new(test_egress_quality_manager()));
        let a1: SocketAddr = "127.0.0.1:41001".parse().unwrap();
        let b1: SocketAddr = "127.0.0.1:41002".parse().unwrap();
        let (path_a1, path_b1) = channel_path_pair(a1, b1);

        let server_manager = manager_b.clone();
        let server_path = path_b1.clone();
        let server = tokio::spawn(async move {
            server_manager
                .offer_path_spec(
                    1,
                    true,
                    path_spec(server_path, a1),
                    "mpquic://127.0.0.1:41001".parse().unwrap(),
                    "mpquic_test",
                )
                .await
        });
        let first_a = manager_a
            .offer_path_spec(
                2,
                false,
                path_spec(path_a1.clone(), b1),
                "mpquic://127.0.0.1:41002".parse().unwrap(),
                "mpquic_test",
            )
            .await;
        let first_a = first_a.unwrap_or_else(|error| {
            panic!(
                "client session failed: {error}; a sent={} recv={}, b sent={} recv={}",
                path_a1.sent.load(Ordering::Relaxed),
                path_a1.received.load(Ordering::Relaxed),
                path_b1.sent.load(Ordering::Relaxed),
                path_b1.received.load(Ordering::Relaxed),
            )
        });
        let OfferPathResult::NewTunnel(tunnel_a) = first_a else {
            panic!("first client path must create a tunnel");
        };
        let first_a_key = path_spec(path_a1.clone(), b1).key;
        assert_eq!(manager_a.tracked_candidate_count(2).await, 1);
        assert_eq!(
            manager_a.candidate_state(2, &first_a_key).await,
            Some(PathLifecycleState::AVAILABLE)
        );
        let (_client_recv, mut client_send) = tunnel_a.split();
        client_send
            .send(ZCPacket::new_with_payload(b"open server stream"))
            .await
            .unwrap();

        let first_b = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("server session did not observe the client stream")
            .unwrap()
            .unwrap_or_else(|error| {
                panic!(
                    "server session failed: {error}; a sent={} recv={}, b sent={} recv={}",
                    path_a1.sent.load(Ordering::Relaxed),
                    path_a1.received.load(Ordering::Relaxed),
                    path_b1.sent.load(Ordering::Relaxed),
                    path_b1.received.load(Ordering::Relaxed),
                )
            });
        let OfferPathResult::NewTunnel(_tunnel_b) = first_b else {
            panic!("first server path must create a tunnel");
        };

        let a2: SocketAddr = "127.0.0.1:41003".parse().unwrap();
        let b2: SocketAddr = "127.0.0.1:41004".parse().unwrap();
        let (path_a2, path_b2) = channel_path_pair(a2, b2);
        let second_a_key = path_spec(path_a2.clone(), b2).key;
        let (second_b, second_a) = tokio::join!(
            manager_b.offer_path_spec(
                1,
                true,
                path_spec(path_b2, a2),
                "mpquic://127.0.0.1:41003".parse().unwrap(),
                "mpquic_test",
            ),
            manager_a.offer_path_spec(
                2,
                false,
                path_spec(path_a2, b2),
                "mpquic://127.0.0.1:41004".parse().unwrap(),
                "mpquic_test",
            ),
        );
        assert!(matches!(second_a.unwrap(), OfferPathResult::PathAdded));
        assert!(matches!(second_b.unwrap(), OfferPathResult::PathAdded));
        assert_eq!(manager_a.tracked_peer_count(), 1);
        assert_eq!(manager_b.tracked_peer_count(), 1);

        let mut second_state = manager_a.candidate_state(2, &second_a_key).await;
        for _ in 0..50 {
            manager_a.refresh_path_telemetry(2).await.unwrap();
            second_state = manager_a.candidate_state(2, &second_a_key).await;
            if second_state != Some(PathLifecycleState::Validating) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(second_state.is_some_and(|state| state.is_established()));

        let mut runtime_config = gen_default_mp_config();
        runtime_config.enabled = true;
        manager_a.set_config(runtime_config).await.unwrap();
        assert!(
            manager_a
                .apply_path_events(2, vec![MpPathEvent::Down(second_a_key)])
                .await
        );
        let down_snapshot = manager_a
            .run_control_tick()
            .await
            .unwrap()
            .snapshots
            .into_iter()
            .next()
            .expect("active MP peer must produce an optimization snapshot");
        assert_eq!(manager_a.candidate_state(2, &second_a_key).await, None);
        assert_eq!(manager_a.tracked_candidate_count(2).await, 1);
        // The path that died carried none of the session's data (it only
        // validated, then died: standby): the active path is untouched
        // (draft-ietf-quic-multipath Section 3.3/3.4).
        assert_eq!(down_snapshot.active_paths, vec![first_a_key]);
        let duplicate_down = manager_a
            .handle_path_down(2, &second_a_key, 1, &[], &[])
            .await;
        assert!(matches!(
            duplicate_down,
            Err(TunnelError::InternalError(message)) if message.contains("is not tracked")
        ));
        let remaining = manager_a.refresh_path_telemetry(2).await.unwrap();
        assert!(
            remaining
                .iter()
                .all(|path| (path.local_addr, path.remote_addr)
                    != (second_a_key.local_addr, second_a_key.remote_addr))
        );
    }

    /// Exercise the production retry path against real connection-ID exhaustion,
    /// not a synthetic OpenAttempt: opening a path succeeds after an old path
    /// drains, without replacing the connection or losing its payload stream.
    #[tokio::test]
    async fn a_refused_real_udp_path_opens_after_a_slot_is_released() {
        use futures::{SinkExt, StreamExt};
        let a = Arc::new(MpSessionManager::new(test_egress_quality_manager()));
        let b = Arc::new(MpSessionManager::new(test_egress_quality_manager()));
        let (first_a, first_b) = real_udp_mp_path_pair().await;
        let server = {
            let b = b.clone();
            tokio::spawn(async move {
                b.offer_path_spec(1, true, first_b.clone(), mpquic_url(&first_b), "mpquic_test").await
            })
        };
        let OfferPathResult::NewTunnel(client_tunnel) = a
            .offer_path_spec(2, false, first_a.clone(), mpquic_url(&first_a), "mpquic_test")
            .await.unwrap() else { panic!("initial client tunnel") };
        let (mut client_recv, mut client_send) = client_tunnel.split();
        client_send.send(ZCPacket::new_with_payload(b"bootstrap")).await.unwrap();
        let OfferPathResult::NewTunnel(server_tunnel) = tokio::time::timeout(
            std::time::Duration::from_secs(10), server,
        ).await.unwrap().unwrap().unwrap() else { panic!("initial server tunnel") };
        let (mut server_recv, mut server_send) = server_tunnel.split();
        let bootstrap = tokio::time::timeout(std::time::Duration::from_secs(5), server_recv.next())
            .await.unwrap().unwrap().unwrap();
        server_send.send(bootstrap).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), client_recv.next()).await.unwrap().unwrap().unwrap();

        let mut mounted = Vec::new();
        let mut queued = None;
        for i in 2..=20 {
            let (spec_a, spec_b) = real_udp_mp_path_pair_from(&format!("127.0.0.{i}")).await;
            let key = spec_a.key;
            b.offer_path_spec(1, true, spec_b.clone(), mpquic_url(&spec_b), "mpquic_test").await.unwrap();
            a.offer_path_spec(2, false, spec_a.clone(), mpquic_url(&spec_a), "mpquic_test").await.unwrap();
            if a.pending_path_opens.contains_key(&(2, key)) {
                queued = Some(key);
                break;
            }
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    if a.refresh_path_telemetry(2).await.unwrap().iter().any(|p|
                        p.local_addr == key.local_addr && p.remote_addr == key.remote_addr
                            && p.validation_state == tquic::PathState::Validated) { break; }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }).await.expect("mounted UDP path validates");
            mounted.push(key);
        }
        let queued = queued.expect("real connection exhausts its path slots");
        assert!(!mounted.is_empty());
        let slot = a.sessions.get(&2).unwrap().clone();
        let handle = MpSessionManager::session_handle(&slot).await.unwrap();
        let removed = mounted.pop().unwrap();
        handle.remove_path(removed.local_addr, removed.remote_addr).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let paths = a.refresh_path_telemetry(2).await.unwrap();
                if paths.iter().any(|p| p.local_addr == queued.local_addr && p.remote_addr == queued.remote_addr
                    && p.validation_state == tquic::PathState::Validated)
                    && !a.pending_path_opens.contains_key(&(2, queued)) { break; }
                assert!(!handle.is_closed(), "slot recovery must keep the session alive");
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }).await.expect("queued path opens once a real slot drains");
        let payload = b"payload after connection-ID recovery";
        client_send.send(ZCPacket::new_with_payload(payload)).await.unwrap();
        let packet = tokio::time::timeout(std::time::Duration::from_secs(5), server_recv.next())
            .await.unwrap().unwrap().unwrap();
        assert_eq!(packet.payload(), payload);
        server_send.send(packet).await.unwrap();
        let echoed = tokio::time::timeout(std::time::Duration::from_secs(5), client_recv.next())
            .await.unwrap().unwrap().unwrap();
        assert_eq!(echoed.payload(), payload);
        a.forget_peer(2).await;
        b.forget_peer(1).await;
    }

    async fn real_udp_mp_path_pair() -> (MpPathSpec, MpPathSpec) {
        real_udp_mp_path_pair_from("127.0.0.1").await
    }

    /// `client_ip` picks the client side's loopback address: two punched
    /// paths observed from the same IP are one WAN to S2.14 dedup, so a
    /// test wanting two distinct paths binds the second one elsewhere.
    async fn real_udp_mp_path_pair_from(client_ip: &str) -> (MpPathSpec, MpPathSpec) {
        let socket_a = Arc::new(tokio::net::UdpSocket::bind((client_ip, 0)).await.unwrap());
        let socket_b = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();
        let provider_a = UdpMpPathProvider::new(CarrierKind::UdpPunch, socket_a, addr_b, None)
            .unwrap();
        let provider_b = UdpMpPathProvider::new(CarrierKind::UdpPunch, socket_b, addr_a, None)
            .unwrap();
        let mut specs_a = provider_a.discover().await.unwrap();
        let mut specs_b = provider_b.discover().await.unwrap();
        assert_eq!(specs_a.len(), 1);
        assert_eq!(specs_b.len(), 1);
        (specs_a.pop().unwrap(), specs_b.pop().unwrap())
    }

    fn mpquic_url(spec: &MpPathSpec) -> url::Url {
        format!("mpquic://{}", spec.key.remote_addr).parse().unwrap()
    }

    /// Both ends punched as client at once. Each end used to run its own
    /// outgoing handshake and queue the incoming one behind it, so both
    /// timed out together, round after round. Now both ends give way to the
    /// lower peer id's outgoing session, well within one timeout, and the
    /// other direction's carrier joins it as a second path instead of being
    /// thrown away.
    #[tokio::test]
    async fn simultaneous_opens_from_both_ends_settle_on_the_lower_peer_ids_session() {
        let manager_a = Arc::new(
            MpSessionManager::new(test_egress_quality_manager()).with_local_peer_id(1),
        );
        let manager_b = Arc::new(
            MpSessionManager::new(test_egress_quality_manager()).with_local_peer_id(2),
        );
        // Pair 1 carries A's outgoing session, pair 2 carries B's.
        let (a_out, b_in) = real_udp_mp_path_pair().await;
        let (b_out, a_in) = real_udp_mp_path_pair_from("127.0.0.2").await;
        let started = std::time::Instant::now();
        let offer = |manager: &Arc<MpSessionManager>, peer, is_server, spec: MpPathSpec| {
            let manager = manager.clone();
            let url = mpquic_url(&spec);
            tokio::spawn(async move {
                manager
                    .offer_path_spec(peer, is_server, spec, url, "mpquic_test")
                    .await
            })
        };
        let a_client = offer(&manager_a, 2, false, a_out);
        let a_server = offer(&manager_a, 2, true, a_in);
        let b_client = offer(&manager_b, 1, false, b_out);
        let b_server = offer(&manager_b, 1, true, b_in);

        let wait = std::time::Duration::from_secs(5);
        let OfferPathResult::NewTunnel(tunnel_a) =
            tokio::time::timeout(wait, a_client).await.unwrap().unwrap().unwrap()
        else {
            panic!("the lower peer id's outgoing session must be created");
        };
        let (_a_recv, mut a_send) = tunnel_a.split();
        a_send
            .send(ZCPacket::new_with_payload(b"open server stream"))
            .await
            .unwrap();
        a_send.flush().await.unwrap();
        let OfferPathResult::NewTunnel(tunnel_b) =
            tokio::time::timeout(wait, b_server).await.unwrap().unwrap().unwrap()
        else {
            panic!("the higher peer id must accept the lower one's session");
        };
        let (mut b_recv, _b_send) = tunnel_b.split();
        let opened = tokio::time::timeout(wait, b_recv.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(opened.payload(), b"open server stream");

        // The other direction's offers never settle on their own session: they
        // join the preferred one, or finish first and are replaced by it.
        for (label, offer) in [("A's incoming", a_server), ("B's outgoing", b_client)] {
            let result = tokio::time::timeout(wait, offer).await.unwrap().unwrap();
            assert!(result.is_ok(), "{label} offer must not fail: {:?}", result.err());
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the collision must not wait out an establishment timeout"
        );
    }

    /// The collision as it happens on a real link: the higher peer id's
    /// outgoing handshake finishes first, and only then the lower id's own
    /// session starts. Both ends must still end on the lower id's outgoing
    /// session (the same decision from the peer ids alone), whichever handshake
    /// completed first: the higher id's end may not keep its completed client
    /// session while the lower id's end drops its counterpart.
    #[tokio::test]
    async fn a_completed_session_of_the_other_direction_gives_way_to_the_preferred_one() {
        let manager_a = Arc::new(
            MpSessionManager::new(test_egress_quality_manager()).with_local_peer_id(1),
        );
        let manager_b = Arc::new(
            MpSessionManager::new(test_egress_quality_manager()).with_local_peer_id(2),
        );
        // Pair 1 carries B's outgoing session, pair 2 carries A's.
        let (b_out, a_in) = real_udp_mp_path_pair().await;
        let (a_out, b_in) = real_udp_mp_path_pair_from("127.0.0.2").await;
        let offer = |manager: &Arc<MpSessionManager>, peer, is_server, spec: MpPathSpec| {
            let manager = manager.clone();
            let url = mpquic_url(&spec);
            tokio::spawn(async move {
                manager
                    .offer_path_spec(peer, is_server, spec, url, "mpquic_test")
                    .await
            })
        };
        let a_server = offer(&manager_a, 2, true, a_in);
        let b_client = offer(&manager_b, 1, false, b_out);
        let wait = std::time::Duration::from_secs(5);
        let OfferPathResult::NewTunnel(tunnel_b) =
            tokio::time::timeout(wait, b_client).await.unwrap().unwrap().unwrap()
        else {
            panic!("the higher peer id's outgoing session is created when it is alone");
        };
        // A's server has completed the QUIC handshake by now, and waits for
        // the first stream data.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let a_client = offer(&manager_a, 2, false, a_out);
        let b_server = offer(&manager_b, 1, true, b_in);

        let OfferPathResult::NewTunnel(tunnel_a2) =
            tokio::time::timeout(wait, a_client).await.unwrap().unwrap().unwrap()
        else {
            panic!("the lower peer id's outgoing session must be created");
        };
        let (_a_recv, mut a_send) = tunnel_a2.split();
        a_send
            .send(ZCPacket::new_with_payload(b"preferred session"))
            .await
            .unwrap();
        a_send.flush().await.unwrap();
        let OfferPathResult::NewTunnel(tunnel_b2) =
            tokio::time::timeout(wait, b_server).await.unwrap().unwrap().unwrap()
        else {
            panic!("the higher peer id must take the lower one's session, not join its own");
        };
        let (mut b_recv, _b_send) = tunnel_b2.split();
        let got = tokio::time::timeout(wait, b_recv.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(got.payload(), b"preferred session");
        // The dropped direction's offer ends, its carrier joined the session.
        tokio::time::timeout(wait, a_server).await.unwrap().unwrap().unwrap();
        drop(tunnel_b);
    }

    /// EasyTier peers are equals: the direction both ends give way to on a
    /// collision must never be the only one that can connect them. With no
    /// collision, the higher peer id's outgoing session comes up at once.
    #[tokio::test]
    async fn the_higher_peer_id_alone_can_still_open_the_session() {
        let lower = Arc::new(
            MpSessionManager::new(test_egress_quality_manager()).with_local_peer_id(1),
        );
        let higher = Arc::new(
            MpSessionManager::new(test_egress_quality_manager()).with_local_peer_id(2),
        );
        let (higher_out, lower_in) = real_udp_mp_path_pair().await;
        let lower_url = mpquic_url(&lower_in);
        let lower_task = tokio::spawn({
            let lower = lower.clone();
            async move {
                lower
                    .offer_path_spec(2, true, lower_in, lower_url, "mpquic_test")
                    .await
            }
        });
        let wait = std::time::Duration::from_secs(5);
        let OfferPathResult::NewTunnel(tunnel) = tokio::time::timeout(
            wait,
            higher.offer_path_spec(1, false, higher_out.clone(), mpquic_url(&higher_out), "mpquic_test"),
        )
        .await
        .unwrap()
        .unwrap() else {
            panic!("the higher peer id's outgoing session must be created");
        };
        let (_recv, mut send) = tunnel.split();
        send.send(ZCPacket::new_with_payload(b"open server stream"))
            .await
            .unwrap();
        send.flush().await.unwrap();
        assert!(matches!(
            tokio::time::timeout(wait, lower_task).await.unwrap().unwrap(),
            Ok(OfferPathResult::NewTunnel(_))
        ));
    }

    /// A handshake to a peer that never answers runs for the whole
    /// establishment timeout. It must not hold the session slot meanwhile:
    /// the control tick and peer teardown take it every second.
    #[tokio::test]
    async fn control_tick_and_forget_peer_do_not_wait_for_a_pending_handshake() {
        let manager = Arc::new(MpSessionManager::new(test_egress_quality_manager()));
        let (spec, _silent_peer) = real_udp_mp_path_pair().await;
        let url = mpquic_url(&spec);
        let pending = tokio::spawn({
            let manager = manager.clone();
            async move {
                manager
                    .offer_path_spec(2, false, spec, url, "mpquic_test")
                    .await
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!pending.is_finished(), "the silent peer must keep the handshake pending");

        let quick = std::time::Duration::from_secs(1);
        tokio::time::timeout(quick, manager.run_control_tick())
            .await
            .expect("control tick blocked behind a pending handshake")
            .unwrap();
        tokio::time::timeout(quick, manager.forget_peer(2))
            .await
            .expect("forget_peer blocked behind a pending handshake");
        pending.abort();
    }

    /// MP_SQM_PLAN.md S2.3 RED spec: gray-box, two real UDP paths, pause one
    /// -- its `sent_bytes` data increment must be 0 and it must stay
    /// Validated. Both carriers are real `tokio::net::UdpSocket`s driving a
    /// real MPQUIC session end to end (real handshake, real payload); only
    /// the second path's measured round trip is set directly (a path nobody
    /// has sent on has none), so the first path is the one selected -- and
    /// the second must stay quiet because it is paused. The real
    /// `select_active_paths` -> `build_path_targets` -> `set_path_targets` ->
    /// TQUIC scheduler pipeline is exercised unmodified.
    #[tokio::test]
    async fn pause_policy_on_a_real_udp_path_stops_new_bytes_while_it_stays_validated() {
        let manager_a = Arc::new(MpSessionManager::new(test_egress_quality_manager()));
        let manager_b = Arc::new(MpSessionManager::new(test_egress_quality_manager()));

        // Primary real UDP path establishes the actual MPQUIC session.
        let (spec_a1, spec_b1) = real_udp_mp_path_pair().await;
        let first_a_key = spec_a1.key;
        let spec_a1_remote_url: url::Url =
            format!("mpquic://{}", spec_a1.key.remote_addr).parse().unwrap();
        let spec_b1_remote_url: url::Url =
            format!("mpquic://{}", spec_b1.key.remote_addr).parse().unwrap();
        let server_manager = manager_b.clone();
        let server = tokio::spawn(async move {
            server_manager
                .offer_path_spec(1, true, spec_b1, spec_b1_remote_url, "mpquic_test")
                .await
        });
        let first_a = manager_a
            .offer_path_spec(2, false, spec_a1, spec_a1_remote_url, "mpquic_test")
            .await
            .unwrap();
        let OfferPathResult::NewTunnel(tunnel_a) = first_a else {
            panic!("first client path must create a tunnel");
        };
        let (mut client_recv, mut client_send) = tunnel_a.split();
        client_send
            .send(ZCPacket::new_with_payload(b"open server stream"))
            .await
            .unwrap();
        client_send.flush().await.unwrap();

        let first_b = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("server session did not observe the client stream")
            .unwrap()
            .unwrap();
        let OfferPathResult::NewTunnel(server_tunnel) = first_b else {
            panic!("first server path must create a tunnel");
        };
        let (mut server_recv, mut server_send) = server_tunnel.split();
        let opened = tokio::time::timeout(std::time::Duration::from_secs(5), server_recv.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(opened.payload(), b"open server stream");

        // Drive enough real payload over the primary path alone to get a
        // genuine round-trip sample for the selector.
        const WARMUP_PACKETS: usize = 64;
        let warmup_payload = vec![b'w'; 900];
        let warmup_echo = tokio::spawn({
            async move {
                for _ in 0..WARMUP_PACKETS {
                    let packet = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        server_recv.next(),
                    )
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                    server_send.send(packet).await.unwrap();
                }
                server_send.flush().await.unwrap();
                (server_recv, server_send)
            }
        });
        for _ in 0..WARMUP_PACKETS {
            client_send
                .send(ZCPacket::new_with_payload(&warmup_payload))
                .await
                .unwrap();
        }
        client_send.flush().await.unwrap();
        for _ in 0..WARMUP_PACKETS {
            tokio::time::timeout(std::time::Duration::from_secs(5), client_recv.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
        let (mut server_recv, mut server_send) = warmup_echo.await.unwrap();

        let mut first_state = manager_a.candidate_state(2, &first_a_key).await;
        for _ in 0..100 {
            manager_a.refresh_path_telemetry(2).await.unwrap();
            first_state = manager_a.candidate_state(2, &first_a_key).await;
            if first_state.is_some_and(|state| state.is_established()) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            first_state.is_some_and(|state| state.is_established()),
            "primary path must be established, got {first_state:?}"
        );

        // Second real UDP path, from a second loopback address so S2.14
        // dedup sees a distinct WAN instead of retiring it as a duplicate.
        let (spec_a2, spec_b2) = real_udp_mp_path_pair_from("127.0.0.2").await;
        let second_a_key = spec_a2.key;
        let spec_a2_remote_url: url::Url =
            format!("mpquic://{}", spec_a2.key.remote_addr).parse().unwrap();
        let spec_b2_remote_url: url::Url =
            format!("mpquic://{}", spec_b2.key.remote_addr).parse().unwrap();
        let (second_b, second_a) = tokio::join!(
            manager_b.offer_path_spec(1, true, spec_b2, spec_b2_remote_url, "mpquic_test"),
            manager_a.offer_path_spec(2, false, spec_a2, spec_a2_remote_url, "mpquic_test"),
        );
        assert!(matches!(second_a.unwrap(), OfferPathResult::PathAdded));
        assert!(matches!(second_b.unwrap(), OfferPathResult::PathAdded));

        // Wait for the real TQUIC path validation handshake (PATH_CHALLENGE/
        // RESPONSE) to complete over the real second UDP socket pair.
        let mut validated = false;
        for _ in 0..100 {
            let telemetry = manager_a.refresh_path_telemetry(2).await.unwrap();
            if telemetry.iter().any(|path| {
                path.local_addr == second_a_key.local_addr
                    && path.remote_addr == second_a_key.remote_addr
                    && path.validation_state == tquic::PathState::Validated
            }) {
                validated = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(validated, "second real UDP path must complete TQUIC validation");

        // A slow measured round trip, so the selector keeps the first path;
        // the transport underneath stays real for everything that follows.
        {
            let candidate_slot = manager_a.candidates.get(&2).unwrap().clone();
            let mut candidates = candidate_slot.lock().await;
            candidates.observe_measurements(
                &second_a_key,
                PathMeasurements {
                    btlbw: 5_000_000,
                    delivery_rate: 4_500_000,
                    propagation_rtt_micros: 500_000,
                    loss_rate: 0.0,
                    app_limited: false,
                    sample_age_micros: Some(1_000),
                    congestion_control_state: tquic::CongestionControlState::ProbeBandwidth,
                    observed_local_addr: None,
                },
            );
        }
        assert_eq!(
            manager_a.candidate_state(2, &second_a_key).await,
            Some(PathLifecycleState::AVAILABLE)
        );

        let mut config = gen_default_mp_config();
        config.enabled = true;
        config.path_policies = vec![MpPathPolicy {
            match_egress_device: String::new(),
            match_carrier_kind: String::new(),
            match_remote_endpoint: second_a_key.remote_addr.to_string(),
            action: "pause".to_string(),
            prefer_weight: 1.0,
            enabled: true,
            note: String::new(),
        }];
        manager_a.set_config(config).await.unwrap();
        let tick = manager_a.run_control_tick().await.unwrap();
        let snapshot = tick
            .snapshots
            .into_iter()
            .next()
            .expect("MP peer must produce an optimization snapshot");
        let second_target = snapshot
            .targets
            .iter()
            .find(|target| {
                target.local_addr == second_a_key.local_addr
                    && target.remote_addr == second_a_key.remote_addr
            })
            .expect("paused path must still receive a scheduler target, just zeroed");
        assert_eq!(
            second_target.rate,
            Some(0),
            "a paused path's scheduler target must be zeroed"
        );

        let telemetry_before = manager_a.refresh_path_telemetry(2).await.unwrap();
        let sent_before = telemetry_before
            .iter()
            .find(|path| {
                path.local_addr == second_a_key.local_addr
                    && path.remote_addr == second_a_key.remote_addr
            })
            .map(|path| path.sent_bytes)
            .expect("paused path telemetry must still be reported");

        // Real application traffic through the tunnel -- must not land on
        // the paused path. Keep the server tunnel halves alive past the
        // echo loop with a oneshot release gate: dropping them right after
        // the last `flush` would send a FIN and race this test's final
        // telemetry sample against the client driver tearing itself down
        // (mirrors `mpquic_real_udp_two_path_payload_and_telemetry` in
        // tunnel::mpquic).
        const PACKETS: usize = 64;
        let payload = vec![b'x'; 900];
        let (release_echo, keep_echo_alive) = tokio::sync::oneshot::channel();
        let echo = tokio::spawn(async move {
            for _ in 0..PACKETS {
                let packet =
                    tokio::time::timeout(std::time::Duration::from_secs(5), server_recv.next())
                        .await
                        .unwrap()
                        .unwrap()
                        .unwrap();
                server_send.send(packet).await.unwrap();
            }
            server_send.flush().await.unwrap();
            let _ = keep_echo_alive.await;
        });
        for _ in 0..PACKETS {
            client_send
                .send(ZCPacket::new_with_payload(&payload))
                .await
                .unwrap();
        }
        client_send.flush().await.unwrap();
        for _ in 0..PACKETS {
            tokio::time::timeout(std::time::Duration::from_secs(5), client_recv.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }

        let telemetry_after = manager_a.refresh_path_telemetry(2).await.unwrap();
        let (sent_after, validation_after) = telemetry_after
            .iter()
            .find(|path| {
                path.local_addr == second_a_key.local_addr
                    && path.remote_addr == second_a_key.remote_addr
            })
            .map(|path| (path.sent_bytes, path.validation_state))
            .expect("paused path telemetry must still be reported after real traffic");
        let _ = release_echo.send(());
        echo.await.unwrap();

        // The paused path still acknowledges what the peer sends on it (pure
        // ACK packets, tens of bytes each), but none of the 64 x 900 B payload.
        assert!(
            sent_after - sent_before < 4096,
            "a paused path must not carry any of the new application traffic: {sent_before} -> {sent_after}"
        );
        assert_eq!(
            validation_after,
            tquic::PathState::Validated,
            "pausing a path must not undo its TQUIC validation"
        );
    }

    /// MP_SQM_PLAN.md S2.4 rate negotiation (consume half), gray-box: proves
    /// the whole chain end to end on a real TQUIC path -- `set_remote_rx_bps_
    /// lookup` -> `select_active_paths`'s `clamp_targets_to_peer_rx_cap` ->
    /// `set_path_target_rate` -> `Path::set_scheduler_target_rate` ->
    /// Brutal's own `effective_bps` clamp -- not just the pure clamp function
    /// (tested above in isolation) or the TQUIC-side unit tests
    /// (`vendor/tquic/.../brutal.rs`) alone.
    ///
    /// `TQUIC's `Path::stats()` recomputes `pacing_rate` fresh from the live
    /// `CongestionController` on every read (`stat_lazy_update`, no ack cycle
    /// needed), and Brutal's `ack_rate` stays at its untouched initial `1.0`
    /// throughout this test (no acks/losses are ever recorded), so `pacing_
    /// rate_bps` reads back exactly `effective_bps * 8` with no measurement
    /// noise -- the assertions below use generous bounds anyway, in case a
    /// future change makes the budget share itself the binding constraint
    /// instead of Brutal's own ceiling/the peer cap.
    #[tokio::test]
    async fn brutal_path_rate_follows_a_negotiated_peer_rx_cap_and_recovers_when_it_clears() {
        let up_mbps = 20.0;
        let mut config = gen_default_mp_config();
        config.congestion_control = "brutal".to_string();
        config.congestion_control_params_json = format!(r#"{{"up_mbps": {up_mbps}}}"#);
        let manager_a = Arc::new(MpSessionManager::new_with_config(
            config.clone(),
            test_egress_quality_manager(),
        ));
        let manager_b = Arc::new(MpSessionManager::new_with_config(
            config,
            test_egress_quality_manager(),
        ));

        let (spec_a, spec_b) = real_udp_mp_path_pair().await;
        let key = spec_a.key;
        let remote_url_a: url::Url = format!("mpquic://{}", spec_a.key.remote_addr)
            .parse()
            .unwrap();
        let remote_url_b: url::Url = format!("mpquic://{}", spec_b.key.remote_addr)
            .parse()
            .unwrap();

        let server_manager = manager_b.clone();
        let server = tokio::spawn(async move {
            server_manager
                .offer_path_spec(1, true, spec_b, remote_url_b, "mpquic_test")
                .await
        });
        let client_result = manager_a
            .offer_path_spec(2, false, spec_a, remote_url_a, "mpquic_test")
            .await
            .unwrap();
        let OfferPathResult::NewTunnel(tunnel_a) = client_result else {
            panic!("first client path must create a tunnel");
        };
        let (client_recv, mut client_send) = tunnel_a.split();
        client_send
            .send(ZCPacket::new_with_payload(b"open server stream"))
            .await
            .unwrap();
        client_send.flush().await.unwrap();
        let server_result = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("server session did not observe the client stream")
            .unwrap()
            .unwrap();
        let OfferPathResult::NewTunnel(server_tunnel) = server_result else {
            panic!("first server path must create a tunnel");
        };
        let (mut server_recv, server_send) = server_tunnel.split();
        let opened = tokio::time::timeout(std::time::Duration::from_secs(5), server_recv.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(opened.payload(), b"open server stream");
        // Keep both halves of the server tunnel alive for the rest of the
        // test (dropping either would send a FIN and tear the session down).
        let _server_recv = server_recv;
        let _server_send = server_send;
        let _client_recv = client_recv;

        // The path is established with a large measured bandwidth, so only
        // `up_mbps` and the peer cap this test injects below are ever the
        // binding constraint on the observed pacing rate.
        {
            let candidate_slot = manager_a.candidates.get(&2).unwrap().clone();
            let mut candidates = candidate_slot.lock().await;
            candidates.set_state(&key, PathLifecycleState::AVAILABLE);
            candidates.observe_measurements(
                &key,
                PathMeasurements {
                    btlbw: 200_000_000,
                    delivery_rate: 200_000_000,
                    propagation_rtt_micros: 1_000,
                    loss_rate: 0.0,
                    app_limited: false,
                    sample_age_micros: Some(1_000),
                    congestion_control_state: tquic::CongestionControlState::ProbeBandwidth,
                    observed_local_addr: None,
                },
            );
        }
        assert_eq!(
            manager_a.candidate_state(2, &key).await,
            Some(PathLifecycleState::AVAILABLE)
        );

        let pacing_bps_for = |manager: &Arc<MpSessionManager>, key: PathKey| {
            let manager = manager.clone();
            async move {
                manager
                    .refresh_path_telemetry(2)
                    .await
                    .unwrap()
                    .into_iter()
                    .find(|path| path.local_addr == key.local_addr && path.remote_addr == key.remote_addr)
                    .map(|path| path.pacing_rate_bps)
            }
        };

        // No peer cap yet: pacing settles near the locally configured
        // up_mbps (where autorate starts), well above the 2 Mbit/s cap
        // injected below.
        manager_a
            .select_active_paths(2, 1, &[], &[])
            .await
            .unwrap();
        let pacing_without_cap = pacing_bps_for(&manager_a, key)
            .await
            .expect("path telemetry must be reported once established");
        assert!(
            pacing_without_cap >= 15_000_000,
            "expected pacing near the configured 20 Mbit/s without a peer cap, got {pacing_without_cap}"
        );

        // Inject a peer rx cap well below the configured up_mbps.
        let peer_cap_bps: u64 = 2_000_000;
        let cap_state = Arc::new(std::sync::Mutex::new(Some(peer_cap_bps)));
        {
            let cap_state = cap_state.clone();
            manager_a
                .set_remote_rx_bps_lookup(Some(Arc::new(move |_peer_id| *cap_state.lock().unwrap())))
                .await;
        }
        manager_a
            .select_active_paths(2, 1, &[], &[])
            .await
            .unwrap();
        let pacing_with_cap = pacing_bps_for(&manager_a, key)
            .await
            .expect("path telemetry must be reported once established");
        assert!(
            pacing_with_cap <= 4_000_000,
            "expected pacing capped near the 2 Mbit/s peer announcement, got {pacing_with_cap}"
        );

        // Clear the announcement: the rate must recover, not stay clamped.
        *cap_state.lock().unwrap() = None;
        manager_a
            .select_active_paths(2, 1, &[], &[])
            .await
            .unwrap();
        let pacing_recovered = pacing_bps_for(&manager_a, key)
            .await
            .expect("path telemetry must be reported once established");
        assert!(
            pacing_recovered >= 15_000_000,
            "expected pacing to recover to near 20 Mbit/s once the peer cap cleared, got {pacing_recovered}"
        );
    }

    /// MP_SQM_PLAN.md S2.2 follow-up (reported from a real two-core live
    /// run): `MpRuntimeInfo.egress` must be populated for a real MP-managed
    /// egress device, not just for a path with a real `EgressSocketBinding`
    /// (only tests build one since S2.14). The ordinary case -- a
    /// plain MP path whose `egress_resource`/`local_resource` device name
    /// came from interface auto-detection (`UdpMpPathProvider::discover`'s
    /// `get_interface_name_by_ip` fallback) -- never gets a binding, and
    /// `refresh_all_egress_capacities` used to require one unconditionally,
    /// so `mp_runtime.egress` came back empty even with live MP-managed
    /// paths and a static ceiling configured.
    ///
    /// Gray-box: one real loopback UDP path (real handshake, real payload)
    /// whose spec carries an explicit device name but no binding -- the
    /// same shape a real auto-detected path has -- a real
    /// `reconcile_egress_bindings` call (populating the new device-name
    /// index) with a synthetic single-interface inventory snapshot, a
    /// static ceiling applied before any traffic, then the same
    /// `refresh_all_egress_capacities` call `run_control_tick` makes.
    #[tokio::test]
    async fn mp_egress_runtime_snapshot_reports_static_ceiling_for_an_auto_detected_device() {
        let manager_a = Arc::new(MpSessionManager::new(test_egress_quality_manager()));
        let manager_b = Arc::new(MpSessionManager::new(test_egress_quality_manager()));

        let socket_a = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket_b = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();
        // `Some("wan-a")`, not `None`: this is the explicit-name form of the
        // same auto-detection outcome `get_interface_name_by_ip` would give
        // a real bound socket on a real NIC, without depending on this
        // test's own loopback interface's OS name.
        let provider_a = UdpMpPathProvider::new(
            CarrierKind::UdpPunch,
            socket_a,
            addr_b,
            Some("wan-a".to_string()),
        )
        .unwrap();
        let provider_b = UdpMpPathProvider::new(CarrierKind::UdpPunch, socket_b, addr_a, None)
            .unwrap();
        let spec_a = provider_a.discover().await.unwrap().pop().unwrap();
        let spec_b = provider_b.discover().await.unwrap().pop().unwrap();
        assert!(
            spec_a.egress_binding.is_none(),
            "sanity: an auto-detected device name alone must not synthesize a binding"
        );
        let spec_a_remote_url: url::Url =
            format!("mpquic://{}", spec_a.key.remote_addr).parse().unwrap();
        let spec_b_remote_url: url::Url =
            format!("mpquic://{}", spec_b.key.remote_addr).parse().unwrap();

        // A static ceiling applied before any traffic -- mirrors a real
        // core's `--egress-wire-limit-bps`.
        manager_a.egress_quality.set_static_ceiling(
            Some(WireBitrate(20_000_000)),
            HashMap::new(),
        );

        let wan_a_id = crate::common::egress_inventory::EgressStableId::Linux {
            netns_inode: 1,
            ifindex: 51,
        };
        let snapshot = crate::common::egress_inventory::EgressInventorySnapshot {
            revision: 1,
            observed_at_unix_ms: 1,
            interfaces: std::collections::BTreeMap::from([(
                wan_a_id.clone(),
                inventory_interface(wan_a_id, "wan-a", 1, "127.0.0.1".parse().unwrap()),
            )]),
        };
        assert_eq!(
            manager_a.reconcile_egress_bindings(&snapshot).await.unwrap(),
            0,
            "no candidate exists yet, so nothing should be retired by this reconcile"
        );

        let server_manager = manager_b.clone();
        let server = tokio::spawn(async move {
            server_manager
                .offer_path_spec(1, true, spec_b, spec_b_remote_url, "mpquic_test")
                .await
        });
        let first_a = manager_a
            .offer_path_spec(2, false, spec_a, spec_a_remote_url, "mpquic_test")
            .await
            .unwrap();
        let OfferPathResult::NewTunnel(tunnel_a) = first_a else {
            panic!("first client path must create a tunnel");
        };
        let (mut client_recv, mut client_send) = tunnel_a.split();
        client_send
            .send(ZCPacket::new_with_payload(b"egress runtime probe"))
            .await
            .unwrap();
        client_send.flush().await.unwrap();

        let first_b = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("server session did not observe the client stream")
            .unwrap()
            .unwrap();
        let OfferPathResult::NewTunnel(server_tunnel) = first_b else {
            panic!("first server path must create a tunnel");
        };
        let (mut server_recv, mut server_send) = server_tunnel.split();
        let (release_echo, keep_echo_alive) = tokio::sync::oneshot::channel();
        let echo = tokio::spawn(async move {
            let packet = tokio::time::timeout(std::time::Duration::from_secs(5), server_recv.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            server_send.send(packet).await.unwrap();
            server_send.flush().await.unwrap();
            let _ = keep_echo_alive.await;
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), client_recv.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        manager_a
            .refresh_all_egress_capacities(1_000_000)
            .await
            .unwrap();
        let egress = manager_a.egress_resource_snapshots();

        assert!(
            !egress.is_empty(),
            "a real MP-managed path on a real (auto-detected) egress device must report at \
             least one egress resource, even with no explicit multi-NIC EgressSocketBinding"
        );
        let wan_a = egress
            .iter()
            .find(|estimate| estimate.egress_device == "wan-a")
            .expect("the auto-detected device must be reported by its plain interface name");
        assert_eq!(wan_a.ceiling_bps, Some(WireBitrate(20_000_000)));
        assert_eq!(wan_a.ceiling_source.as_str(), "static");
        assert!(!wan_a.fallback_scope, "a real resolved interface identity is not a fallback");
        // MP_SQM_PLAN.md S2.5 §9 `MpEgressResourceStatus.autorate_estimate_bps`:
        // the estimator must have already produced a value from the
        // `publish_sample` call inside this same `refresh_all_egress_capacities`.
        assert!(
            wan_a.autorate_estimate_bps.is_some(),
            "autorate must estimate this scope's bandwidth"
        );
        // The carrier is governed by the NIC scope this sampling resolves:
        // without a binding it used to land on `EgressStableId::Fallback`, so
        // the resolved scope's handle never saw a byte (and a per-NIC limit or
        // an autorate estimate published to it never reached the sends).
        let nic_scope = EgressScope::from_resolved_route(
            crate::common::egress_inventory::EgressStableId::Linux {
                netns_inode: 1,
                ifindex: 51,
            },
            1,
            EgressDirection::Egress,
        );
        assert!(
            crate::tunnel::mpquic::cake_status(&manager_a.egress_quality.handle_for(nic_scope))
                .is_some_and(|cake| cake.sent_packets > 0),
            "the probe's sends must be charged to the resolved NIC scope"
        );

        // Keep the server halves alive until the last refresh: dropping them
        // sends FIN and races the client driver's exit against the telemetry
        // request (same as `pause_policy_on_a_real_udp_path_...`).
        let _ = release_echo.send(());
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn manual_paths_reconcile_once_and_config_removal_retires_the_path() {
        fn free_udp_port() -> u16 {
            std::net::UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        }

        let a_port = free_udp_port();
        let b_port = free_udp_port();
        let source_a = format!("mp+udp://127.0.0.1:{b_port}?peer_id=2&bind=127.0.0.1:{a_port}");
        let source_b = format!("mp+udp://127.0.0.1:{a_port}?peer_id=1&bind=127.0.0.1:{b_port}");
        let mut config_a = gen_default_mp_config();
        config_a.enabled = true;
        config_a.providers.push("manual".into());
        config_a.manual_paths = vec![source_a.clone()];
        let mut config_b = config_a.clone();
        config_b.manual_paths = vec![source_b];

        let manager_a = Arc::new(MpSessionManager::new_with_config(
            config_a.clone(),
            test_egress_quality_manager(),
        ));
        let manager_b = Arc::new(MpSessionManager::new_with_config(
            config_b,
            test_egress_quality_manager(),
        ));
        let global_a = crate::common::global_ctx::tests::get_mock_global_ctx();
        let global_b = crate::common::global_ctx::tests::get_mock_global_ctx();

        let server_manager = manager_b.clone();
        let server =
            tokio::spawn(async move { server_manager.reconcile_manual_paths(&global_b, 2).await });
        let mut client_offers = manager_a
            .reconcile_manual_paths(&global_a, 1)
            .await
            .unwrap();
        assert_eq!(client_offers.len(), 1);
        let OfferPathResult::NewTunnel(tunnel_a) = client_offers.pop().unwrap().outcome else {
            panic!("first manual client path must create a TQUIC tunnel");
        };
        let (_recv, mut send) = tunnel_a.split();
        send.send(ZCPacket::new_with_payload(b"open manual server stream"))
            .await
            .unwrap();

        let server_offers = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("manual server path did not complete")
            .unwrap()
            .unwrap();
        assert_eq!(server_offers.len(), 1);
        assert!(matches!(
            server_offers.into_iter().next().unwrap().outcome,
            OfferPathResult::NewTunnel(_)
        ));
        assert!(manager_a.has_live_carrier(2, CarrierKind::Manual).await);

        assert!(
            manager_a
                .reconcile_manual_paths(&global_a, 1)
                .await
                .unwrap()
                .is_empty(),
            "an unchanged manual path must not create a duplicate carrier"
        );

        config_a.manual_paths.clear();
        manager_a.set_config(config_a).await.unwrap();
        manager_a
            .reconcile_manual_paths(&global_a, 1)
            .await
            .unwrap();
        assert!(!manager_a.has_live_carrier(2, CarrierKind::Manual).await);
    }

    #[test]
    fn relay_next_hop_accepts_validating_mtu_as_peer_reachability() {
        assert_eq!(
            path_validation_decision(tquic::PathState::Validated, CarrierKind::RelayNextHop),
            Some(true)
        );
        assert_eq!(
            path_validation_decision(tquic::PathState::ValidatingMTU, CarrierKind::RelayNextHop),
            Some(true),
            "virtual ULA relay paths must not wait forever on PMTU probe"
        );
        assert_eq!(
            path_validation_decision(tquic::PathState::ValidatingMTU, CarrierKind::UdpDirect),
            None,
            "real UDP sockets must still complete full TQUIC MTU validation"
        );
        assert_eq!(
            path_validation_decision(tquic::PathState::Failed, CarrierKind::RelayNextHop),
            Some(false)
        );
        assert_eq!(
            path_validation_decision(tquic::PathState::Validating, CarrierKind::RelayNextHop),
            None
        );
    }

    /// White-box: `path_validation_decision` matrix for every carrier kind ×
    /// relevant TQUIC path states (critical admission automaton).
    #[test]
    fn path_validation_decision_matrix_all_carriers() {
        use tquic::PathState;
        let carriers = [
            CarrierKind::UdpDirect,
            CarrierKind::UdpPunch,
            CarrierKind::FakeTcpPunch,
            CarrierKind::RelayNextHop,
            CarrierKind::Manual,
        ];
        for kind in carriers {
            assert_eq!(
                path_validation_decision(PathState::Validated, kind),
                Some(true),
                "{kind:?} Validated"
            );
            assert_eq!(
                path_validation_decision(PathState::Failed, kind),
                Some(false),
                "{kind:?} Failed"
            );
            assert_eq!(
                path_validation_decision(PathState::Validating, kind),
                None,
                "{kind:?} Validating still in progress"
            );
            let mtu = path_validation_decision(PathState::ValidatingMTU, kind);
            if kind == CarrierKind::RelayNextHop {
                assert_eq!(mtu, Some(true), "only relay accepts ValidatingMTU");
            } else {
                assert_eq!(
                    mtu, None,
                    "{kind:?} must wait for full MTU validation, got {mtu:?}"
                );
            }
        }
    }

    #[test]
    fn carrier_enabled_by_config_matrix() {
        let mut config = gen_default_mp_config();
        config.enabled = true;
        config.providers = vec!["udp-direct".into(), "relay-next-hop".into()];
        assert!(carrier_is_enabled_by_config(
            &config,
            CarrierKind::UdpDirect
        ));
        assert!(carrier_is_enabled_by_config(
            &config,
            CarrierKind::RelayNextHop
        ));
        assert!(!carrier_is_enabled_by_config(
            &config,
            CarrierKind::UdpPunch
        ));
        assert!(!carrier_is_enabled_by_config(
            &config,
            CarrierKind::FakeTcpPunch
        ));
        // Manual is not gated by provider list name.
        assert!(carrier_is_enabled_by_config(&config, CarrierKind::Manual));

        config.enabled = false;
        assert!(!carrier_is_enabled_by_config(
            &config,
            CarrierKind::UdpDirect
        ));
        assert!(
            !carrier_is_enabled_by_config(&config, CarrierKind::Manual),
            "master switch off disables every carrier including manual"
        );
    }

    #[test]
    fn concrete_remote_endpoint_rejects_unspecified() {
        assert!(!has_concrete_remote_endpoint("0.0.0.0:0".parse().unwrap()));
        assert!(!has_concrete_remote_endpoint(
            "0.0.0.0:443".parse().unwrap()
        ));
        assert!(!has_concrete_remote_endpoint(
            "127.0.0.1:0".parse().unwrap()
        ));
        assert!(has_concrete_remote_endpoint(
            "127.0.0.1:443".parse().unwrap()
        ));
        assert!(has_concrete_remote_endpoint("[::1]:443".parse().unwrap()));
    }
}

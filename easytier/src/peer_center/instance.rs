use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::{Arc, Weak},
    time::{Duration, Instant},
};

use crossbeam::atomic::AtomicCell;
use futures::Future;
use std::sync::RwLock;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tracing::Instrument;

use crate::{
    common::{PeerId, global_ctx::GlobalCtx},
    peers::{
        link_sqm::LinkSqmRegistry,
        peer_manager::PeerManager,
        peer_map::PeerMap,
        peer_rpc::PeerRpcManager,
        route_trait::{RouteCostCalculator, RouteCostCalculatorInterface, mp_weighted_enabled},
        rpc_service::PeerManagerRpcService,
    },
    proto::{
        peer_rpc::{
            DirectConnectedPeerInfo, GetGlobalPeerMapRequest, GetGlobalPeerMapResponse,
            GlobalPeerMap, PeerCenterRpc, PeerCenterRpcClientFactory, PeerCenterRpcServer,
            PeerInfoForGlobalMap, ReportPeersRequest, ReportPeersResponse,
        },
        rpc_types::{self, controller::BaseController},
    },
};

use super::{Digest, Error, server::PeerCenterServer};

/// One raw signal sample for a directly-connected egress link, fed to the
/// per-link SQM estimator registry (MP_SQM_PLAN.md §7.2).
#[derive(Clone, Copy, Debug)]
pub struct DirectLinkStat {
    pub peer_id: PeerId,
    /// min pingpong latency across this peer's conns (µs).
    pub latency_us: u64,
    /// cumulative bytes sent to this peer across its conns.
    pub tx_bytes: u64,
}

/// Aggregate per-directly-connected-peer signal samples from a `PeerMap`:
/// min latency + summed egress bytes across that peer's conns.
async fn collect_link_stats(peer_map: &PeerMap) -> Vec<DirectLinkStat> {
    let mut ret = Vec::new();
    for peer in peer_map.list_peers() {
        let Some(conns) = peer_map.list_peer_conns(peer).await else {
            continue;
        };
        let mut min_lat = u64::MAX;
        let mut tx_bytes = 0u64;
        for conn in &conns {
            if let Some(stats) = conn.stats.as_ref() {
                min_lat = min_lat.min(stats.latency_us);
                tx_bytes = tx_bytes.saturating_add(stats.tx_bytes);
            }
        }
        if min_lat != u64::MAX {
            ret.push(DirectLinkStat {
                peer_id: peer,
                latency_us: min_lat,
                tx_bytes,
            });
        }
    }
    ret
}

/// Whether our local est_bw for any direct link shifted enough since the last
/// gossip to justify an out-of-cycle report (MP_SQM_PLAN.md §9.1): a link
/// appeared/vanished, crossed the known/zero boundary, or moved by ≥25%. This
/// keeps downstream full-path bottleneck weights fresh without gossiping on
/// every 2 Hz jitter, and is only consulted when weighted multipath is on.
fn est_bw_changed(last: &HashMap<PeerId, u64>, cur: &HashMap<PeerId, u64>) -> bool {
    if last.len() != cur.len() {
        return true;
    }
    for (peer, &c) in cur {
        let Some(&p) = last.get(peer) else {
            return true;
        };
        let hi = p.max(c);
        let lo = p.min(c);
        // crossing to/from zero, or a ≥25% relative move.
        if (lo == 0) != (hi == 0) {
            return true;
        }
        if hi > 0 && (hi - lo).saturating_mul(4) >= hi {
            return true;
        }
    }
    false
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Arc, Box)]
pub trait PeerCenterPeerManagerTrait: Send + Sync + 'static {
    async fn list_peers(&self) -> PeerInfoForGlobalMap;
    fn my_peer_id(&self) -> PeerId;
    fn get_global_ctx(&self) -> Arc<GlobalCtx>;
    fn get_rpc_mgr(&self) -> Weak<PeerRpcManager>;
    async fn list_routes(&self) -> Vec<crate::proto::api::instance::Route>;
    /// Per-link raw signals for the SQM estimator. Default empty so impls that
    /// don't carry live conns (e.g. test doubles) opt out transparently.
    async fn list_link_stats(&self) -> Vec<DirectLinkStat> {
        Vec::new()
    }
}

struct PeerCenterBase {
    peer_mgr: Arc<dyn PeerCenterPeerManagerTrait>,
    my_peer_id: PeerId,
    tasks: Mutex<JoinSet<()>>,
    lock: Arc<Mutex<()>>,
}

// static SERVICE_ID: u32 = 5; for compatibility with the original code
static SERVICE_ID: u32 = 50;

struct PeridicJobCtx<T> {
    peer_mgr: Arc<dyn PeerCenterPeerManagerTrait>,
    my_peer_id: PeerId,
    center_peer: AtomicCell<PeerId>,
    job_ctx: T,
}

impl PeerCenterBase {
    pub async fn init(&self) -> Result<(), Error> {
        let Some(rpc_mgr) = self.peer_mgr.get_rpc_mgr().upgrade() else {
            return Err(Error::Shutdown);
        };
        rpc_mgr.rpc_server().registry().register(
            PeerCenterRpcServer::new(PeerCenterServer::new()),
            &self.peer_mgr.get_global_ctx().get_network_name(),
        );
        Ok(())
    }

    async fn select_center_peer(peer_mgr: &dyn PeerCenterPeerManagerTrait) -> Option<PeerId> {
        let peers = peer_mgr.list_routes().await;
        if peers.is_empty() {
            return None;
        }
        // find peer with alphabetical smallest id.
        let mut min_peer = peer_mgr.my_peer_id();
        for peer in peers
            .iter()
            .filter(|r| r.feature_flag.map(|r| !r.is_public_server).unwrap_or(true))
        {
            let peer_id = peer.peer_id;
            if peer_id < min_peer {
                min_peer = peer_id;
            }
        }
        Some(min_peer)
    }

    async fn init_periodic_job<
        T: Send + Sync + 'static + Clone,
        Fut: Future<Output = Result<u32, rpc_types::error::Error>> + Send + 'static,
    >(
        &self,
        job_ctx: T,
        job_fn: impl Fn(
            Box<dyn PeerCenterRpc<Controller = BaseController> + Send>,
            Arc<PeridicJobCtx<T>>,
        ) -> Fut
        + Send
        + Sync
        + 'static,
    ) {
        let my_peer_id = self.my_peer_id;
        let peer_mgr = self.peer_mgr.clone();
        let lock = self.lock.clone();
        self.tasks.lock().await.spawn(
            async move {
                let ctx = Arc::new(PeridicJobCtx {
                    peer_mgr: peer_mgr.clone(),
                    my_peer_id,
                    center_peer: AtomicCell::new(PeerId::default()),
                    job_ctx,
                });
                loop {
                    let Some(center_peer) = Self::select_center_peer(&peer_mgr).await else {
                        tracing::trace!("no center peer found, sleep 1 second");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    };
                    let Some(rpc_mgr) = peer_mgr.get_rpc_mgr().upgrade() else {
                        tracing::error!("rpc manager is shutdown, exit periodic job");
                        return;
                    };

                    ctx.center_peer.store(center_peer);
                    tracing::trace!(?center_peer, "run periodic job");
                    let _g = lock.lock().await;
                    let stub = rpc_mgr
                        .rpc_client()
                        .scoped_client::<PeerCenterRpcClientFactory<BaseController>>(
                            my_peer_id,
                            center_peer,
                            peer_mgr.get_global_ctx().get_network_name(),
                        );
                    let ret = job_fn(stub, ctx.clone()).await;
                    drop(_g);

                    let Ok(sleep_time_ms) = ret else {
                        tracing::error!("periodic job to center server rpc failed: {:?}", ret);
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        continue;
                    };

                    if sleep_time_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(sleep_time_ms as u64)).await;
                    }
                }
            }
            .instrument(tracing::info_span!("periodic_job", ?my_peer_id)),
        );
    }

    pub fn new(peer_mgr: Arc<dyn PeerCenterPeerManagerTrait>) -> Self {
        let my_peer_id = peer_mgr.my_peer_id();
        PeerCenterBase {
            peer_mgr,
            my_peer_id,
            tasks: Mutex::new(JoinSet::new()),
            lock: Arc::new(Mutex::new(())),
        }
    }
}

#[derive(Clone)]
pub struct PeerCenterInstanceService {
    global_peer_map: Arc<RwLock<GlobalPeerMap>>,
    global_peer_map_digest: Arc<AtomicCell<Digest>>,
}

#[async_trait::async_trait]
impl PeerCenterRpc for PeerCenterInstanceService {
    type Controller = BaseController;

    async fn get_global_peer_map(
        &self,
        _: BaseController,
        _: GetGlobalPeerMapRequest,
    ) -> Result<GetGlobalPeerMapResponse, rpc_types::error::Error> {
        let global_peer_map = self.global_peer_map.read().unwrap();
        Ok(GetGlobalPeerMapResponse {
            global_peer_map: global_peer_map.map.clone(),
            digest: Some(self.global_peer_map_digest.load()),
        })
    }

    async fn report_peers(
        &self,
        _: BaseController,
        _req: ReportPeersRequest,
    ) -> Result<ReportPeersResponse, rpc_types::error::Error> {
        Err(anyhow::anyhow!("not implemented").into())
    }
}

pub struct PeerCenterInstance {
    peer_mgr: Arc<dyn PeerCenterPeerManagerTrait>,

    client: Arc<PeerCenterBase>,
    global_peer_map: Arc<RwLock<GlobalPeerMap>>,
    global_peer_map_digest: Arc<AtomicCell<Digest>>,
    global_peer_map_update_time: Arc<AtomicCell<Instant>>,
    // per-egress-link SQM estimators (MP_SQM_PLAN.md §7.2): fed locally by the
    // sampler job, read by the cost calculator's `directed_bandwidth_bps`, and
    // gossiped through the global peer map by the report-peers job.
    link_sqm: Arc<LinkSqmRegistry>,
}

impl PeerCenterInstance {
    pub fn new(peer_mgr: Arc<dyn PeerCenterPeerManagerTrait>) -> Self {
        PeerCenterInstance {
            peer_mgr: peer_mgr.clone(),
            client: Arc::new(PeerCenterBase::new(peer_mgr.clone())),
            global_peer_map: Arc::new(RwLock::new(GlobalPeerMap::default())),
            global_peer_map_digest: Arc::new(AtomicCell::new(Digest::default())),
            global_peer_map_update_time: Arc::new(AtomicCell::new(Instant::now())),
            link_sqm: Arc::new(LinkSqmRegistry::new()),
        }
    }

    pub async fn init(&self) {
        self.client.init().await.unwrap();
        self.init_get_global_info_job().await;
        self.init_report_peers_job().await;
        self.init_sqm_estimator_job().await;
    }

    // MP_SQM_PLAN.md §7.2: sample every direct link's pingpong latency + egress
    // byte rate at ~2 Hz and feed the per-link SQM estimator registry. Purely
    // local (no center RPC); the returned est_bw is consumed by the cost
    // calculator and gossiped by the report-peers job.
    async fn init_sqm_estimator_job(&self) {
        // This loop is purely local — it reads live conn stats and updates the
        // per-link estimators. It must NOT ride `init_periodic_job`, which only
        // runs once a center peer is elected and serializes on the shared
        // center-RPC lock; that would gate/starve the 2 Hz control loop behind
        // network RPCs. So it owns an independent ticker task instead.
        let peer_mgr = self.peer_mgr.clone();
        let link_sqm = self.link_sqm.clone();
        let my_peer_id = self.client.my_peer_id;

        self.client.tasks.lock().await.spawn(
            async move {
                let mut last = Instant::now();
                let mut ticker = tokio::time::interval(Duration::from_millis(500));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let mut tick_n: u64 = 0;
                loop {
                    // ~2 Hz control loop (MP_SQM_PLAN.md §7.3 tick).
                    ticker.tick().await;
                    let now = Instant::now();
                    let dt_us = now
                        .duration_since(last)
                        .as_micros()
                        .min(u64::MAX as u128) as u64;
                    last = now;

                    let samples = peer_mgr.list_link_stats().await;
                    let mut live = HashSet::with_capacity(samples.len());
                    for s in &samples {
                        live.insert(s.peer_id);
                        link_sqm.observe(s.peer_id, s.latency_us, s.tx_bytes, dt_us);
                    }
                    link_sqm.retain(&live);

                    // Observability (MP_SQM_PLAN §10): dump per-link est_bw ~every
                    // 5 s. Filter with `RUST_LOG=et_mp=info`.
                    tick_n += 1;
                    if tick_n % 10 == 0 {
                        for s in &samples {
                            tracing::info!(
                                target: "et_mp",
                                peer = s.peer_id,
                                latency_us = s.latency_us,
                                tx_bytes = s.tx_bytes,
                                est_bw_bps = ?link_sqm.est_bw_bps(s.peer_id),
                                "sqm link sample"
                            );
                        }
                    }
                }
            }
            .instrument(tracing::info_span!("sqm_estimator_job", ?my_peer_id)),
        );
    }

    async fn init_get_global_info_job(&self) {
        struct Ctx {
            global_peer_map: Arc<RwLock<GlobalPeerMap>>,
            global_peer_map_digest: Arc<AtomicCell<Digest>>,
            global_peer_map_update_time: Arc<AtomicCell<Instant>>,
        }

        let ctx = Arc::new(Ctx {
            global_peer_map: self.global_peer_map.clone(),
            global_peer_map_digest: self.global_peer_map_digest.clone(),
            global_peer_map_update_time: self.global_peer_map_update_time.clone(),
        });

        self.client
            .init_periodic_job(ctx, |client, ctx| async move {
                if ctx
                    .job_ctx
                    .global_peer_map_update_time
                    .load()
                    .elapsed()
                    .as_secs()
                    > 120
                {
                    ctx.job_ctx.global_peer_map_digest.store(Digest::default());
                }

                let ret = client
                    .get_global_peer_map(
                        BaseController::default(),
                        GetGlobalPeerMapRequest {
                            digest: ctx.job_ctx.global_peer_map_digest.load(),
                        },
                    )
                    .await;

                let Ok(resp) = ret else {
                    tracing::error!(
                        "get global info from center server got error result: {:?}",
                        ret
                    );
                    return Ok(10000);
                };

                if resp == GetGlobalPeerMapResponse::default() {
                    // digest match, no need to update
                    return Ok(15000);
                }

                tracing::info!(
                    "get global info from center server: {:?}, digest: {:?}",
                    resp.global_peer_map,
                    resp.digest
                );

                *ctx.job_ctx.global_peer_map.write().unwrap() = GlobalPeerMap {
                    map: resp.global_peer_map,
                };
                ctx.job_ctx
                    .global_peer_map_digest
                    .store(resp.digest.unwrap_or_default());
                ctx.job_ctx
                    .global_peer_map_update_time
                    .store(Instant::now());

                Ok(15000)
            })
            .await;
    }

    async fn init_report_peers_job(&self) {
        struct Ctx {
            peer_mgr: Arc<dyn PeerCenterPeerManagerTrait>,
            last_report_peers: Mutex<BTreeSet<PeerId>>,
            link_sqm: Arc<LinkSqmRegistry>,
            // last est_bw we actually gossiped, per direct peer (MP_SQM_PLAN §9.1)
            last_bw: Mutex<HashMap<PeerId, u64>>,

            last_center_peer: AtomicCell<PeerId>,
            last_report_time: AtomicCell<Instant>,
        }
        let ctx = Arc::new(Ctx {
            peer_mgr: self.peer_mgr.clone(),
            last_report_peers: Mutex::new(BTreeSet::new()),
            link_sqm: self.link_sqm.clone(),
            last_bw: Mutex::new(HashMap::new()),
            last_center_peer: AtomicCell::new(PeerId::default()),
            last_report_time: AtomicCell::new(Instant::now()),
        });

        self.client
            .init_periodic_job(ctx, |client, ctx| async move {
                let my_node_id = ctx.my_peer_id;
                let mut peers = ctx.job_ctx.peer_mgr.list_peers().await;
                // MP_SQM_PLAN.md §9.1: attach the local per-link est_bw so the
                // global peer map can seed full-path bottleneck weights.
                let mut cur_bw = HashMap::with_capacity(peers.direct_peers.len());
                for (peer_id, info) in peers.direct_peers.iter_mut() {
                    // Tri-state: None = unknown, Some(0) = saturated, Some(n) = headroom.
                    info.est_bw_bps = ctx.job_ctx.link_sqm.est_bw_bps(*peer_id);
                    cur_bw.insert(*peer_id, info.est_bw_bps.unwrap_or(0));
                }
                let peer_list: BTreeSet<PeerId> = peers.direct_peers.keys().copied().collect();
                let job_ctx = &ctx.job_ctx;

                // §9.1: also refresh when our est_bw shifted enough that downstream
                // full-path bottleneck weights would otherwise go stale — MP mode
                // only, and bounded to this job's 5 s cadence so it cannot storm.
                // Scope the guard so it drops before the report RPC below.
                let bw_stale = if mp_weighted_enabled() {
                    let last_bw = job_ctx.last_bw.lock().await;
                    est_bw_changed(&*last_bw, &cur_bw)
                } else {
                    false
                };

                // only report when:
                // 1. center peer changed
                // 2. last report time is more than 60 seconds
                // 3. peers changed
                // 4. est_bw drifted materially (MP mode)
                if !bw_stale
                    && ctx.center_peer.load() == ctx.job_ctx.last_center_peer.load()
                    && job_ctx.last_report_time.load().elapsed().as_secs() < 60
                    && *job_ctx.last_report_peers.lock().await == peer_list
                {
                    return Ok(5000);
                }

                let ret = client
                    .report_peers(
                        BaseController::default(),
                        ReportPeersRequest {
                            my_peer_id: my_node_id,
                            peer_infos: Some(peers),
                        },
                    )
                    .await;

                if ret.is_ok() {
                    ctx.job_ctx.last_center_peer.store(ctx.center_peer.load());
                    *ctx.job_ctx.last_report_peers.lock().await = peer_list;
                    *ctx.job_ctx.last_bw.lock().await = cur_bw;
                    ctx.job_ctx.last_report_time.store(Instant::now());
                } else {
                    tracing::error!("report peers to center server got error result: {:?}", ret);
                }

                Ok(5000)
            })
            .await;
    }

    pub fn get_rpc_service(&self) -> PeerCenterInstanceService {
        PeerCenterInstanceService {
            global_peer_map: self.global_peer_map.clone(),
            global_peer_map_digest: self.global_peer_map_digest.clone(),
        }
    }

    pub fn get_cost_calculator(&self) -> RouteCostCalculator {
        struct RouteCostCalculatorImpl {
            my_peer_id: PeerId,
            global_peer_map: Arc<RwLock<GlobalPeerMap>>,

            global_peer_map_clone: GlobalPeerMap,

            link_sqm: Arc<LinkSqmRegistry>,

            last_update_time: AtomicCell<Instant>,
            global_peer_map_update_time: Arc<AtomicCell<Instant>>,
        }

        impl RouteCostCalculatorImpl {
            fn directed_cost(&self, src: PeerId, dst: PeerId) -> Option<i32> {
                self.global_peer_map_clone
                    .map
                    .get(&src)
                    .and_then(|src_peer_info| src_peer_info.direct_peers.get(&dst))
                    .map(|info| info.latency_ms)
            }
        }

        impl RouteCostCalculatorInterface for RouteCostCalculatorImpl {
            fn calculate_cost(&self, src: PeerId, dst: PeerId) -> i32 {
                if let Some(cost) = self.directed_cost(src, dst) {
                    return cost;
                }
                self.directed_cost(dst, src).unwrap_or(500)
            }

            fn directed_bandwidth_bps(&self, src: PeerId, dst: PeerId) -> Option<u64> {
                // MP_SQM_PLAN.md §9.1: our own egress links use the freshest
                // local SQM estimate; downstream links fall back to the value
                // gossiped through the global peer map. Both preserve the
                // tri-state (None = unknown, Some(0) = saturated) via proto3
                // presence, so a saturated far hop is de-prioritised rather than
                // mistaken for no-data.
                if src == self.my_peer_id {
                    if let Some(bw) = self.link_sqm.est_bw_bps(dst) {
                        return Some(bw);
                    }
                }
                self.global_peer_map_clone
                    .map
                    .get(&src)
                    .and_then(|src_peer_info| src_peer_info.direct_peers.get(&dst))
                    .and_then(|info| info.est_bw_bps)
            }

            fn begin_update(&mut self) {
                let global_peer_map = self.global_peer_map.read().unwrap();
                self.global_peer_map_clone = global_peer_map.clone();
            }

            fn end_update(&mut self) {
                self.last_update_time
                    .store(self.global_peer_map_update_time.load());
            }

            fn need_update(&self) -> bool {
                self.last_update_time.load() < self.global_peer_map_update_time.load()
            }
        }

        Box::new(RouteCostCalculatorImpl {
            my_peer_id: self.peer_mgr.my_peer_id(),
            global_peer_map: self.global_peer_map.clone(),
            global_peer_map_clone: GlobalPeerMap::default(),
            link_sqm: self.link_sqm.clone(),
            last_update_time: AtomicCell::new(
                self.global_peer_map_update_time.load() - Duration::from_secs(1),
            ),
            global_peer_map_update_time: self.global_peer_map_update_time.clone(),
        })
    }
}

#[async_trait::async_trait]
impl PeerCenterPeerManagerTrait for PeerManager {
    async fn list_peers(&self) -> PeerInfoForGlobalMap {
        PeerManagerRpcService::list_peers(self).await.into()
    }

    fn my_peer_id(&self) -> PeerId {
        self.get_peer_map().my_peer_id()
    }

    fn get_global_ctx(&self) -> Arc<GlobalCtx> {
        self.get_peer_map().get_global_ctx()
    }

    fn get_rpc_mgr(&self) -> Weak<PeerRpcManager> {
        Arc::downgrade(&self.get_peer_rpc_mgr())
    }

    async fn list_routes(&self) -> Vec<crate::proto::api::instance::Route> {
        self.list_routes().await
    }

    async fn list_link_stats(&self) -> Vec<DirectLinkStat> {
        let peer_map = self.get_peer_map();
        collect_link_stats(&peer_map).await
    }
}

/// Lowest latency among the connections that already have a latency sample.
///
/// A freshly established connection reports `latency_us == 0` until its first
/// ping completes. Treating that as a real value would advertise the peer as
/// 1 ms away to the peer center, so latency-first routing could detour through
/// a slow or lossy link until the next report. Unmeasured connections are
/// skipped instead; a peer with none measured is left out of the report and is
/// reported once its first sample arrives, because the peer list changes then.
fn min_measured_latency_us(latencies_us: impl IntoIterator<Item = u64>) -> Option<u64> {
    latencies_us.into_iter().filter(|lat| *lat > 0).min()
}

pub struct PeerMapWithPeerRpcManager {
    pub peer_map: Arc<PeerMap>,
    pub rpc_mgr: Arc<PeerRpcManager>,
}

#[async_trait::async_trait]
impl PeerCenterPeerManagerTrait for PeerMapWithPeerRpcManager {
    async fn list_peers(&self) -> PeerInfoForGlobalMap {
        // TODO: currently latency between public server cannot be calculated because one public-server pair
        // has no connection between them. (hard to get latency from peer manager because it's hard to transfrom the peer id)
        // but it's fine because we don't want to too much traffic between public servers.
        let peers = self.peer_map.list_peers();
        let mut ret = PeerInfoForGlobalMap::default();
        for peer in peers {
            if let Some(conns) = self.peer_map.list_peer_conns(peer).await {
                let Some(min_lat) = min_measured_latency_us(
                    conns
                        .iter()
                        .map(|conn| conn.stats.as_ref().unwrap().latency_us),
                ) else {
                    continue;
                };

                ret.direct_peers.insert(
                    peer,
                    DirectConnectedPeerInfo {
                        latency_ms: std::cmp::max(1, (min_lat as u32 / 1000) as i32),
                        // est_bw enriched by the report-peers job from the local
                        // SQM registry; unknown (None) here.
                        est_bw_bps: None,
                    },
                );
            }
        }

        ret
    }

    fn my_peer_id(&self) -> PeerId {
        self.peer_map.my_peer_id()
    }

    fn get_global_ctx(&self) -> Arc<GlobalCtx> {
        self.peer_map.get_global_ctx()
    }

    fn get_rpc_mgr(&self) -> Weak<PeerRpcManager> {
        Arc::downgrade(&self.rpc_mgr)
    }

    async fn list_routes(&self) -> Vec<crate::proto::api::instance::Route> {
        self.peer_map.list_route_infos().await
    }

    async fn list_link_stats(&self) -> Vec<DirectLinkStat> {
        collect_link_stats(&self.peer_map).await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        peers::tests::{connect_peer_manager, create_mock_peer_manager, wait_route_appear},
        tunnel::common::tests::wait_for_condition,
    };

    use super::*;

    #[test]
    fn unmeasured_connections_are_not_reported_as_fastest() {
        assert_eq!(min_measured_latency_us([0, 306_000]), Some(306_000));
        assert_eq!(min_measured_latency_us([306_000, 0, 93_000]), Some(93_000));
    }

    #[test]
    fn peer_without_measured_connection_is_skipped() {
        assert_eq!(min_measured_latency_us([0, 0]), None);
        assert_eq!(min_measured_latency_us([]), None);
    }

    #[test]
    fn sub_millisecond_lan_latency_is_still_reported() {
        assert_eq!(min_measured_latency_us([400]), Some(400));
    }

    #[tokio::test]
    async fn test_peer_center_instance() {
        let peer_mgr_a = create_mock_peer_manager().await;
        let peer_mgr_b = create_mock_peer_manager().await;
        let peer_mgr_c = create_mock_peer_manager().await;

        let peer_center_a = PeerCenterInstance::new(peer_mgr_a.clone());
        let peer_center_b = PeerCenterInstance::new(peer_mgr_b.clone());
        let peer_center_c = PeerCenterInstance::new(peer_mgr_c.clone());

        let peer_centers = [&peer_center_a, &peer_center_b, &peer_center_c];
        for pc in peer_centers.iter() {
            pc.init().await;
        }

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let mut digest = None;
        for pc in peer_centers.iter() {
            let rpc_service = pc.get_rpc_service();
            wait_for_condition(
                || async { rpc_service.global_peer_map.read().unwrap().map.len() == 3 },
                Duration::from_secs(20),
            )
            .await;

            println!("rpc service ready, {:#?}", rpc_service.global_peer_map);

            if let Some(prev) = digest {
                let v = rpc_service.global_peer_map_digest.load();
                assert_eq!(prev, v);
                digest = Some(prev);
            } else {
                digest = Some(rpc_service.global_peer_map_digest.load());
            }

            let mut route_cost = pc.get_cost_calculator();
            assert!(route_cost.need_update());

            route_cost.begin_update();
            assert!(
                route_cost.calculate_cost(peer_mgr_a.my_peer_id(), peer_mgr_b.my_peer_id()) < 30
            );
            assert!(
                route_cost.calculate_cost(peer_mgr_b.my_peer_id(), peer_mgr_a.my_peer_id()) < 30
            );
            assert!(
                route_cost.calculate_cost(peer_mgr_b.my_peer_id(), peer_mgr_c.my_peer_id()) < 30
            );
            assert!(
                route_cost.calculate_cost(peer_mgr_c.my_peer_id(), peer_mgr_b.my_peer_id()) < 30
            );
            assert!(
                route_cost.calculate_cost(peer_mgr_c.my_peer_id(), peer_mgr_a.my_peer_id()) > 50
            );
            assert!(
                route_cost.calculate_cost(peer_mgr_a.my_peer_id(), peer_mgr_c.my_peer_id()) > 50
            );
            route_cost.end_update();
            assert!(!route_cost.need_update());
        }
    }
}

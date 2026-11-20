use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

#[cfg(feature = "mpquic")]
use crate::proto::common::PeerFeatureFlag;

use anyhow::{Context, Error};
use both_easy_sym::{PunchBothEasySymHoleClient, PunchBothEasySymHoleServer};
use common::{PunchHoleServerCommon, UdpNatType, UdpPunchClientMethod};
use cone::{PunchConeHoleClient, PunchConeHoleServer};
use dashmap::DashMap;
use hotpath::instant::Instant;
use once_cell::sync::Lazy;
use sym_to_cone::{PunchSymToConeHoleClient, PunchSymToConeHoleServer};
use tokio::{sync::Mutex, task::JoinHandle};

use crate::{
    common::{PeerId, stun::StunInfoCollectorTrait},
    peers::{
        peer_manager::PeerManager,
        peer_task::{PeerTaskLauncher, PeerTaskManager},
    },
    proto::{
        common::{NatType, Void},
        peer_rpc::{
            SelectPunchListenerRequest, SelectPunchListenerResponse,
            SendPunchPacketBothEasySymRequest, SendPunchPacketBothEasySymResponse,
            SendPunchPacketConeRequest, SendPunchPacketEasySymRequest,
            SendPunchPacketHardSymRequest, SendPunchPacketHardSymResponse, UdpHolePunchRpc,
            UdpHolePunchRpcServer,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::Tunnel,
};

use crate::connector::udp_hole_punch_transport::{
    FinishOutcome as UdpFinishOutcome, UdpPunchRole, attach_new_tunnel,
};
use crate::connector::{should_background_p2p_with_peer, should_try_p2p_with_peer};

pub(crate) mod both_easy_sym;
pub(crate) mod common;
pub(crate) mod cone;
pub(crate) mod sym_to_cone;

// sym punch should be serialized
static SYM_PUNCH_LOCK: Lazy<DashMap<PeerId, Arc<Mutex<()>>>> = Lazy::new(DashMap::new);
pub static RUN_TESTING: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));

// Blacklist timeout in seconds
pub const BLACKLIST_TIMEOUT_SEC: u64 = 3600;

fn get_sym_punch_lock(peer_id: PeerId) -> Arc<Mutex<()>> {
    SYM_PUNCH_LOCK
        .entry(peer_id)
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .value()
        .clone()
}

struct UdpHolePunchServer {
    common: Arc<PunchHoleServerCommon>,
    cone_server: PunchConeHoleServer,
    sym_to_cone_server: PunchSymToConeHoleServer,
    both_easy_sym_server: PunchBothEasySymHoleServer,
}

impl UdpHolePunchServer {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Arc<Self> {
        let common = Arc::new(PunchHoleServerCommon::new(peer_mgr));
        let cone_server = PunchConeHoleServer::new(common.clone());
        let sym_to_cone_server = PunchSymToConeHoleServer::new(common.clone());
        let both_easy_sym_server = PunchBothEasySymHoleServer::new(common.clone());

        Arc::new(Self {
            common,
            cone_server,
            sym_to_cone_server,
            both_easy_sym_server,
        })
    }
}

#[async_trait::async_trait]
impl UdpHolePunchRpc for UdpHolePunchServer {
    type Controller = BaseController;

    async fn select_punch_listener(
        &self,
        _ctrl: Self::Controller,
        input: SelectPunchListenerRequest,
    ) -> rpc_types::error::Result<SelectPunchListenerResponse> {
        #[cfg(feature = "mpquic")]
        let mp_accepted = input.use_mp
            && crate::connector::udp_hole_punch_transport::mp_udp_provider_enabled(
                &self.common.get_global_ctx().get_flags(),
                crate::connector::udp_hole_punch_transport::normalize_mp_udp_provider(
                    &input.mp_provider,
                ),
            );
        #[cfg(not(feature = "mpquic"))]
        let mp_accepted = false;

        #[cfg(feature = "mpquic")]
        let selected = if mp_accepted {
            self.common
                .select_mp_listener(
                    crate::connector::udp_hole_punch_transport::normalize_mp_udp_provider(
                        &input.mp_provider,
                    ) != "udp-direct",
                )
                .await
        } else {
            self.common
                .select_listener(input.force_new, input.prefer_port_mapping)
                .await
        };
        #[cfg(not(feature = "mpquic"))]
        let selected = self
            .common
            .select_listener(input.force_new, input.prefer_port_mapping)
            .await;
        let (socket, addr) = selected.ok_or(anyhow::anyhow!("no listener available"))?;
        let local_addr = socket.local_addr().map_err(anyhow::Error::new)?;
        #[cfg(feature = "mpquic")]
        let mp_alt_listener_ips = if mp_accepted {
            cone::mp_alt_public_ips(
                &self
                    .common
                    .get_global_ctx()
                    .get_stun_info_collector()
                    .get_stun_info()
                    .public_ip,
                addr,
            )
        } else {
            Vec::new()
        };
        #[cfg(not(feature = "mpquic"))]
        let mp_alt_listener_ips = Vec::new();

        // Observe where the requester's punch packets come from before the listener's address is
        // known to it. The echo tells the requester that the registration exists; MP punches
        // through its own raw listener and never asks for one.
        let transaction_id = match input.transaction_id {
            Some(transaction_id) if !mp_accepted => {
                self.common.prepare_hole_punch(&addr, transaction_id).await?;
                Some(transaction_id)
            }
            _ => None,
        };

        Ok(SelectPunchListenerResponse {
            listener_mapped_addr: Some(addr.into()),
            transaction_id,
            mp_accepted,
            listener_local_addr: Some(local_addr.into()),
            mp_alt_listener_ips,
        })
    }

    /// send packet to one remote_addr, used by nat1-3 to nat1-3
    async fn send_punch_packet_cone(
        &self,
        ctrl: Self::Controller,
        input: SendPunchPacketConeRequest,
    ) -> rpc_types::error::Result<Void> {
        self.cone_server.send_punch_packet_cone(ctrl, input).await
    }

    /// send packet to multiple remote_addr (birthday attack), used by nat4 to nat1-3
    async fn send_punch_packet_hard_sym(
        &self,
        _ctrl: Self::Controller,
        input: SendPunchPacketHardSymRequest,
    ) -> rpc_types::error::Result<SendPunchPacketHardSymResponse> {
        let _locked = get_sym_punch_lock(self.common.get_peer_mgr().my_peer_id())
            .try_lock_owned()
            .with_context(|| "sym punch lock is busy")?;
        self.sym_to_cone_server
            .send_punch_packet_hard_sym(input)
            .await
    }

    async fn send_punch_packet_easy_sym(
        &self,
        _ctrl: Self::Controller,
        input: SendPunchPacketEasySymRequest,
    ) -> rpc_types::error::Result<Void> {
        let _locked = get_sym_punch_lock(self.common.get_peer_mgr().my_peer_id())
            .try_lock_owned()
            .with_context(|| "sym punch lock is busy")?;
        self.sym_to_cone_server
            .send_punch_packet_easy_sym(input)
            .await
            .map(|_| Void {})
    }

    /// nat4 to nat4 (both predictably)
    async fn send_punch_packet_both_easy_sym(
        &self,
        _ctrl: Self::Controller,
        input: SendPunchPacketBothEasySymRequest,
    ) -> rpc_types::error::Result<SendPunchPacketBothEasySymResponse> {
        let _locked = get_sym_punch_lock(self.common.get_peer_mgr().my_peer_id())
            .try_lock_owned()
            .with_context(|| "sym punch lock is busy")?;
        self.both_easy_sym_server
            .send_punch_packet_both_easy_sym(input)
            .await
    }
}

#[derive(Debug)]
pub struct BackOff {
    backoffs_ms: Vec<u64>,
    current_idx: usize,
}

impl BackOff {
    pub fn new(backoffs_ms: Vec<u64>) -> Self {
        Self {
            backoffs_ms,
            current_idx: 0,
        }
    }

    pub fn next_backoff(&mut self) -> u64 {
        let backoff = self.backoffs_ms[self.current_idx];
        self.current_idx = (self.current_idx + 1).min(self.backoffs_ms.len() - 1);
        backoff
    }

    pub fn rollback(&mut self) {
        self.current_idx = self.current_idx.saturating_sub(1);
    }

    pub async fn sleep_for_next_backoff(&mut self) {
        let backoff = self.next_backoff();
        if backoff > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(backoff)).await;
        }
    }
}

pub fn handle_rpc_result<T>(
    ret: Result<T, rpc_types::error::Error>,
    dst_peer_id: PeerId,
    blacklist: &timedmap::TimedMap<PeerId, ()>,
) -> Result<T, rpc_types::error::Error> {
    match ret {
        Ok(ret) => Ok(ret),
        Err(e) => {
            if matches!(e, rpc_types::error::Error::InvalidServiceKey(_, _)) {
                blacklist.insert(dst_peer_id, (), Duration::from_secs(BLACKLIST_TIMEOUT_SEC));
            }
            Err(e)
        }
    }
}

/// MP UDP punch is a route-discovered carrier provider, not legacy automatic
/// P2P.  In particular, `disable_p2p` must keep suppressing the latter without
/// preventing an enabled MP supervisor from asking a routed peer to establish
/// a raw UDP/TQUIC carrier through the normal hole-punch RPC.
///
/// Public servers remain relay/discovery infrastructure, rather than direct
/// punch targets, and a peer that does not run MP cannot take an MP carrier.
#[cfg(feature = "mpquic")]
fn should_collect_route_discovered_mp_udp_punch(
    peer_feature_flag: Option<&PeerFeatureFlag>,
    mp_enabled: bool,
    udp_punch_provider_enabled: bool,
) -> bool {
    mp_enabled
        && udp_punch_provider_enabled
        && crate::connector::peer_runs_mp(peer_feature_flag)
        && peer_feature_flag.is_none_or(|feature| !feature.is_public_server)
}

struct UdpHoePunchConnectorData {
    cone_client: PunchConeHoleClient,
    sym_to_cone_client: PunchSymToConeHoleClient,
    both_easy_sym_client: PunchBothEasySymHoleClient,
    peer_mgr: Arc<PeerManager>,
    blacklist: Arc<timedmap::TimedMap<PeerId, ()>>,
    #[cfg(feature = "mpquic")]
    mp_punch_progress: DashMap<PeerId, crate::connector::mp_session::MpPunchProgress>,
}

impl UdpHoePunchConnectorData {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Arc<Self> {
        let blacklist = Arc::new(timedmap::TimedMap::new());
        let cone_client = PunchConeHoleClient::new(peer_mgr.clone(), blacklist.clone());
        let sym_to_cone_client = PunchSymToConeHoleClient::new(peer_mgr.clone(), blacklist.clone());
        let both_easy_sym_client =
            PunchBothEasySymHoleClient::new(peer_mgr.clone(), blacklist.clone());

        Arc::new(Self {
            cone_client,
            sym_to_cone_client,
            both_easy_sym_client,
            peer_mgr,
            blacklist,
            #[cfg(feature = "mpquic")]
            mp_punch_progress: DashMap::new(),
        })
    }

    /// MP_SQM_PLAN.md S2.14: the slot of the next MP punch for `peer_id`, or
    /// `None` when its punched carriers already cover enough WANs.
    #[cfg(feature = "mpquic")]
    async fn mp_punch_slot(
        &self,
        peer_id: PeerId,
        mp: &crate::proto::common::MpConfig,
    ) -> Option<u32> {
        let summary = self
            .peer_mgr
            .get_mp_session_manager()
            .punch_wan_summary(peer_id, crate::connector::mp_path::CarrierKind::UdpPunch)
            .await;
        let mut progress = self.mp_punch_progress.entry(peer_id).or_default();
        crate::connector::mp_session::next_mp_punch_slot(
            &summary,
            &mut progress,
            crate::common::config::effective_mp_punch_attempts(mp),
        )
    }

    #[tracing::instrument(skip(self))]
    async fn handle_punch_result(
        &self,
        ret: Result<Option<Box<dyn Tunnel>>, Error>,
        backoff: Option<&mut BackOff>,
        round: Option<&mut u32>,
    ) -> bool {
        let op = |rollback: bool| {
            if rollback {
                if let Some(backoff) = backoff {
                    backoff.rollback();
                }
                if let Some(round) = round {
                    *round = round.saturating_sub(1);
                }
            } else if let Some(round) = round {
                *round += 1;
            }
        };

        match ret {
            Ok(Some(tunnel)) => {
                tracing::info!(?tunnel, "hole punching get tunnel success");

                if let Err(e) = self.peer_mgr.add_client_tunnel(tunnel, false).await {
                    tracing::warn!("add client tunnel failed, err: {}", e);
                    op(true);
                    false
                } else {
                    true
                }
            }
            Ok(None) => {
                tracing::info!("hole punching failed, no punch tunnel");
                op(false);
                false
            }
            Err(e) => {
                tracing::info!("hole punching failed, err: {}", e);
                op(true);
                false
            }
        }
    }

    async fn handle_udp_transport_result(
        &self,
        dst_peer_id: PeerId,
        ret: Result<Option<UdpFinishOutcome>, Error>,
        backoff: Option<&mut BackOff>,
        round: Option<&mut u32>,
    ) -> bool {
        let op = |rollback: bool| {
            if rollback {
                if let Some(backoff) = backoff {
                    backoff.rollback();
                }
                if let Some(round) = round {
                    *round = round.saturating_sub(1);
                }
            } else if let Some(round) = round {
                *round += 1;
            }
        };

        match ret {
            Ok(Some(UdpFinishOutcome::NewTunnel { tunnel, mp_role })) => {
                tracing::info!(?tunnel, "UDP hole punching created a new tunnel");
                if let Err(error) = attach_new_tunnel(
                    &self.peer_mgr,
                    dst_peer_id,
                    tunnel,
                    mp_role,
                    UdpPunchRole::Client,
                    false,
                )
                .await
                {
                    tracing::warn!(?error, "failed to add UDP punched tunnel");
                    op(true);
                    false
                } else {
                    true
                }
            }
            Ok(Some(UdpFinishOutcome::PathAdded)) => {
                tracing::info!("UDP punched carrier added to existing MPQUIC session");
                true
            }
            Ok(None) => {
                tracing::info!("UDP hole punching failed, no transport produced");
                op(false);
                false
            }
            Err(error) => {
                tracing::info!(?error, "UDP hole punching transport failed");
                op(true);
                false
            }
        }
    }

    #[tracing::instrument(skip(self))]
    async fn cone_to_cone(self: Arc<Self>, task_info: PunchTaskInfo) -> Result<(), Error> {
        let mut backoff = BackOff::new(vec![1000, 1000, 2000, 4000, 4000, 8000, 8000, 16000]);

        loop {
            backoff.sleep_for_next_backoff().await;

            let ret = self
                .cone_client
                .do_hole_punching(task_info.dst_peer_id)
                .await;

            if self
                .handle_udp_transport_result(task_info.dst_peer_id, ret, Some(&mut backoff), None)
                .await
            {
                break;
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn sym_to_cone(self: Arc<Self>, task_info: PunchTaskInfo) -> Result<(), Error> {
        let mut backoff =
            BackOff::new(vec![1000, 1000, 2000, 4000, 4000, 8000, 8000, 16000, 64000]);
        let mut round = 0;
        let mut port_idx = rand::random();

        loop {
            backoff.sleep_for_next_backoff().await;

            // always try cone first
            if !RUN_TESTING.load(std::sync::atomic::Ordering::Relaxed) {
                let ret = self
                    .cone_client
                    .do_hole_punching(task_info.dst_peer_id)
                    .await;
                if self
                    .handle_udp_transport_result(task_info.dst_peer_id, ret, None, None)
                    .await
                {
                    break;
                }
            }

            let ret = {
                let _lock = get_sym_punch_lock(self.peer_mgr.my_peer_id())
                    .lock_owned()
                    .await;
                self.sym_to_cone_client
                    .do_hole_punching(
                        task_info.dst_peer_id,
                        round,
                        &mut port_idx,
                        task_info.my_nat_type,
                    )
                    .await
            };

            if self
                .handle_udp_transport_result(
                    task_info.dst_peer_id,
                    ret,
                    Some(&mut backoff),
                    Some(&mut round),
                )
                .await
            {
                break;
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn both_easy_sym(self: Arc<Self>, task_info: PunchTaskInfo) -> Result<(), Error> {
        let mut backoff =
            BackOff::new(vec![1000, 1000, 2000, 4000, 4000, 8000, 8000, 16000, 64000]);

        loop {
            backoff.sleep_for_next_backoff().await;

            // always try cone first
            if !RUN_TESTING.load(std::sync::atomic::Ordering::Relaxed) {
                let ret = self
                    .cone_client
                    .do_hole_punching(task_info.dst_peer_id)
                    .await;
                if self
                    .handle_udp_transport_result(task_info.dst_peer_id, ret, None, None)
                    .await
                {
                    break;
                }
            }

            let mut is_busy = false;

            let ret = {
                let _lock = get_sym_punch_lock(self.peer_mgr.my_peer_id())
                    .lock_owned()
                    .await;
                self.both_easy_sym_client
                    .do_hole_punching(
                        task_info.dst_peer_id,
                        task_info.my_nat_type,
                        task_info.dst_nat_type,
                        &mut is_busy,
                    )
                    .await
            };

            if is_busy {
                backoff.rollback();
            } else if self
                .handle_udp_transport_result(task_info.dst_peer_id, ret, Some(&mut backoff), None)
                .await
            {
                break;
            }
        }

        Ok(())
    }
}

#[derive(Clone)]
struct UdpHolePunchPeerTaskLauncher {}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct PunchTaskInfo {
    dst_peer_id: PeerId,
    dst_nat_type: UdpNatType,
    my_nat_type: UdpNatType,
    /// MP multi-punch slot (number of live punched carriers when the attempt
    /// was scheduled); always 0 for native punching.
    slot: u32,
    /// MP UDP punch toward an MP peer: also punches symmetric-to-symmetric
    /// (`get_punch_hole_method_for`); false keeps the native method choice.
    mp: bool,
}

#[async_trait::async_trait]
impl PeerTaskLauncher for UdpHolePunchPeerTaskLauncher {
    type Data = Arc<UdpHoePunchConnectorData>;
    type CollectPeerItem = PunchTaskInfo;
    type TaskRet = ();

    fn new_data(&self, peer_mgr: Arc<PeerManager>) -> Self::Data {
        UdpHoePunchConnectorData::new(peer_mgr)
    }

    async fn collect_peers_need_task(&self, data: &Self::Data) -> Vec<Self::CollectPeerItem> {
        let my_nat_type = data
            .peer_mgr
            .get_global_ctx()
            .get_stun_info_collector()
            .get_stun_info()
            .udp_nat_type;
        let my_nat_type: UdpNatType = NatType::try_from(my_nat_type)
            .unwrap_or(NatType::Unknown)
            .into();
        if !my_nat_type.is_sym() {
            data.sym_to_cone_client.clear_udp_array().await;
        }

        let mut peers_to_connect: Vec<Self::CollectPeerItem> = Vec::new();
        // do not do anything if:
        // 1. our nat type is OpenInternet or NoPat, which means we can wait other peers to connect us
        // notice that if we are unknown, we treat ourselves as cone
        if my_nat_type.is_open() {
            return peers_to_connect;
        }

        let my_peer_id = data.peer_mgr.my_peer_id();
        let flags = data.peer_mgr.get_global_ctx().get_flags();
        let lazy_p2p = flags.lazy_p2p;
        let now = Instant::now();

        data.blacklist.cleanup();

        #[cfg(feature = "mpquic")]
        let mut routed_peers = std::collections::HashSet::new();

        // collect peer list from peer manager and do some filter:
        // 1. peers without direct conns;
        // 2. peers is full cone (any restricted type);
        // 3. peers not in blacklist;
        for route in data.peer_mgr.list_routes().await.iter() {
            let mp = flags
                .mp
                .clone()
                .unwrap_or_else(crate::common::config::gen_default_mp_config);
            let udp_punch_provider_enabled = mp.providers.iter().any(|p| p == "udp-punch");

            let static_allowed = should_background_p2p_with_peer(
                route.feature_flag.as_ref(),
                false,
                lazy_p2p,
                flags.disable_p2p,
                flags.need_p2p,
            );
            let dynamic_allowed = should_try_p2p_with_peer(
                route.feature_flag.as_ref(),
                false,
                flags.disable_p2p,
                flags.need_p2p,
            ) && data.peer_mgr.has_recent_traffic(route.peer_id, now);
            #[cfg(feature = "mpquic")]
            let mp_udp_punch_allowed = should_collect_route_discovered_mp_udp_punch(
                route.feature_flag.as_ref(),
                mp.enabled,
                udp_punch_provider_enabled,
            );
            #[cfg(not(feature = "mpquic"))]
            let mp_udp_punch_allowed = false;

            // Keep the legacy policy intact, but let an enabled MP UDP-punch
            // provider supervise routed peers even when legacy automatic P2P
            // is disabled.  The later NAT/client capability checks still
            // decide whether a real raw punch can be attempted.
            if !static_allowed && !dynamic_allowed && !mp_udp_punch_allowed {
                continue;
            }

            let peer_nat_type = route
                .stun_info
                .as_ref()
                .map(|x| x.udp_nat_type)
                .unwrap_or(0);
            let Ok(peer_nat_type) = NatType::try_from(peer_nat_type) else {
                continue;
            };
            let peer_nat_type = peer_nat_type.into();

            let peer_id: PeerId = route.peer_id;
            #[cfg(feature = "mpquic")]
            routed_peers.insert(peer_id);

            // Check if peer is blacklisted
            if data.blacklist.contains(&peer_id) {
                tracing::debug!(?peer_id, "peer is blacklisted, skipping");
                continue;
            }

            let has_peer = data.peer_mgr.get_peer_map().has_peer(peer_id);
            let global_ctx = data.peer_mgr.get_global_ctx();
            if !my_nat_type.can_punch_hole_as_client(
                peer_nat_type,
                my_peer_id,
                peer_id,
                global_ctx.clone(),
                mp_udp_punch_allowed,
            ) {
                continue;
            }
            let slot = if mp_udp_punch_allowed {
                #[cfg(feature = "mpquic")]
                let slot = data.mp_punch_slot(peer_id, &mp).await;
                #[cfg(not(feature = "mpquic"))]
                let slot = (!has_peer).then_some(0);
                slot
            } else {
                (!has_peer).then_some(0)
            };
            let Some(slot) = slot else {
                continue;
            };

            tracing::info!(
                ?peer_id,
                ?peer_nat_type,
                ?my_nat_type,
                slot,
                "found peer to do hole punching"
            );

            peers_to_connect.push(PunchTaskInfo {
                dst_peer_id: peer_id,
                dst_nat_type: peer_nat_type,
                my_nat_type,
                slot,
                mp: mp_udp_punch_allowed,
            });
        }

        #[cfg(feature = "mpquic")]
        data.mp_punch_progress
            .retain(|peer_id, _| routed_peers.contains(peer_id));

        peers_to_connect
    }

    async fn launch_task(
        &self,
        data: &Self::Data,
        item: Self::CollectPeerItem,
    ) -> JoinHandle<Result<Self::TaskRet, Error>> {
        let data = data.clone();
        let global_ctx = data.peer_mgr.get_global_ctx();
        let punch_method = item
            .my_nat_type
            .get_punch_hole_method_for(item.dst_nat_type, global_ctx, item.mp);
        #[cfg(feature = "mpquic")]
        let in_flight = crate::connector::mp_session::MpPunchInFlight::new(
            data.clone(),
            |data| &data.mp_punch_progress,
            item.dst_peer_id,
            item.slot,
        );
        let punch = async move {
            #[cfg(feature = "mpquic")]
            let _in_flight = in_flight;
            match punch_method {
                UdpPunchClientMethod::ConeToCone => data.cone_to_cone(item).await,
                UdpPunchClientMethod::SymToCone => data.sym_to_cone(item).await,
                UdpPunchClientMethod::EasySymToEasySym => data.both_easy_sym(item).await,
                _ => unreachable!(),
            }
        };
        tokio::spawn(punch)
    }

    async fn all_task_done(&self, data: &Self::Data) {
        data.sym_to_cone_client.clear_udp_array().await;
    }

    fn loop_interval_ms(&self) -> u64 {
        5000
    }
}

pub struct UdpHolePunchConnector {
    server: Arc<UdpHolePunchServer>,
    client: PeerTaskManager<UdpHolePunchPeerTaskLauncher>,
    peer_mgr: Arc<PeerManager>,
}

// Currently support:
// Symmetric -> Full Cone
// Any Type of Full Cone -> Any Type of Full Cone

// if same level of full cone, node with smaller peer_id will be the initiator
// if different level of full cone, node with more strict level will be the initiator

impl UdpHolePunchConnector {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        Self {
            server: UdpHolePunchServer::new(peer_mgr.clone()),
            client: PeerTaskManager::new_with_external_signal(
                UdpHolePunchPeerTaskLauncher {},
                peer_mgr.clone(),
                Some(peer_mgr.p2p_demand_notify()),
            ),
            peer_mgr,
        }
    }

    pub async fn run_as_client(&mut self) -> Result<(), Error> {
        self.client.start();
        Ok(())
    }

    pub async fn run_as_server(&mut self) -> Result<(), Error> {
        self.peer_mgr
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                UdpHolePunchRpcServer::new(Arc::downgrade(&self.server)),
                &self.peer_mgr.get_global_ctx().get_network_name(),
            );

        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        let global_ctx = self.peer_mgr.get_global_ctx();

        if global_ctx.get_flags().disable_udp_hole_punching {
            return Ok(());
        }

        self.run_as_client().await?;
        self.run_as_server().await?;

        Ok(())
    }

    #[cfg(test)]
    pub async fn run_immediately_for_test(&self) {
        self.client.run_immediately().await;
    }
}

#[cfg(test)]
pub mod tests {

    use std::sync::Arc;
    use std::time::Duration;

    use crate::common::stun::MockStunInfoCollector;
    use crate::peers::{
        peer_manager::PeerManager,
        peer_task::PeerTaskLauncher,
        tests::{connect_peer_manager, create_mock_peer_manager, wait_route_appear},
    };
    use crate::proto::common::NatType;
    use crate::tunnel::common::tests::wait_for_condition;

    use super::{RUN_TESTING, UdpHolePunchConnector, UdpHolePunchPeerTaskLauncher};

    #[cfg(feature = "mpquic")]
    use super::should_collect_route_discovered_mp_udp_punch;

    #[cfg(feature = "mpquic")]
    #[test]
    fn mp_udp_punch_policy_is_independent_from_legacy_disable_p2p() {
        use crate::connector::should_background_p2p_with_peer;

        assert!(
            !should_background_p2p_with_peer(None, false, false, true, false),
            "disable_p2p must continue to suppress legacy automatic P2P"
        );
        let mp_peer = crate::proto::common::PeerFeatureFlag {
            mp_enabled: true,
            ..Default::default()
        };
        assert!(
            should_collect_route_discovered_mp_udp_punch(Some(&mp_peer), true, true),
            "an enabled MP UDP-punch provider must still supervise a routed MP peer"
        );
        assert!(
            !should_collect_route_discovered_mp_udp_punch(
                Some(&crate::proto::common::PeerFeatureFlag {
                    is_public_server: true,
                    ..mp_peer
                }),
                true,
                true,
            ),
            "the discovery relay must not be recycled as an MP direct-punch target"
        );
        for peer in [None, Some(&crate::proto::common::PeerFeatureFlag::default())] {
            assert!(
                !should_collect_route_discovered_mp_udp_punch(peer, true, true),
                "a peer without MP never takes an MP carrier, so MP must not punch it"
            );
        }
    }

    #[cfg(feature = "mpquic")]
    fn enable_mp_udp_punch(peer_mgr: &PeerManager, punch_attempts: u32) {
        let mut flags = peer_mgr.get_global_ctx().get_flags();
        let mut mp = crate::common::config::gen_default_mp_config();
        mp.enabled = true;
        mp.providers = vec!["udp-punch".into()];
        mp.punch_attempts = punch_attempts;
        flags.mp = Some(mp);
        peer_mgr.get_global_ctx().set_flags(flags);
    }

    pub fn replace_stun_info_collector(peer_mgr: Arc<PeerManager>, udp_nat_type: NatType) {
        let collector = Box::new(MockStunInfoCollector { udp_nat_type });
        peer_mgr
            .get_global_ctx()
            .replace_stun_info_collector(collector);
    }

    pub async fn create_mock_peer_manager_with_mock_stun(
        udp_nat_type: NatType,
    ) -> Arc<PeerManager> {
        let p_a = create_mock_peer_manager().await;
        let mut flags = p_a.get_global_ctx().get_flags();
        flags.disable_upnp = true;
        p_a.get_global_ctx().set_flags(flags);
        replace_stun_info_collector(p_a.clone(), udp_nat_type);
        p_a
    }

    async fn collect_lazy_punch_peers(peer_mgr: Arc<PeerManager>) -> Vec<u32> {
        let launcher = UdpHolePunchPeerTaskLauncher {};
        let data = launcher.new_data(peer_mgr);
        launcher
            .collect_peers_need_task(&data)
            .await
            .into_iter()
            .map(|task| task.dst_peer_id)
            .collect()
    }

    /// A requester that names its transaction while selecting gets the registration confirmed
    /// (the echo); one that does not, as every older one, gets no echo and no registration.
    #[tokio::test]
    async fn select_punch_listener_registers_and_echoes_the_transaction() {
        use crate::proto::{
            peer_rpc::{SelectPunchListenerRequest, UdpHolePunchRpc},
            rpc_types::controller::BaseController,
        };

        let server = super::UdpHolePunchServer::new(
            create_mock_peer_manager_with_mock_stun(NatType::Restricted).await,
        );
        let select = |transaction_id| {
            server.select_punch_listener(
                BaseController::default(),
                SelectPunchListenerRequest {
                    prefer_port_mapping: true,
                    transaction_id,
                    ..Default::default()
                },
            )
        };
        let resp = select(Some(0)).await.unwrap();
        assert_eq!(resp.transaction_id, Some(0));
        let addr = std::net::SocketAddr::from(resp.listener_mapped_addr.unwrap());
        assert!(server.common.prepare_hole_punch(&addr, 0).await.is_err());

        let resp = select(None).await.unwrap();
        assert_eq!(resp.transaction_id, None);
        // nothing was registered for it, on whichever listener it got
        let other = std::net::SocketAddr::from(resp.listener_mapped_addr.unwrap());
        server.common.prepare_hole_punch(&other, 1).await.unwrap();
        server.common.prepare_hole_punch(&addr, 2).await.unwrap();
    }

    #[rstest::rstest]
    #[tokio::test]
    pub async fn test_hole_punching_blacklist(
        #[values(NatType::Symmetric, NatType::PortRestricted, NatType::Unknown)] nat_type: NatType,
    ) {
        RUN_TESTING.store(true, std::sync::atomic::Ordering::Relaxed);

        let p_a = create_mock_peer_manager_with_mock_stun(nat_type).await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let mut hole_punching_a = UdpHolePunchConnector::new(p_a.clone());

        hole_punching_a.run().await.unwrap();

        hole_punching_a.client.run_immediately().await;

        wait_for_condition(
            || async {
                hole_punching_a
                    .client
                    .data()
                    .blacklist
                    .contains(&p_c.my_peer_id())
            },
            Duration::from_secs(10),
        )
        .await;
    }

    #[tokio::test]
    async fn lazy_p2p_collects_udp_hole_punch_tasks_only_after_recent_traffic() {
        let p_a = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;

        let mut flags = p_a.get_global_ctx().get_flags();
        flags.lazy_p2p = true;
        p_a.get_global_ctx().set_flags(flags);

        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        assert!(
            !collect_lazy_punch_peers(p_a.clone())
                .await
                .contains(&p_c.my_peer_id())
        );

        p_a.mark_recent_traffic(p_c.my_peer_id());

        assert!(
            collect_lazy_punch_peers(p_a.clone())
                .await
                .contains(&p_c.my_peer_id())
        );
    }

    #[cfg(feature = "mpquic")]
    #[tokio::test]
    async fn disabled_legacy_p2p_still_collects_route_discovered_mp_udp_punch_task() {
        let p_a = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;

        enable_mp_udp_punch(&p_a, crate::common::config::gen_default_mp_config().punch_attempts);
        let mut flags = p_a.get_global_ctx().get_flags();
        flags.disable_p2p = true;
        p_a.get_global_ctx().set_flags(flags);
        enable_mp_udp_punch(&p_c, crate::common::config::gen_default_mp_config().punch_attempts);

        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        assert!(
            collect_lazy_punch_peers(p_a)
                .await
                .contains(&p_c.my_peer_id()),
            "a routed peer must enter the MP UDP-punch supervisor despite disable_p2p"
        );
    }

    #[cfg(feature = "mpquic")]
    #[tokio::test]
    async fn mp_punch_collects_one_task_per_peer_and_keeps_native_skip_when_mp_is_off() {
        let p_a = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_d = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        enable_mp_udp_punch(&p_b, 4);
        enable_mp_udp_punch(&p_c, 4);
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        // p_d runs no MP (an official build, or MP off) and is directly connected.
        connect_peer_manager(p_a.clone(), p_d.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();
        wait_route_appear(p_a.clone(), p_d.clone()).await.unwrap();

        let launcher = UdpHolePunchPeerTaskLauncher {};
        let data = launcher.new_data(p_a.clone());

        // MP off: native behavior, the directly connected peers are skipped.
        let tasks = launcher.collect_peers_need_task(&data).await;
        assert!(tasks.iter().all(|task| task.dst_peer_id != p_b.my_peer_id()));
        assert!(tasks.iter().all(|task| task.dst_peer_id != p_d.my_peer_id()));
        assert!(tasks.iter().all(|task| task.slot == 0));

        enable_mp_udp_punch(&p_a, 4);

        // MP on without punched carriers: exactly one task per MP peer, slot
        // 0, even for a directly connected peer.
        let tasks = launcher.collect_peers_need_task(&data).await;
        for peer in [p_b.my_peer_id(), p_c.my_peer_id()] {
            let peer_tasks: Vec<_> = tasks.iter().filter(|t| t.dst_peer_id == peer).collect();
            assert_eq!(peer_tasks.len(), 1, "one scheduler entry per peer, not per NIC");
            assert_eq!(peer_tasks[0].slot, 0);
        }
        // A punch toward a peer without MP never becomes an MP carrier, so MP
        // would re-punch it forever: it keeps the native skip.
        assert!(
            tasks.iter().all(|task| task.dst_peer_id != p_d.my_peer_id()),
            "a directly connected peer without MP must not be punched again"
        );
    }

    #[cfg(feature = "mpquic")]
    #[tokio::test]
    async fn symmetric_to_symmetric_is_punched_only_by_mp() {
        let p_a = create_mock_peer_manager_with_mock_stun(NatType::Symmetric).await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(NatType::Symmetric).await;
        enable_mp_udp_punch(&p_c, 1);
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        assert!(
            !collect_lazy_punch_peers(p_a.clone())
                .await
                .contains(&p_c.my_peer_id()),
            "MP off: two symmetric NATs keep the native no-punch decision"
        );

        enable_mp_udp_punch(&p_a, 1);
        assert!(
            collect_lazy_punch_peers(p_a.clone())
                .await
                .contains(&p_c.my_peer_id()),
            "MP on: a symmetric MP peer behind a symmetric NAT is punched"
        );

        let mut flags = p_a.get_global_ctx().get_flags();
        flags.disable_sym_hole_punching = true;
        p_a.get_global_ctx().set_flags(flags);
        assert!(
            !collect_lazy_punch_peers(p_a)
                .await
                .contains(&p_c.my_peer_id()),
            "disable_sym_hole_punching still turns symmetric punching off under MP"
        );
    }
}

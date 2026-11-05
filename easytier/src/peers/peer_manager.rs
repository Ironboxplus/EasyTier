use anyhow::Context;
use async_trait::async_trait;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use dashmap::DashMap;
use hotpath::instant::Instant;
use std::collections::BTreeSet;
use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Weak, atomic::AtomicBool},
    time::{Duration, SystemTime},
};

#[cfg(feature = "mpquic")]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "hotpath")]
use hotpath::wrap::tokio::sync::{Mutex, RwLock};
#[cfg(not(feature = "hotpath"))]
use tokio::sync::{Mutex, RwLock};
use tokio::{
    sync::{
        OnceCell,
        mpsc::{self, UnboundedReceiver, UnboundedSender},
    },
    task::JoinSet,
};

#[cfg(feature = "mpquic")]
use crate::common::egress_inventory::EgressInventoryEvent;
#[cfg(feature = "mpquic")]
use crate::connector::{
    mp_relay::{RelayDatagram, RelayNextHopTransport, relay_path_spec},
    mp_session::{MpSessionManager, OfferPathResult},
};

use crate::{
    common::{
        PeerId,
        compressor::{Compressor as _, DefaultCompressor},
        constants::EASYTIER_VERSION,
        egress_inventory::{EgressInventory, EgressInventoryConfig, InventoryError},
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent, NetworkIdentity},
        shrink_dashmap,
        stats_manager::{CounterHandle, LabelSet, LabelType, MetricName},
        stun::StunInfoCollectorTrait,
    },
    peers::{
        PeerPacketFilter,
        peer_conn::PeerConn,
        peer_rpc::PeerRpcManagerTransport,
        peer_session::PeerSessionStore,
        recv_packet_from_chan,
        route_trait::{
            ForeignNetworkRouteInfoMap, MockRoute, NextHopPolicy, RouteInterface,
            mp_weighted_enabled,
        },
        traffic_metrics::{
            InstanceLabelKind, LogicalTrafficMetrics, TrafficKind, TrafficMetricRecorder,
            is_relay_data_packet_type, route_peer_info_instance_id, traffic_kind,
        },
    },
    proto::{
        api::instance::{
            self, ListGlobalForeignNetworkResponse,
            list_global_foreign_network_response::OneForeignNetwork,
        },
        peer_rpc::{
            ForeignNetworkRouteInfoEntry, ForeignNetworkRouteInfoKey, PeerIdentityType,
            RouteForeignNetworkSummary,
        },
    },
    tunnel::{
        self, Tunnel, TunnelConnector,
        packet_def::{CompressorAlgo, PacketType, ZCPacket},
    },
};

use super::{
    BoxNicPacketFilter, BoxPeerPacketFilter, PacketRecvChan, PacketRecvChanReceiver,
    create_packet_recv_chan,
    encrypt::{Encryptor, NullCipher},
    foreign_network_client::ForeignNetworkClient,
    foreign_network_manager::{ForeignNetworkManager, GlobalForeignNetworkAccessor},
    peer_conn::PeerConnId,
    peer_map::PeerMap,
    peer_ospf_route::PeerRoute,
    peer_rpc::PeerRpcManager,
    peer_task::ExternalTaskSignal,
    relay_peer_map::RelayPeerMap,
    route_trait::{ArcRoute, Route},
};

/// Relay paths offered to one peer, through the fastest first hops. A TQUIC
/// connection holds at most `MP_ACTIVE_CONNECTION_ID_LIMIT` (16; 8 toward an
/// older peer) paths: a relay
/// path through every first hop would take every slot and leave none for the
/// punched direct paths (up to `punch_attempts`, 6 on a multi-WAN host).
#[cfg(feature = "mpquic")]
const MP_RELAY_PATH_BUDGET: usize = 2;

struct RpcTransport {
    my_peer_id: PeerId,
    peers: Weak<PeerMap>,
    // TODO: this seems can be removed
    foreign_peers: Mutex<Option<Weak<ForeignNetworkClient>>>,

    packet_recv: Mutex<UnboundedReceiver<ZCPacket>>,
    peer_rpc_tspt_sender: UnboundedSender<ZCPacket>,

    encryptor: Arc<dyn Encryptor>,
    is_secure_mode_enabled: bool,
}

#[async_trait::async_trait]
impl PeerRpcManagerTransport for RpcTransport {
    fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    async fn send(&self, mut msg: ZCPacket, dst_peer_id: PeerId) -> Result<(), Error> {
        let peers = self.peers.upgrade().ok_or(Error::Unknown)?;
        // NOTE: if route info is not exchanged, this will return None. treat it as public server.
        let is_dst_peer_public_server = peers
            .get_route_peer_info(dst_peer_id)
            .await
            .and_then(|x| x.feature_flag.map(|x| x.is_public_server))
            // if dst is directly connected, it's must not public server
            .unwrap_or(!peers.has_peer(dst_peer_id));
        if !is_dst_peer_public_server && !self.is_secure_mode_enabled {
            self.encryptor
                .encrypt(&mut msg)
                .with_context(|| "encrypt failed")?;
        }
        // send to self and this packet will be forwarded in peer_recv loop
        peers.send_msg_directly(msg, self.my_peer_id).await
    }

    async fn recv(&self) -> Result<ZCPacket, Error> {
        if let Some(o) = self.packet_recv.lock().await.recv().await {
            Ok(o)
        } else {
            Err(Error::Unknown)
        }
    }
}

pub enum RouteAlgoType {
    Ospf,
    None,
}

enum RouteAlgoInst {
    Ospf(Arc<PeerRoute>),
    None,
}

impl Clone for RouteAlgoInst {
    fn clone(&self) -> Self {
        match self {
            RouteAlgoInst::Ospf(route) => RouteAlgoInst::Ospf(route.clone()),
            RouteAlgoInst::None => RouteAlgoInst::None,
        }
    }
}

struct SelfTxCounters {
    self_tx_packets: CounterHandle,
    self_tx_bytes: CounterHandle,
    compress_tx_bytes_before: CounterHandle,
    compress_tx_bytes_after: CounterHandle,
}

pub struct PeerManager {
    my_peer_id: PeerId,

    global_ctx: ArcGlobalCtx,
    nic_channel: PacketRecvChan,

    tasks: Mutex<JoinSet<()>>,

    packet_recv: Arc<Mutex<Option<PacketRecvChanReceiver>>>,

    peers: Arc<PeerMap>,

    peer_rpc_mgr: Arc<PeerRpcManager>,
    peer_rpc_tspt: Arc<RpcTransport>,

    peer_packet_process_pipeline: Arc<RwLock<Vec<BoxPeerPacketFilter>>>,
    nic_packet_process_pipeline: Arc<RwLock<Vec<BoxNicPacketFilter>>>,

    route_algo_inst: RouteAlgoInst,

    foreign_network_manager: Arc<ForeignNetworkManager>,
    foreign_network_client: Arc<ForeignNetworkClient>,
    relay_peer_map: Arc<RelayPeerMap>,

    encryptor: Arc<dyn Encryptor + 'static>,
    data_compress_algo: CompressorAlgo,

    exit_nodes: RwLock<Vec<IpAddr>>,

    reserved_my_peer_id_map: DashMap<String, PeerId>,
    recent_have_traffic: Arc<DashMap<PeerId, Instant>>,
    p2p_demand_notify: Arc<ExternalTaskSignal>,

    allow_loopback_tunnel: AtomicBool,

    self_tx_counters: SelfTxCounters,
    traffic_metrics: Arc<TrafficMetricRecorder>,

    peer_session_store: Arc<PeerSessionStore>,
    egress_inventory: OnceCell<EgressInventory>,
    #[cfg(feature = "mpquic")]
    mp_session_manager: Arc<MpSessionManager>,
    #[cfg(feature = "mpquic")]
    mp_relay_transport: Arc<RelayNextHopTransport>,
    #[cfg(feature = "mpquic")]
    mp_relay_outbound_rx: Mutex<Option<mpsc::Receiver<RelayDatagram>>>,
    #[cfg(feature = "mpquic")]
    mp_relay_tunnel_tx: UnboundedSender<Box<dyn Tunnel>>,
    #[cfg(feature = "mpquic")]
    mp_relay_tunnel_rx: Mutex<Option<UnboundedReceiver<Box<dyn Tunnel>>>>,
    #[cfg(feature = "mpquic")]
    mp_relay_route_generation: Arc<AtomicU64>,
    /// A relay reconcile pass is running; the control loop never waits for it.
    #[cfg(feature = "mpquic")]
    mp_relay_reconciling: Arc<AtomicBool>,
    /// (destination, first hop) -> (last offer, offers since the path was last live).
    #[cfg(feature = "mpquic")]
    mp_relay_offer_backoff: DashMap<(PeerId, PeerId), (std::time::Instant, u32)>,
    is_secure_mode_enabled: bool,
}

impl Debug for PeerManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerManager")
            .field("my_peer_id", &self.my_peer_id())
            .field("instance_name", &self.global_ctx.inst_name)
            .field("net_ns", &self.global_ctx.net_ns.name())
            .finish()
    }
}

impl PeerManager {
    // Keep lazy-p2p demand alive across the 5s task rescan interval and a full on-demand
    // connect attempt, without retaining extra per-task state in the hot path.
    const RECENT_HAVE_TRAFFIC_TTL: Duration = Duration::from_secs(30);

    fn should_mark_recent_traffic_for_fanout(total_dst_peers: usize) -> bool {
        total_dst_peers <= 1
    }

    fn gc_recent_traffic_entries<F>(
        recent_have_traffic: &DashMap<PeerId, Instant>,
        now: Instant,
        mut has_directly_connected_conn: F,
    ) where
        F: FnMut(PeerId) -> bool,
    {
        let mut to_remove = Vec::new();
        for entry in recent_have_traffic.iter() {
            let peer_id = *entry.key();
            let expired =
                now.saturating_duration_since(*entry.value()) > Self::RECENT_HAVE_TRAFFIC_TTL;
            if expired || has_directly_connected_conn(peer_id) {
                to_remove.push(peer_id);
            }
        }

        if !to_remove.is_empty() {
            for peer_id in to_remove {
                recent_have_traffic.remove(&peer_id);
            }
            shrink_dashmap(recent_have_traffic, None);
        }
    }

    pub fn new(
        route_algo: RouteAlgoType,
        global_ctx: ArcGlobalCtx,
        nic_channel: PacketRecvChan,
    ) -> Self {
        let my_peer_id = rand::random();

        let (packet_send, packet_recv) = create_packet_recv_chan();
        let peers = Arc::new(PeerMap::new(
            packet_send.clone(),
            global_ctx.clone(),
            my_peer_id,
        ));
        let peer_session_store = Arc::new(PeerSessionStore::new());

        let encryptor = if global_ctx.get_flags().enable_encryption {
            // 只有在启用加密时才使用工厂函数选择算法
            let algorithm = &global_ctx.get_flags().encryption_algorithm;
            super::encrypt::create_encryptor(
                algorithm,
                global_ctx.get_128_key(),
                global_ctx.get_256_key(),
            )
        } else {
            // disable_encryption = true 时使用 NullCipher
            Arc::new(NullCipher)
        };

        if global_ctx
            .check_network_in_whitelist(&global_ctx.get_network_name())
            .is_err()
        {
            // if local network is not in whitelist, avoid relay data when exist any other route path
            global_ctx.set_avoid_relay_data_preference(true);
        }

        let is_secure_mode_enabled = global_ctx
            .config
            .get_secure_mode()
            .map(|cfg| cfg.enabled)
            .unwrap_or(false);

        // TODO: remove these because we have impl pipeline processor.
        let (peer_rpc_tspt_sender, peer_rpc_tspt_recv) = mpsc::unbounded_channel();
        let rpc_tspt = Arc::new(RpcTransport {
            my_peer_id,
            peers: Arc::downgrade(&peers),
            foreign_peers: hotpath::mutex!(tokio::sync::Mutex::new(None)),
            packet_recv: hotpath::mutex!(tokio::sync::Mutex::new(peer_rpc_tspt_recv)),
            peer_rpc_tspt_sender,
            encryptor: encryptor.clone(),
            is_secure_mode_enabled,
        });
        let peer_rpc_mgr = Arc::new(PeerRpcManager::new_with_stats_manager(
            rpc_tspt.clone(),
            global_ctx.stats_manager().clone(),
        ));

        let route_algo_inst = match route_algo {
            RouteAlgoType::Ospf => RouteAlgoInst::Ospf(PeerRoute::new(
                my_peer_id,
                global_ctx.clone(),
                peer_rpc_mgr.clone(),
            )),
            RouteAlgoType::None => RouteAlgoInst::None,
        };

        let foreign_network_manager = Arc::new(ForeignNetworkManager::new(
            my_peer_id,
            global_ctx.clone(),
            peer_session_store.clone(),
            packet_send.clone(),
            Self::build_foreign_network_manager_accessor(&peers),
        ));
        let foreign_network_client = Arc::new(ForeignNetworkClient::new(
            global_ctx.clone(),
            packet_send,
            peer_rpc_mgr.clone(),
            my_peer_id,
        ));

        let data_compress_algo = global_ctx
            .get_flags()
            .data_compress_algo()
            .try_into()
            .expect("invalid data compress algo, maybe some features not enabled");

        let exit_nodes = global_ctx.config.get_exit_nodes();

        let stats_manager = global_ctx.stats_manager();
        let network_name = global_ctx.get_network_name();
        let traffic_tx_metrics = Arc::new(LogicalTrafficMetrics::new(
            stats_manager.clone(),
            network_name.clone(),
            MetricName::TrafficBytesTx,
            MetricName::TrafficPacketsTx,
            MetricName::TrafficBytesTxByInstance,
            MetricName::TrafficPacketsTxByInstance,
            InstanceLabelKind::To,
        ));
        let traffic_control_tx_metrics = Arc::new(LogicalTrafficMetrics::new(
            stats_manager.clone(),
            network_name.clone(),
            MetricName::TrafficControlBytesTx,
            MetricName::TrafficControlPacketsTx,
            MetricName::TrafficControlBytesTxByInstance,
            MetricName::TrafficControlPacketsTxByInstance,
            InstanceLabelKind::To,
        ));
        let relay_peer_map = RelayPeerMap::new(
            peers.clone(),
            Some(foreign_network_client.clone()),
            global_ctx.clone(),
            my_peer_id,
            peer_session_store.clone(),
        );
        let self_tx_counters = SelfTxCounters {
            self_tx_packets: stats_manager.get_counter(
                MetricName::TrafficPacketsSelfTx,
                LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone())),
            ),
            self_tx_bytes: stats_manager.get_counter(
                MetricName::TrafficBytesSelfTx,
                LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone())),
            ),
            compress_tx_bytes_before: stats_manager.get_counter(
                MetricName::CompressionBytesTxBefore,
                LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone())),
            ),
            compress_tx_bytes_after: stats_manager.get_counter(
                MetricName::CompressionBytesTxAfter,
                LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone())),
            ),
        };
        let traffic_rx_metrics = Arc::new(LogicalTrafficMetrics::new(
            stats_manager.clone(),
            network_name,
            MetricName::TrafficBytesRx,
            MetricName::TrafficPacketsRx,
            MetricName::TrafficBytesRxByInstance,
            MetricName::TrafficPacketsRxByInstance,
            InstanceLabelKind::From,
        ));
        let traffic_control_rx_metrics = Arc::new(LogicalTrafficMetrics::new(
            stats_manager.clone(),
            global_ctx.get_network_name(),
            MetricName::TrafficControlBytesRx,
            MetricName::TrafficControlPacketsRx,
            MetricName::TrafficControlBytesRxByInstance,
            MetricName::TrafficControlPacketsRxByInstance,
            InstanceLabelKind::From,
        ));
        let route_algo_inst_for_metrics = route_algo_inst.clone();
        let traffic_metrics = Arc::new(TrafficMetricRecorder::new(
            my_peer_id,
            traffic_tx_metrics,
            traffic_control_tx_metrics,
            traffic_rx_metrics,
            traffic_control_rx_metrics,
            move |peer_id| {
                let route_algo_inst = route_algo_inst_for_metrics.clone();
                async move {
                    match &route_algo_inst {
                        RouteAlgoInst::Ospf(route) => route
                            .get_peer_info(peer_id)
                            .await
                            .as_ref()
                            .and_then(route_peer_info_instance_id),
                        RouteAlgoInst::None => None,
                    }
                }
            },
        ));

        #[cfg(feature = "mpquic")]
        let mp_config = global_ctx
            .get_flags()
            .mp
            .unwrap_or_else(crate::common::config::gen_default_mp_config);
        #[cfg(feature = "mpquic")]
        let mp_egress_quality = global_ctx.egress_quality_manager().clone();
        #[cfg(feature = "mpquic")]
        let reflector_socket_mark = global_ctx.get_flags().socket_mark;
        #[cfg(feature = "mpquic")]
        let (mp_relay_transport, mp_relay_outbound_rx) = RelayNextHopTransport::new();
        #[cfg(feature = "mpquic")]
        let (mp_relay_tunnel_tx, mp_relay_tunnel_rx) = mpsc::unbounded_channel();

        PeerManager {
            my_peer_id,

            global_ctx,
            nic_channel,

            tasks: hotpath::mutex!(tokio::sync::Mutex::new(JoinSet::new())),

            packet_recv: Arc::new(hotpath::mutex!(tokio::sync::Mutex::new(Some(packet_recv)))),

            peers,

            peer_rpc_mgr,
            peer_rpc_tspt: rpc_tspt,

            peer_packet_process_pipeline: Arc::new(hotpath::rw_lock!(tokio::sync::RwLock::new(
                Vec::new()
            ))),
            nic_packet_process_pipeline: Arc::new(hotpath::rw_lock!(tokio::sync::RwLock::new(
                Vec::new()
            ))),

            route_algo_inst,

            foreign_network_manager,
            foreign_network_client,
            relay_peer_map,

            encryptor,
            data_compress_algo,

            exit_nodes: hotpath::rw_lock!(tokio::sync::RwLock::new(exit_nodes)),

            reserved_my_peer_id_map: DashMap::new(),
            recent_have_traffic: Arc::new(DashMap::new()),
            p2p_demand_notify: Arc::new(ExternalTaskSignal::new()),

            allow_loopback_tunnel: AtomicBool::new(true),

            self_tx_counters,
            traffic_metrics,

            peer_session_store,
            egress_inventory: OnceCell::new(),
            #[cfg(feature = "mpquic")]
            mp_session_manager: Arc::new(
                MpSessionManager::new_with_config(mp_config, mp_egress_quality)
                    .with_local_peer_id(my_peer_id)
                    .with_reflector_socket_mark(reflector_socket_mark),
            ),
            #[cfg(feature = "mpquic")]
            mp_relay_transport,
            #[cfg(feature = "mpquic")]
            mp_relay_outbound_rx: hotpath::mutex!(tokio::sync::Mutex::new(Some(
                mp_relay_outbound_rx
            ))),
            #[cfg(feature = "mpquic")]
            mp_relay_tunnel_tx,
            #[cfg(feature = "mpquic")]
            mp_relay_tunnel_rx: hotpath::mutex!(tokio::sync::Mutex::new(Some(mp_relay_tunnel_rx))),
            #[cfg(feature = "mpquic")]
            mp_relay_route_generation: Arc::new(AtomicU64::new(0)),
            #[cfg(feature = "mpquic")]
            mp_relay_reconciling: Arc::new(AtomicBool::new(false)),
            #[cfg(feature = "mpquic")]
            mp_relay_offer_backoff: DashMap::new(),
            is_secure_mode_enabled,
        }
    }

    pub fn set_allow_loopback_tunnel(&self, allow_loopback_tunnel: bool) {
        self.allow_loopback_tunnel
            .store(allow_loopback_tunnel, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn mark_recent_traffic(&self, dst_peer_id: PeerId) {
        if dst_peer_id == self.my_peer_id {
            return;
        }

        let flags = self.global_ctx.flags_arc();
        if flags.disable_p2p || !flags.lazy_p2p || self.has_directly_connected_conn(dst_peer_id) {
            return;
        }

        let now = Instant::now();
        if let Some(mut last_seen) = self.recent_have_traffic.get_mut(&dst_peer_id) {
            let should_notify =
                now.saturating_duration_since(*last_seen) > Self::RECENT_HAVE_TRAFFIC_TTL;
            *last_seen = now;
            if !should_notify {
                return;
            }
        } else {
            self.recent_have_traffic.insert(dst_peer_id, now);
        }
        self.p2p_demand_notify.notify();
    }

    pub fn has_recent_traffic(&self, peer_id: PeerId, now: Instant) -> bool {
        if self.has_directly_connected_conn(peer_id) {
            return false;
        }

        self.recent_have_traffic
            .get(&peer_id)
            .map(|last_seen| {
                now.saturating_duration_since(*last_seen) <= Self::RECENT_HAVE_TRAFFIC_TTL
            })
            .unwrap_or(false)
    }

    pub fn clear_recent_traffic(&self, peer_id: PeerId) {
        self.recent_have_traffic.remove(&peer_id);
    }

    pub fn p2p_demand_notify(&self) -> Arc<ExternalTaskSignal> {
        self.p2p_demand_notify.clone()
    }

    fn gc_recent_traffic(&self) {
        Self::gc_recent_traffic_entries(&self.recent_have_traffic, Instant::now(), |peer_id| {
            self.has_directly_connected_conn(peer_id)
        });
    }

    async fn close_untrusted_credential_peers(peer_map: &Arc<PeerMap>, global_ctx: &ArcGlobalCtx) {
        let network_name = global_ctx.get_network_name();
        for peer_id in peer_map.list_peers() {
            if !matches!(
                peer_map.get_peer_identity_type(peer_id),
                Some(PeerIdentityType::Credential)
            ) {
                continue;
            }
            let Some(peer) = peer_map.get_peer_by_id(peer_id) else {
                continue;
            };
            let Some(pubkey) = peer.get_peer_public_key() else {
                continue;
            };

            if global_ctx.is_pubkey_trusted(&pubkey, &network_name) {
                continue;
            }

            tracing::warn!(?peer_id, "closing untrusted credential peer");
            if let Err(e) = peer_map.close_peer(peer_id).await {
                tracing::warn!(?e, ?peer_id, "failed to close untrusted credential peer");
            }
        }
    }

    fn build_foreign_network_manager_accessor(
        peer_map: &Arc<PeerMap>,
    ) -> Box<dyn GlobalForeignNetworkAccessor> {
        struct T {
            peer_map: Weak<PeerMap>,
        }

        #[async_trait::async_trait]
        impl GlobalForeignNetworkAccessor for T {
            async fn list_global_foreign_peer(
                &self,
                network_identity: &NetworkIdentity,
            ) -> Vec<PeerId> {
                let Some(peer_map) = self.peer_map.upgrade() else {
                    return vec![];
                };

                peer_map
                    .list_peers_own_foreign_network(network_identity)
                    .await
            }
        }

        Box::new(T {
            peer_map: Arc::downgrade(peer_map),
        })
    }

    // `mut` is only needed for `take_mp_session_handle()` below, which is
    // itself `#[cfg(feature = "mpquic")]`.
    #[cfg_attr(not(feature = "mpquic"), allow(unused_mut))]
    async fn add_new_peer_conn(&self, mut peer_conn: PeerConn) -> Result<(), Error> {
        let my_identity = self.global_ctx.get_network_identity();
        let peer_identity = peer_conn.get_network_identity();
        let conn_info = peer_conn.get_conn_info();
        let local_secure_mode = self
            .global_ctx
            .config
            .get_secure_mode()
            .as_ref()
            .map(|cfg| cfg.enabled)
            .unwrap_or(false);
        let peer_secure_mode = !conn_info.noise_remote_static_pubkey.is_empty();

        if local_secure_mode != peer_secure_mode {
            return Err(Error::SecretKeyError(
                "same-network peers must use the same secure mode".to_string(),
            ));
        }

        // For credential nodes, network_secret_digest is either None or all-zeros
        // (all-zeros when received over the wire via handshake).
        // In this case, only compare network_name.
        let my_digest_empty = my_identity
            .network_secret_digest
            .as_ref()
            .is_none_or(|d| d.iter().all(|b| *b == 0));
        let peer_digest_empty = peer_identity
            .network_secret_digest
            .as_ref()
            .is_none_or(|d| d.iter().all(|b| *b == 0));

        let identity_ok = if my_digest_empty || peer_digest_empty {
            // Credential node: only check network_name
            my_identity.network_name == peer_identity.network_name
        } else {
            my_identity == peer_identity
        };

        if !identity_ok {
            return Err(Error::SecretKeyError(
                "network identity not match".to_string(),
            ));
        }
        let peer_id = peer_conn.get_peer_id();
        // MP_SQM_PLAN.md S1.4: capture before handing `peer_conn` to the peer
        // map below, which takes ownership of it.
        #[cfg(feature = "mpquic")]
        let standalone_mp_session_handle = peer_conn.take_mp_session_handle();
        #[cfg(feature = "mpquic")]
        let standalone_mp_congestion_control = peer_conn.mp_congestion_control();
        self.peers.add_new_peer_conn(peer_conn).await?;
        self.clear_recent_traffic(peer_id);
        #[cfg(feature = "mpquic")]
        if let Some(handle) = standalone_mp_session_handle {
            self.mp_session_manager.register_standalone_session(
                peer_id,
                handle,
                // Both are captured from the same standalone tunnel at
                // `PeerConn` construction, so this is always `Some` in
                // practice; fall back to the same default MP-managed
                // sessions report so a future refactor that decouples them
                // fails safe instead of relabeling a real profile.
                standalone_mp_congestion_control.unwrap_or("engine-default"),
                !conn_info.is_client,
            ).await;
        }
        Ok(())
    }

    pub async fn add_client_tunnel(
        &self,
        tunnel: Box<dyn Tunnel>,
        is_directly_connected: bool,
    ) -> Result<(PeerId, PeerConnId), Error> {
        self.add_client_tunnel_with_peer_id_hint(tunnel, is_directly_connected, None)
            .await
    }

    pub async fn add_client_tunnel_with_peer_id_hint(
        &self,
        tunnel: Box<dyn Tunnel>,
        is_directly_connected: bool,
        peer_id_hint: Option<PeerId>,
    ) -> Result<(PeerId, PeerConnId), Error> {
        let mut peer = PeerConn::new_with_peer_id_hint(
            self.my_peer_id,
            self.global_ctx.clone(),
            tunnel,
            peer_id_hint,
            self.peer_session_store.clone(),
        );
        peer.set_is_hole_punched(!is_directly_connected);
        peer.do_handshake_as_client().await?;
        let conn_id = peer.get_conn_id();
        let peer_id = peer.get_peer_id();
        if peer.get_network_identity().network_name
            == self.global_ctx.get_network_identity().network_name
        {
            self.add_new_peer_conn(peer).await?;
        } else {
            self.foreign_network_client.add_new_peer_conn(peer).await?;
        }
        Ok((peer_id, conn_id))
    }

    pub fn has_directly_connected_conn(&self, peer_id: PeerId) -> bool {
        if let Some(peer) = self.peers.get_peer_by_id(peer_id) {
            peer.has_directly_connected_conn()
        } else {
            self.foreign_network_client.get_peer_map().has_peer(peer_id)
        }
    }

    #[tracing::instrument]
    pub async fn try_direct_connect<C>(&self, connector: C) -> Result<(PeerId, PeerConnId), Error>
    where
        C: TunnelConnector + Debug,
    {
        self.try_direct_connect_with_peer_id_hint(connector, None)
            .await
    }

    #[tracing::instrument]
    pub async fn try_direct_connect_with_peer_id_hint<C>(
        &self,
        connector: C,
        peer_id_hint: Option<PeerId>,
    ) -> Result<(PeerId, PeerConnId), Error>
    where
        C: TunnelConnector + Debug,
    {
        let t = self.connect_tunnel(connector).await?;
        self.add_client_tunnel_with_peer_id_hint(t, true, peer_id_hint)
            .await
    }

    pub(crate) async fn connect_tunnel<C>(&self, mut connector: C) -> Result<Box<dyn Tunnel>, Error>
    where
        C: TunnelConnector + Debug,
    {
        let ns = self.global_ctx.net_ns.clone();
        Ok(ns
            .run_async(|| async move { connector.connect().await })
            .await?)
    }

    // avoid loop back to virtual network
    fn check_remote_addr_not_from_virtual_network(
        &self,
        tunnel: &dyn Tunnel,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("check remote addr not from virtual network");
        let Some(tunnel_info) = tunnel.info() else {
            anyhow::bail!("tunnel info is not set");
        };
        let Some(src) = tunnel_info.remote_addr.map(url::Url::from) else {
            anyhow::bail!("tunnel info remote addr is not set");
        };
        if src.scheme() == "ring" {
            return Ok(());
        }
        let Ok(Some(addr)) = src.socket_addrs(|| Some(1)).map(|x| x.first().cloned()) else {
            // if the tunnel is not rely on ip address, skip check
            return Ok(());
        };

        // if no-tun is enabled, the src ip of packet in virtual network is converted to loopback address
        // we already filter out the connection in tcp/quic/kcp proxy so no need check here.
        if addr.ip().is_loopback() {
            // allow other loopback address, good for conn from cdn/l4 connection
            return Ok(());
        }

        if self.global_ctx.is_ip_in_same_network(&addr.ip()) {
            anyhow::bail!(
                "tunnel src {} is from the same network (ignore this error please)",
                addr
            );
        }

        Ok(())
    }

    fn release_reserved_peer_id(&self, network_name: &str) {
        self.reserved_my_peer_id_map.remove(network_name);
        shrink_dashmap(&self.reserved_my_peer_id_map, None);
    }

    #[tracing::instrument(ret)]
    pub async fn add_tunnel_as_server(
        &self,
        tunnel: Box<dyn Tunnel>,
        is_directly_connected: bool,
    ) -> Result<(), Error> {
        tracing::info!("add tunnel as server start");
        self.check_remote_addr_not_from_virtual_network(&tunnel)?;

        let mut conn = PeerConn::new(
            self.my_peer_id,
            self.global_ctx.clone(),
            tunnel,
            self.peer_session_store.clone(),
        );
        let mut reserved_peer_id_network_name = None;
        let handshake_ret = conn.do_handshake_as_server_ext(|peer, network_name:&str| {
            if network_name
                == self.global_ctx.get_network_identity().network_name
            {
                return Ok(());
            }

            let mut peer_id = self
                .foreign_network_manager
                .get_network_peer_id(network_name);
            if peer_id.is_none() {
                reserved_peer_id_network_name = Some(network_name.to_string());
                peer_id = Some(*self.reserved_my_peer_id_map.entry(network_name.to_string()).or_insert_with(|| {
                    rand::random::<PeerId>()
                }).value());
            }
            peer.set_peer_id(peer_id.unwrap());

            tracing::info!(
                ?peer_id,
                ?network_name,
                "handshake as server with foreign network, new peer id: {}, peer id in foreign manager: {:?}",
                peer.get_my_peer_id(), peer_id
            );

            Ok(())
        })
        .await;

        if let Err(err) = handshake_ret {
            if let Some(network_name) = reserved_peer_id_network_name {
                self.release_reserved_peer_id(&network_name);
            }
            return Err(err);
        }

        let peer_identity = conn.get_network_identity();
        let peer_network_name = peer_identity.network_name.clone();
        let my_identity = self.global_ctx.get_network_identity();
        let is_local_network = peer_network_name == my_identity.network_name;
        let trusted_foreign_credential =
            matches!(conn.get_peer_identity_type(), PeerIdentityType::Credential)
                && self
                    .foreign_network_manager
                    .is_existing_credential_pubkey_trusted(
                        &peer_network_name,
                        &conn.get_conn_info().noise_remote_static_pubkey,
                    );
        let foreign_network_allowed =
            conn.matches_local_network_secret() || trusted_foreign_credential;

        if !is_local_network && self.global_ctx.get_flags().private_mode && !foreign_network_allowed
        {
            self.release_reserved_peer_id(&peer_network_name);
            return Err(Error::SecretKeyError(
                "private mode is turned on, foreign network secret mismatch".to_string(),
            ));
        }

        conn.set_is_hole_punched(!is_directly_connected);

        let add_peer_ret = if is_local_network {
            self.add_new_peer_conn(conn).await
        } else {
            self.foreign_network_manager.add_peer_conn(conn).await
        };

        if let Err(err) = add_peer_ret {
            self.release_reserved_peer_id(&peer_network_name);
            return Err(err);
        }

        self.release_reserved_peer_id(&peer_network_name);

        tracing::info!("add tunnel as server done");
        Ok(())
    }

    async fn try_handle_foreign_network_packet(
        mut packet: ZCPacket,
        my_peer_id: PeerId,
        peer_map: &PeerMap,
        foreign_network_mgr: &ForeignNetworkManager,
        disable_relay_data: bool,
    ) -> Result<(), ZCPacket> {
        let pm_header = packet.peer_manager_header().unwrap();
        if pm_header.packet_type != PacketType::ForeignNetworkPacket as u8 {
            return Err(packet);
        }

        let from_peer_id = pm_header.from_peer_id.get();
        let to_peer_id = pm_header.to_peer_id.get();

        if disable_relay_data && Self::is_relay_data_zc_packet(&packet) {
            tracing::debug!(
                ?from_peer_id,
                ?to_peer_id,
                inner_packet_type = ?packet.foreign_network_inner_packet_type(),
                "drop foreign network relay data while relay data is disabled"
            );
            return Ok(());
        }

        let foreign_hdr = packet.foreign_network_hdr().unwrap();
        let foreign_network_name = foreign_hdr.get_network_name(packet.payload());
        let foreign_peer_id = foreign_hdr.get_dst_peer_id();

        let foreign_network_my_peer_id =
            foreign_network_mgr.get_network_peer_id(&foreign_network_name);

        let buf_len = packet.buf_len();
        let stats_manager = peer_map.get_global_ctx().stats_manager().clone();
        let label_set =
            LabelSet::new().with_label_type(LabelType::NetworkName(foreign_network_name.clone()));
        let add_counter = move |bytes_metric, packets_metric| {
            stats_manager
                .get_counter(bytes_metric, label_set.clone())
                .add(buf_len as u64);
            stats_manager.get_counter(packets_metric, label_set).inc();
        };

        // NOTICE: the to peer id is modified by the src from foreign network my peer id to the origin my peer id
        if to_peer_id == my_peer_id {
            // packet sent from other peer to me, extract the inner packet and forward it
            add_counter(
                MetricName::TrafficBytesForeignForwardRx,
                MetricName::TrafficPacketsForeignForwardRx,
            );
            if let Err(e) = foreign_network_mgr
                .forward_foreign_network_packet(
                    &foreign_network_name,
                    foreign_peer_id,
                    packet.foreign_network_packet(),
                )
                .await
            {
                tracing::debug!(
                    ?e,
                    ?foreign_network_name,
                    ?foreign_peer_id,
                    "foreign network mgr send_msg_to_peer failed"
                );
            }
            Ok(())
        } else if Some(from_peer_id) == foreign_network_my_peer_id {
            // to_peer_id is my peer id for the foreign network, need to convert to the origin my_peer_id of dst
            let Some(to_peer_id) = peer_map
                .get_origin_my_peer_id(&foreign_network_name, to_peer_id)
                .await
            else {
                tracing::debug!(
                    ?foreign_network_name,
                    ?to_peer_id,
                    "cannot find origin my peer id for foreign network."
                );
                return Err(packet);
            };

            add_counter(
                MetricName::TrafficBytesForeignForwardTx,
                MetricName::TrafficPacketsForeignForwardTx,
            );

            // modify the to_peer id from foreign network my peer id to the origin my peer id
            packet
                .mut_peer_manager_header()
                .unwrap()
                .to_peer_id
                .set(to_peer_id);

            // packet is generated from foreign network mgr and should be forward to other peer
            if let Err(e) = peer_map
                .send_msg(packet, to_peer_id, NextHopPolicy::LeastHop)
                .await
            {
                tracing::debug!(
                    ?e,
                    ?to_peer_id,
                    "send_msg_directly failed when forward local generated foreign network packet"
                );
            }
            Ok(())
        } else {
            // target is not me, forward it. try get origin peer id
            add_counter(
                MetricName::TrafficBytesForeignForwardForwarded,
                MetricName::TrafficPacketsForeignForwardForwarded,
            );
            Err(packet)
        }
    }

    fn is_relay_data_packet(packet_type: u8) -> bool {
        is_relay_data_packet_type(packet_type)
    }

    fn is_relay_data_zc_packet(packet: &ZCPacket) -> bool {
        let Some(hdr) = packet.peer_manager_header() else {
            return false;
        };

        if hdr.packet_type == PacketType::ForeignNetworkPacket as u8 {
            let inner_packet_type = packet.foreign_network_inner_packet_type();
            if inner_packet_type.is_none() {
                tracing::warn!(
                    ?hdr,
                    "foreign network packet has unparseable inner peer manager header"
                );
            }
            return inner_packet_type.is_none_or(Self::is_relay_data_packet);
        }

        Self::is_relay_data_packet(hdr.packet_type)
    }

    async fn start_peer_recv(&self) {
        let mut recv = self.packet_recv.lock().await.take().unwrap();
        let my_peer_id = self.my_peer_id;
        let peers = self.peers.clone();
        let pipe_line = self.peer_packet_process_pipeline.clone();
        let foreign_client = self.foreign_network_client.clone();
        let relay_peer_map = self.relay_peer_map.clone();
        let foreign_mgr = self.foreign_network_manager.clone();
        let encryptor = self.encryptor.clone();
        let compress_algo = self.data_compress_algo;
        let acl_filter = self.global_ctx.get_acl_filter().clone();
        let global_ctx = self.global_ctx.clone();
        let secure_mode_enabled = self.is_secure_mode_enabled;
        let stats_mgr = self.global_ctx.stats_manager().clone();
        let route = self.get_route();
        let is_credential_node = self
            .global_ctx
            .get_network_identity()
            .network_secret
            .is_none()
            && secure_mode_enabled;

        let label_set =
            LabelSet::new().with_label_type(LabelType::NetworkName(global_ctx.get_network_name()));

        let self_tx_bytes = self.self_tx_counters.self_tx_bytes.clone();
        let self_tx_packets = self.self_tx_counters.self_tx_packets.clone();
        let self_rx_bytes =
            stats_mgr.get_counter(MetricName::TrafficBytesSelfRx, label_set.clone());
        let self_rx_packets =
            stats_mgr.get_counter(MetricName::TrafficPacketsSelfRx, label_set.clone());
        let forward_data_tx_bytes =
            stats_mgr.get_counter(MetricName::TrafficBytesForwarded, label_set.clone());
        let forward_data_tx_packets =
            stats_mgr.get_counter(MetricName::TrafficPacketsForwarded, label_set.clone());
        let forward_control_tx_bytes =
            stats_mgr.get_counter(MetricName::TrafficControlBytesForwarded, label_set.clone());
        let forward_control_tx_packets = stats_mgr.get_counter(
            MetricName::TrafficControlPacketsForwarded,
            label_set.clone(),
        );

        let compress_tx_bytes_before = self.self_tx_counters.compress_tx_bytes_before.clone();
        let compress_tx_bytes_after = self.self_tx_counters.compress_tx_bytes_after.clone();
        let compress_rx_bytes_before =
            stats_mgr.get_counter(MetricName::CompressionBytesRxBefore, label_set.clone());
        let compress_rx_bytes_after =
            stats_mgr.get_counter(MetricName::CompressionBytesRxAfter, label_set.clone());
        let traffic_metrics = self.traffic_metrics.clone();

        self.tasks.lock().await.spawn(async move {
            tracing::trace!("start_peer_recv");
            while let Ok(ret) = recv_packet_from_chan(&mut recv).await {
                let disable_relay_data = global_ctx.flags_arc().disable_relay_data;
                let Err(mut ret) = Self::try_handle_foreign_network_packet(
                    ret,
                    my_peer_id,
                    &peers,
                    &foreign_mgr,
                    disable_relay_data,
                )
                .await
                else {
                    continue;
                };

                let buf_len = ret.buf_len();
                let is_relay_data_packet = Self::is_relay_data_zc_packet(&ret);
                let Some(hdr) = ret.mut_peer_manager_header() else {
                    tracing::warn!(?ret, "invalid packet, skip");
                    continue;
                };

                tracing::trace!(?hdr, "peer recv a packet...");
                let from_peer_id = hdr.from_peer_id.get();
                let to_peer_id = hdr.to_peer_id.get();
                let packet_type = hdr.packet_type;
                let is_encrypted = hdr.is_encrypted();
                if to_peer_id != my_peer_id {
                    if disable_relay_data && is_relay_data_packet {
                        tracing::debug!(
                            ?from_peer_id,
                            ?to_peer_id,
                            packet_type,
                            "drop forwarded relay data while relay data is disabled"
                        );
                        continue;
                    }

                    if hdr.forward_counter > 7 {
                        tracing::warn!(?hdr, "forward counter exceed, drop packet");
                        continue;
                    }

                    // Step 10b: credential nodes don't forward handshake packets
                    if is_credential_node
                        && (packet_type == PacketType::HandShake as u8
                            || packet_type == PacketType::NoiseHandshakeMsg1 as u8
                            || packet_type == PacketType::NoiseHandshakeMsg2 as u8
                            || packet_type == PacketType::NoiseHandshakeMsg3 as u8)
                    {
                        tracing::debug!("credential node dropping forwarded handshake packet");
                        continue;
                    }

                    if hdr.forward_counter > 2 && hdr.is_latency_first() {
                        tracing::trace!(?hdr, "set_latency_first false because too many hop");
                        hdr.set_latency_first(false);
                    }

                    hdr.forward_counter += 1;

                    if from_peer_id == my_peer_id {
                        compress_tx_bytes_before.add(buf_len as u64);

                        if packet_type == PacketType::Data as u8
                            || packet_type == PacketType::KcpSrc as u8
                            || packet_type == PacketType::KcpDst as u8
                        {
                            let _ = Self::try_compress_and_encrypt(
                                compress_algo,
                                &encryptor,
                                &mut ret,
                                secure_mode_enabled,
                            )
                            .await;
                        }

                        compress_tx_bytes_after.add(ret.buf_len() as u64);
                        self_tx_bytes.add(ret.buf_len() as u64);
                        self_tx_packets.inc();
                    } else {
                        match traffic_kind(packet_type) {
                            TrafficKind::Data => {
                                forward_data_tx_bytes.add(buf_len as u64);
                                forward_data_tx_packets.inc();
                            }
                            TrafficKind::Control => {
                                forward_control_tx_bytes.add(buf_len as u64);
                                forward_control_tx_packets.inc();
                            }
                        }
                    }

                    tracing::trace!(?to_peer_id, ?my_peer_id, "need forward");
                    let tx_metrics = if from_peer_id == my_peer_id {
                        Some(&traffic_metrics)
                    } else {
                        None
                    };
                    let ret = Self::send_msg_internal(
                        &peers,
                        &foreign_client,
                        &relay_peer_map,
                        tx_metrics,
                        ret,
                        to_peer_id,
                    )
                    .await;
                    if ret.is_err() {
                        tracing::error!(?ret, ?to_peer_id, ?from_peer_id, "forward packet error");
                    }
                } else {
                    if packet_type == PacketType::RelayHandshake as u8
                        || packet_type == PacketType::RelayHandshakeAck as u8
                    {
                        let _ = relay_peer_map.handle_handshake_packet(ret).await;
                        continue;
                    }
                    if !secure_mode_enabled {
                        if let Err(e) = encryptor.decrypt(&mut ret) {
                            tracing::error!(?e, "decrypt failed");
                            continue;
                        }
                    } else if is_encrypted {
                        match relay_peer_map.decrypt_if_needed(&mut ret).await {
                            Ok(true) => {}
                            Ok(false) => {
                                tracing::error!("secure session not found");
                                continue;
                            }
                            Err(e) => {
                                tracing::error!(?e, "secure decrypt failed");
                                continue;
                            }
                        }
                    }

                    self_rx_bytes.add(buf_len as u64);
                    self_rx_packets.inc();
                    traffic_metrics
                        .record_rx(from_peer_id, packet_type, buf_len as u64)
                        .await;
                    compress_rx_bytes_before.add(buf_len as u64);

                    let compressor = DefaultCompressor {};
                    if let Err(e) = compressor.decompress(&mut ret).await {
                        tracing::error!(?e, "decompress failed");
                        continue;
                    }

                    compress_rx_bytes_after.add(ret.buf_len() as u64);

                    if !acl_filter.process_packet_with_acl(
                        &ret,
                        true,
                        global_ctx.get_ipv4().map(|x| x.address()),
                        |dst| global_ctx.is_ip_local_ipv6(&dst),
                        &route,
                    ) {
                        continue;
                    }

                    let mut processed = false;
                    let mut zc_packet = Some(ret);
                    tracing::trace!(?zc_packet, "try_process_packet_from_peer");
                    for pipeline in pipe_line.read().await.iter().rev() {
                        zc_packet = pipeline
                            .try_process_packet_from_peer(zc_packet.unwrap())
                            .await;
                        if zc_packet.is_none() {
                            processed = true;
                            break;
                        }
                    }
                    if !processed {
                        tracing::error!(?zc_packet, "unhandled packet");
                    }
                }
            }
            panic!("done_peer_recv");
        });
    }

    pub async fn add_packet_process_pipeline(&self, pipeline: BoxPeerPacketFilter) {
        // newest pipeline will be executed first
        self.peer_packet_process_pipeline
            .write()
            .await
            .push(pipeline);
    }

    pub async fn add_nic_packet_process_pipeline(&self, pipeline: BoxNicPacketFilter) {
        // newest pipeline will be executed first
        self.nic_packet_process_pipeline
            .write()
            .await
            .push(pipeline);
    }

    async fn init_packet_process_pipeline(&self) {
        // for tun/tap ip/eth packet.
        struct NicPacketProcessor {
            nic_channel: PacketRecvChan,
        }
        #[async_trait::async_trait]
        impl PeerPacketFilter for NicPacketProcessor {
            async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
                let hdr = packet.peer_manager_header().unwrap();
                if hdr.packet_type == PacketType::Data as u8 && !hdr.is_not_send_to_tun() {
                    if hdr.is_encrypted() || hdr.is_compressed() {
                        tracing::warn!(
                            from_peer_id = hdr.from_peer_id.get(),
                            to_peer_id = hdr.to_peer_id.get(),
                            encrypted = hdr.is_encrypted(),
                            compressed = hdr.is_compressed(),
                            "dropping packet before nic because it is not fully decoded"
                        );
                        return None;
                    }
                    tracing::trace!(?packet, "send packet to nic channel");
                    // TODO: use a function to get the body ref directly for zero copy
                    // A full host queue drops the packet rather than block the
                    // shared peer packet router (upstream 8622277).
                    if let Err(error) = self.nic_channel.try_send(packet) {
                        tracing::trace!(
                            ?error,
                            "dropping packet because nic channel cannot accept it"
                        );
                    }
                    None
                } else {
                    Some(packet)
                }
            }
        }
        self.add_packet_process_pipeline(Box::new(NicPacketProcessor {
            nic_channel: self.nic_channel.clone(),
        }))
        .await;

        // for peer rpc packet
        struct PeerRpcPacketProcessor {
            peer_rpc_tspt_sender: UnboundedSender<ZCPacket>,
        }

        #[async_trait::async_trait]
        impl PeerPacketFilter for PeerRpcPacketProcessor {
            async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
                let hdr = packet.peer_manager_header().unwrap();
                if hdr.packet_type == PacketType::TaRpc as u8
                    || hdr.packet_type == PacketType::RpcReq as u8
                    || hdr.packet_type == PacketType::RpcResp as u8
                {
                    self.peer_rpc_tspt_sender.send(packet).unwrap();
                    None
                } else {
                    Some(packet)
                }
            }
        }
        self.add_packet_process_pipeline(Box::new(PeerRpcPacketProcessor {
            peer_rpc_tspt_sender: self.peer_rpc_tspt.peer_rpc_tspt_sender.clone(),
        }))
        .await;

        #[cfg(feature = "mpquic")]
        {
            struct RelayMpPacketProcessor {
                my_peer_id: PeerId,
                peers: Arc<PeerMap>,
                foreign_network_client: Arc<ForeignNetworkClient>,
                global_ctx: ArcGlobalCtx,
                transport: Arc<RelayNextHopTransport>,
                session_manager: Arc<MpSessionManager>,
                tunnel_tx: UnboundedSender<Box<dyn Tunnel>>,
            }

            #[async_trait::async_trait]
            impl PeerPacketFilter for RelayMpPacketProcessor {
                async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
                    let Some(hdr) = packet.peer_manager_header() else {
                        return Some(packet);
                    };
                    if hdr.packet_type != PacketType::MpRelayDatagram as u8 {
                        return Some(packet);
                    }
                    let mp_config = self
                        .global_ctx
                        .get_flags()
                        .mp
                        .clone()
                        .unwrap_or_else(crate::common::config::gen_default_mp_config);
                    if !mp_config.enabled
                        || !mp_config
                            .providers
                            .iter()
                            .any(|provider| provider == "relay-next-hop")
                    {
                        return None;
                    }
                    let header_from_peer_id = hdr.from_peer_id.get();
                    let header_to_peer_id = hdr.to_peer_id.get();
                    let datagram = match RelayDatagram::decode(packet.payload()) {
                        Ok(datagram) => datagram,
                        Err(error) => {
                            tracing::warn!(?error, "dropping malformed relay MP datagram");
                            return None;
                        }
                    };
                    let is_local_terminal = match PeerManager::relay_datagram_is_local_terminal(
                        self.my_peer_id,
                        header_from_peer_id,
                        header_to_peer_id,
                        &datagram,
                    ) {
                        Ok(is_local_terminal) => is_local_terminal,
                        Err(error) => {
                            tracing::warn!(
                                header_from_peer_id,
                                header_to_peer_id,
                                envelope_source_peer_id = datagram.source_peer_id,
                                envelope_destination_peer_id = datagram.destination_peer_id,
                                error,
                                "dropping relay MP datagram with mismatched EasyTier header"
                            );
                            return None;
                        }
                    };
                    if !is_local_terminal {
                        // This node is the selected first hop (or a later relay),
                        // not the TQUIC endpoint.  Leave the opaque datagram for
                        // the stock EasyTier forwarding pipeline; the destination
                        // validates and delivers it to the relay MP transport.
                        return Some(packet);
                    }
                    let direct_peers = PeerManager::relay_next_hop_candidates_from_maps(
                        &self.peers,
                        &self.foreign_network_client,
                        self.my_peer_id,
                    )
                    .await;
                    let Some(reply_first_hop_peer_id) = direct_peers
                        .iter()
                        .copied()
                        .find(|peer_id| *peer_id == datagram.first_hop_peer_id)
                        .or_else(|| {
                            direct_peers
                                .into_iter()
                                .find(|peer_id| *peer_id != self.my_peer_id)
                        })
                    else {
                        tracing::debug!(
                            source_peer_id = datagram.source_peer_id,
                            "relay MP destination has no direct peer for the reverse path"
                        );
                        return None;
                    };
                    let admission = match self
                        .transport
                        .prepare_inbound(&datagram, reply_first_hop_peer_id)
                        .await
                    {
                        Ok(admission) => admission,
                        Err(error) => {
                            tracing::warn!(?error, "dropping invalid relay MP datagram admission");
                            return None;
                        }
                    };
                    if admission.created {
                        // `offer_path_spec` waits for TQUIC's server stream to
                        // become ready.  That stream can only be created after
                        // this first QUIC Initial is delivered, so attach in a
                        // task and enqueue the Initial below without waiting.
                        let admission_for_attach = admission.clone();
                        let peers = self.peers.clone();
                        let foreign_network_client = self.foreign_network_client.clone();
                        let session_manager = self.session_manager.clone();
                        let transport = self.transport.clone();
                        let tunnel_tx = self.tunnel_tx.clone();
                        tokio::spawn(async move {
                            // Looked up here, not before the spawn: it lists the
                            // first hop's conns and runs a blocking route lookup,
                            // which must not hold up the packet router.
                            let egress_device = PeerManager::relay_first_hop_egress_device(
                                &peers,
                                &foreign_network_client,
                                admission_for_attach.egress_first_hop_peer_id,
                            )
                            .await;
                            let remote_url = crate::tunnel::build_url_from_socket_addr(
                                &admission_for_attach.identity.remote_addr.to_string(),
                                "mpquic",
                            );
                            match session_manager
                                .offer_path_spec(
                                    admission_for_attach.source_peer_id,
                                    true,
                                    relay_path_spec(
                                        admission_for_attach.identity,
                                        admission_for_attach.carrier.clone(),
                                        admission_for_attach.egress_first_hop_peer_id,
                                        egress_device.as_deref(),
                                    ),
                                    remote_url,
                                    "mpquic_relay_next_hop",
                                )
                                .await
                            {
                                Ok(OfferPathResult::NewTunnel(tunnel)) => {
                                    tracing::info!(
                                        peer_id = admission_for_attach.source_peer_id,
                                        first_hop_peer_id =
                                            admission_for_attach.egress_first_hop_peer_id,
                                        route_generation =
                                            admission_for_attach.identity.route_generation,
                                        "relay MP server TQUIC ready; attaching EasyTier tunnel"
                                    );
                                    if tunnel_tx.send(tunnel).is_err() {
                                        tracing::warn!(
                                            peer_id = admission_for_attach.source_peer_id,
                                            "relay MP server tunnel attach worker has stopped"
                                        );
                                        transport.retire_path(&admission_for_attach.identity);
                                    }
                                }
                                Ok(OfferPathResult::PathAdded) => {}
                                Err(error) => {
                                    tracing::warn!(
                                        ?error,
                                        peer_id = admission_for_attach.source_peer_id,
                                        first_hop_peer_id =
                                            admission_for_attach.identity.first_hop_peer_id,
                                        "failed to attach relay MP carrier to TQUIC session"
                                    );
                                    transport.retire_path(&admission_for_attach.identity);
                                }
                            }
                        });
                    }
                    if let Err(error) = self.transport.deliver_inbound(datagram).await {
                        tracing::warn!(?error, "failed to deliver relay MP datagram to TQUIC");
                    }
                    None
                }
            }

            self.add_packet_process_pipeline(Box::new(RelayMpPacketProcessor {
                my_peer_id: self.my_peer_id,
                peers: self.peers.clone(),
                foreign_network_client: self.foreign_network_client.clone(),
                global_ctx: self.global_ctx.clone(),
                transport: self.mp_relay_transport.clone(),
                session_manager: self.mp_session_manager.clone(),
                tunnel_tx: self.mp_relay_tunnel_tx.clone(),
            }))
            .await;
        }
    }

    pub async fn add_route<T>(&self, route: T)
    where
        T: Route + PeerPacketFilter + Send + Sync + Clone + 'static,
    {
        // for route
        self.add_packet_process_pipeline(Box::new(route.clone()))
            .await;

        struct Interface {
            my_peer_id: PeerId,
            peers: Weak<PeerMap>,
            foreign_network_client: Weak<ForeignNetworkClient>,
            foreign_network_manager: Weak<ForeignNetworkManager>,
        }

        #[async_trait]
        impl RouteInterface for Interface {
            async fn list_peers(&self) -> Vec<PeerId> {
                let Some(foreign_client) = self.foreign_network_client.upgrade() else {
                    return vec![];
                };

                let Some(peer_map) = self.peers.upgrade() else {
                    return vec![];
                };

                let mut peers = foreign_client.list_public_peers().await;
                // Not peers reached only over a relay MP carrier: announced as a
                // link, it becomes the next hop of the relay that carries it.
                peers.extend(peer_map.list_peers_with_link_conn().await);
                peers
            }

            fn my_peer_id(&self) -> PeerId {
                self.my_peer_id
            }

            async fn close_peer(&self, peer_id: PeerId) {
                if let Some(peer_map) = self.peers.upgrade() {
                    let _ = peer_map.close_peer(peer_id).await;
                }

                if let Some(foreign_client) = self.foreign_network_client.upgrade() {
                    let _ = foreign_client.get_peer_map().close_peer(peer_id).await;
                }
            }

            async fn get_peer_public_key(&self, peer_id: PeerId) -> Option<Vec<u8>> {
                let peer_map = self.peers.upgrade()?;
                peer_map.get_peer_public_key(peer_id)
            }

            async fn get_peer_identity_type(&self, peer_id: PeerId) -> Option<PeerIdentityType> {
                let peer_map = self.peers.upgrade()?;
                peer_map.get_peer_identity_type(peer_id)
            }

            async fn list_foreign_networks(&self) -> ForeignNetworkRouteInfoMap {
                let ret = DashMap::new();
                let Some(foreign_mgr) = self.foreign_network_manager.upgrade() else {
                    return ret;
                };

                let networks = foreign_mgr.list_foreign_networks().await;
                for (network_name, info) in networks.foreign_networks.iter() {
                    if info.peers.is_empty() {
                        continue;
                    }

                    let last_update = foreign_mgr
                        .get_foreign_network_last_update(network_name)
                        .unwrap_or(SystemTime::now());
                    ret.insert(
                        ForeignNetworkRouteInfoKey {
                            peer_id: self.my_peer_id,
                            network_name: network_name.clone(),
                        },
                        ForeignNetworkRouteInfoEntry {
                            foreign_peer_ids: info.peers.iter().map(|x| x.peer_id).collect(),
                            last_update: Some(last_update.into()),
                            version: 0,
                            network_secret_digest: info.network_secret_digest.clone(),
                            my_peer_id_for_this_network: info.my_peer_id_for_this_network,
                        },
                    );
                }
                ret
            }
        }

        let my_peer_id = self.my_peer_id;
        let _route_id = route
            .open(Box::new(Interface {
                my_peer_id,
                peers: Arc::downgrade(&self.peers),
                foreign_network_client: Arc::downgrade(&self.foreign_network_client),
                foreign_network_manager: Arc::downgrade(&self.foreign_network_manager),
            }))
            .await
            .unwrap();

        let arc_route: ArcRoute = Arc::new(Box::new(route));
        self.peers.add_route(arc_route).await;
    }

    pub fn get_route(&self) -> Box<dyn Route + Send + Sync + 'static> {
        match &self.route_algo_inst {
            RouteAlgoInst::Ospf(route) => Box::new(route.clone()),
            RouteAlgoInst::None => Box::new(MockRoute {}),
        }
    }

    pub async fn list_routes(&self) -> Vec<instance::Route> {
        self.get_route().list_routes().await
    }

    pub async fn get_route_peer_info_last_update_time(&self) -> Instant {
        self.get_route().get_peer_info_last_update_time().await
    }

    pub async fn list_proxy_cidrs(&self) -> BTreeSet<Ipv4Cidr> {
        self.get_route().list_proxy_cidrs().await
    }

    pub async fn list_proxy_cidrs_v6(&self) -> BTreeSet<Ipv6Cidr> {
        self.get_route().list_proxy_cidrs_v6().await
    }

    pub async fn list_public_ipv6_routes(&self) -> BTreeSet<cidr::Ipv6Inet> {
        self.get_route().list_public_ipv6_routes().await
    }

    pub async fn get_my_public_ipv6_addr(&self) -> Option<cidr::Ipv6Inet> {
        self.get_route().get_my_public_ipv6_addr().await
    }

    pub async fn get_local_public_ipv6_info(&self) -> instance::ListPublicIpv6InfoResponse {
        self.get_route().get_local_public_ipv6_info().await
    }

    pub async fn dump_route(&self) -> String {
        self.get_route().dump().await
    }

    pub async fn list_global_foreign_network(&self) -> ListGlobalForeignNetworkResponse {
        let mut resp = ListGlobalForeignNetworkResponse::default();
        let ret = self.get_route().list_foreign_network_info().await;
        for info in ret.infos.iter() {
            let entry = resp
                .foreign_networks
                .entry(info.key.as_ref().unwrap().peer_id)
                .or_insert_with(Default::default);
            let Some(route_info) = info.value.as_ref() else {
                continue;
            };

            let f = OneForeignNetwork {
                network_name: info.key.as_ref().unwrap().network_name.clone(),
                peer_ids: route_info.foreign_peer_ids.clone(),
                last_updated: serde_json::to_string(&route_info.last_update.unwrap()).unwrap(),
                version: route_info.version,
            };

            entry.foreign_networks.push(f);
        }

        resp
    }

    pub async fn get_foreign_network_summary(&self) -> RouteForeignNetworkSummary {
        self.get_route().get_foreign_network_summary().await
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "PeerManager"))]
    async fn run_nic_packet_process_pipeline(&self, data: &mut ZCPacket) -> bool {
        // Enforce ACL for outbound (NIC-originated) packets. If ACL denies, stop processing.
        if !self.global_ctx.get_acl_filter().process_packet_with_acl(
            data,
            false,
            None,
            |_| false,
            &self.get_route(),
        ) {
            return false;
        }

        for pipeline in self.nic_packet_process_pipeline.read().await.iter().rev() {
            let _ = pipeline.try_process_packet_from_nic(data).await;
        }

        true
    }

    pub async fn remove_nic_packet_process_pipeline(&self, id: String) -> Result<(), Error> {
        let mut pipelines = self.nic_packet_process_pipeline.write().await;
        if let Some(pos) = pipelines.iter().position(|x| x.id() == id) {
            pipelines.remove(pos);
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    fn get_next_hop_policy(
        is_first_latency: bool,
        flow_hash: Option<u64>,
        allow_overlay_weighted: bool,
    ) -> NextHopPolicy {
        if mp_weighted_enabled() && allow_overlay_weighted {
            // Multipath: spread across the weighted edge-disjoint set (falls back
            // to the least-cost single hop per-dst when no set exists). A flow
            // hash pins realtime flows to one next-hop (MP_SQM_PLAN.md §9.3).
            NextHopPolicy::Weighted { flow_hash }
        } else if is_first_latency {
            NextHopPolicy::LeastCost
        } else {
            NextHopPolicy::LeastHop
        }
    }

    /// MP_SQM_PLAN.md §9.3: derive a per-flow hash from an *unencrypted* inner IP
    /// packet's 5-tuple, but only for realtime/connectionless flows (UDP/ICMP)
    /// that should be pinned to a single path to avoid reordering. Returns `None`
    /// for TCP and others (left to the weighted split for aggregation) and on any
    /// parse failure, so the caller safely falls back to weighted round-robin.
    ///
    /// Returns `None` immediately when weighted multipath is off, so the stock
    /// data path pays no IP-parse/hash cost when nothing downstream would use
    /// the result.
    fn packet_flow_hash(&self, msg: &ZCPacket) -> Option<u64> {
        if !mp_weighted_enabled() {
            return None;
        }
        use crate::tunnel::mp_dataplane::{IP_PROTO_ICMP, IP_PROTO_ICMPV6, IP_PROTO_UDP};
        use std::hash::{Hash, Hasher};

        if let Some(key) = Self::proxy_transport_flow_key(msg) {
            return Some(key);
        }
        let ip = Self::inner_ip(msg)?;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        ip.src.hash(&mut hasher);
        ip.dst.hash(&mut hasher);
        ip.protocol.hash(&mut hasher);
        if let Some(id) = ip.fragment_id {
            // A fragmented datagram only carries its L4 header in the first
            // fragment. Keying later fragments off ports would parse payload
            // bytes as ports and scatter a datagram's fragments across paths.
            // Key the whole datagram off its identification instead, so all
            // fragments stay on one path while distinct datagrams spread.
            id.hash(&mut hasher);
        } else {
            // Ports for flows we pin to a single path; None => don't pin (split it).
            let (sp, dp) = match ip.protocol {
                IP_PROTO_UDP => ip.ports?,
                IP_PROTO_ICMP | IP_PROTO_ICMPV6 => (0, 0),
                _ => return None,
            };
            sp.hash(&mut hasher);
            dp.hash(&mut hasher);
        }
        Some(hasher.finish())
    }

    /// The inner IP packet of a data packet; the one parser for the whole
    /// send path (shared with the MP data-plane classifier, MP_SQM_PLAN.md
    /// S2.10). Only data packets carry one: the QUIC and KCP proxies' packets
    /// carry their own transport's, and a QUIC short header's first byte
    /// (0x40..0x5f) reads as IPv4 with addresses and ports from ciphertext.
    fn inner_ip(msg: &ZCPacket) -> Option<crate::tunnel::mp_dataplane::InnerIp> {
        const DATA: u8 = PacketType::Data as u8;
        const DATA_KCP: u8 = PacketType::DataWithKcpSrcModified as u8;
        const DATA_QUIC: u8 = PacketType::DataWithQuicSrcModified as u8;
        match msg.peer_manager_header()?.packet_type {
            DATA | DATA_KCP | DATA_QUIC => crate::tunnel::mp_dataplane::parse_inner_ip(msg.payload()),
            _ => None,
        }
    }

    /// The QUIC and KCP proxies' packets of one type to one peer are the one
    /// transport connection between the two proxies: one flow, whose packets
    /// must stay in order on one path and in one queue.
    fn proxy_transport_flow_key(msg: &ZCPacket) -> Option<u64> {
        use std::hash::{Hash, Hasher};
        const KCP_SRC: u8 = PacketType::KcpSrc as u8;
        const KCP_DST: u8 = PacketType::KcpDst as u8;
        const QUIC_SRC: u8 = PacketType::QuicSrc as u8;
        const QUIC_DST: u8 = PacketType::QuicDst as u8;
        let hdr = msg.peer_manager_header()?;
        if !matches!(hdr.packet_type, KCP_SRC | KCP_DST | QUIC_SRC | QUIC_DST) {
            return None;
        }
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        hdr.packet_type.hash(&mut hasher);
        hdr.to_peer_id.get().hash(&mut hasher);
        Some(hasher.finish())
    }

    /// MP_SQM_PLAN.md S2.10 oversize policy `icmp_ptb` (RFC 9484 Section
    /// 10.1): a datagram-class inner packet too long for one QUIC datagram
    /// to `peer_id` is dropped and the local host gets ICMP Packet Too Big,
    /// so its TCP lowers the packet size by PMTU discovery. The limit exists
    /// only while that peer's MP session negotiated the datagram plane with
    /// this policy; the packet may still leave on another of the peer's
    /// connections, which merely costs it a smaller path MTU.
    #[cfg(feature = "mpquic")]
    async fn answer_with_packet_too_big(&self, peer_id: PeerId, msg: &ZCPacket) -> bool {
        use crate::tunnel::mp_dataplane::{ClassMode, build_packet_too_big};
        let Some(limit) = self.mp_session_manager.ptb_limit(peer_id) else {
            return false;
        };
        let inner = msg.payload();
        if inner.len() <= limit {
            return false;
        }
        let Some(policy) = self.mp_session_manager.data_plane_hint() else {
            return false;
        };
        if policy.mode_for(policy.classify_ip(inner).0) != ClassMode::Datagram {
            return false;
        }
        let Some(ptb) = build_packet_too_big(inner, limit as u32) else {
            return false;
        };
        let mut reply = ZCPacket::new_with_payload(&ptb);
        reply.fill_peer_manager_hdr(self.my_peer_id, self.my_peer_id, PacketType::Data as u8);
        // Never wait on a full host queue from the send path (the packet
        // router drops there too): without an answer the packet goes out as
        // usual.
        if self.nic_channel.try_send(reply).is_err() {
            return false;
        }
        self.mp_session_manager.note_ptb_sent(peer_id);
        true
    }

    fn check_p2p_only_before_send(&self, dst_peer_id: PeerId) -> Result<(), Error> {
        if self.global_ctx.p2p_only() && !self.peers.has_peer(dst_peer_id) {
            return Err(Error::RouteError(None));
        }
        Ok(())
    }

    pub async fn send_msg_for_proxy(
        &self,
        mut msg: ZCPacket,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        self.mark_recent_traffic(dst_peer_id);
        self.check_p2p_only_before_send(dst_peer_id)?;

        // §9.3: compute the flow hash from the still-plaintext inner packet,
        // before compression/encryption obscures the 5-tuple. `packet_flow_hash`
        // is a no-op (returns None) unless weighted multipath is enabled.
        let flow_hash = self.packet_flow_hash(&msg);

        self.self_tx_counters
            .compress_tx_bytes_before
            .add(msg.buf_len() as u64);

        Self::try_compress_and_encrypt(
            self.data_compress_algo,
            &self.encryptor,
            &mut msg,
            self.is_secure_mode_enabled,
        )
        .await?;

        self.self_tx_counters
            .compress_tx_bytes_after
            .add(msg.buf_len() as u64);

        let msg_len = msg.buf_len() as u64;
        let result = Self::send_msg_internal_with_flow(
            &self.peers,
            &self.foreign_network_client,
            &self.relay_peer_map,
            Some(&self.traffic_metrics),
            msg,
            dst_peer_id,
            flow_hash,
        )
        .await;
        if result.is_ok() {
            self.self_tx_counters.self_tx_bytes.add(msg_len);
            self.self_tx_counters.self_tx_packets.inc();
        }
        result
    }

    async fn send_msg_internal(
        peers: &Arc<PeerMap>,
        foreign_network_client: &Arc<ForeignNetworkClient>,
        relay_peer_map: &Arc<RelayPeerMap>,
        direct_tx_metrics: Option<&Arc<TrafficMetricRecorder>>,
        msg: ZCPacket,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        Self::send_msg_internal_with_flow(
            peers,
            foreign_network_client,
            relay_peer_map,
            direct_tx_metrics,
            msg,
            dst_peer_id,
            None,
        )
        .await
    }

    fn direct_send_requires_non_mpquic_carrier(packet_type: u8) -> bool {
        packet_type == PacketType::MpRelayDatagram as u8
    }

    fn allow_overlay_weighted_for_packet(endpoint_mp_owns_routing: bool, packet_type: u8) -> bool {
        !endpoint_mp_owns_routing && !Self::direct_send_requires_non_mpquic_carrier(packet_type)
    }

    #[cfg(feature = "mpquic")]
    fn relay_datagram_is_local_terminal(
        my_peer_id: PeerId,
        header_from_peer_id: PeerId,
        header_to_peer_id: PeerId,
        datagram: &RelayDatagram,
    ) -> Result<bool, &'static str> {
        if header_to_peer_id != my_peer_id {
            return Ok(false);
        }
        if datagram.destination_peer_id != my_peer_id {
            return Err("relay MP destination does not match EasyTier header destination");
        }
        if datagram.source_peer_id != header_from_peer_id {
            return Err("relay MP source does not match EasyTier header source");
        }
        Ok(true)
    }

    // `flow_hash` (MP_SQM_PLAN.md §9.3): when set and multipath is on, the flow
    // is pinned to a single weighted next-hop (sticky) to avoid reordering
    // realtime/connectionless traffic; `None` spreads packets by weighted RR.
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "PeerManager"))]
    async fn send_msg_internal_with_flow(
        peers: &Arc<PeerMap>,
        foreign_network_client: &Arc<ForeignNetworkClient>,
        relay_peer_map: &Arc<RelayPeerMap>,
        direct_tx_metrics: Option<&Arc<TrafficMetricRecorder>>,
        msg: ZCPacket,
        dst_peer_id: PeerId,
        flow_hash: Option<u64>,
    ) -> Result<(), Error> {
        let endpoint_mp_owns_routing = peers.endpoint_mp_owns_routing(dst_peer_id);
        let allow_overlay_weighted = Self::allow_overlay_weighted_for_packet(
            endpoint_mp_owns_routing,
            msg.peer_manager_header().unwrap().packet_type,
        );
        let policy = Self::get_next_hop_policy(
            msg.peer_manager_header().unwrap().is_latency_first(),
            flow_hash,
            allow_overlay_weighted,
        );
        let packet_type = msg.peer_manager_header().unwrap().packet_type;
        let direct_send_requires_non_mpquic =
            Self::direct_send_requires_non_mpquic_carrier(packet_type);
        let msg_len = msg.buf_len() as u64;
        // Multipath (only) also routes via a weighted gateway even when the dst
        // is directly connected, so traffic can spread across relay paths, not
        // just the direct link. When the weighted pick IS the direct dst it is
        // filtered out here and falls through to the direct-send branch below.
        // Gated on the MP flag alone (not latency_first) so default and
        // latency-first routing stay byte-for-byte identical to upstream: the
        // MP feature is additive and off unless ET_MP_WEIGHTED is set.
        let mp_gateway = if mp_weighted_enabled() && allow_overlay_weighted {
            peers
                .get_gateway_peer_id(dst_peer_id, policy.clone())
                .await
                .filter(|gateway| *gateway != dst_peer_id)
        } else {
            None
        };
        // A packet that must not ride mpquic (a relay MP datagram) to a peer
        // reached only over mpquic goes through the route's gateway instead.
        let direct_peer = peers.has_peer(dst_peer_id)
            && (!direct_send_requires_non_mpquic || peers.has_live_non_mpquic_conn(dst_peer_id));
        let send_result = if let Some(gateway) = mp_gateway
            && (peers.has_peer(gateway) || foreign_network_client.has_next_hop(gateway))
        {
            relay_peer_map.send_msg(msg, dst_peer_id, policy).await
        } else if direct_peer {
            if direct_send_requires_non_mpquic {
                peers.send_msg_directly_non_mpquic(msg, dst_peer_id).await
            } else {
                peers.send_msg_directly(msg, dst_peer_id).await
            }
        } else if foreign_network_client.has_next_hop(dst_peer_id) {
            if direct_send_requires_non_mpquic {
                foreign_network_client
                    .get_peer_map()
                    .send_msg_directly_non_mpquic(msg, dst_peer_id)
                    .await
            } else {
                foreign_network_client.send_msg(msg, dst_peer_id).await
            }
        } else if let Some(gateway) = peers
            .get_gateway_peer_id(dst_peer_id, policy.clone())
            .await
            .filter(|gateway| !(direct_send_requires_non_mpquic && *gateway == dst_peer_id))
        {
            if peers.has_peer(gateway) || foreign_network_client.has_next_hop(gateway) {
                relay_peer_map.send_msg(msg, dst_peer_id, policy).await
            } else {
                tracing::warn!(
                    ?gateway,
                    ?dst_peer_id,
                    "cannot send msg to peer through gateway"
                );
                Err(Error::RouteError(None))
            }
        } else if foreign_network_client.has_next_hop(dst_peer_id) {
            // check foreign network again. so in happy path we can avoid extra check
            foreign_network_client.send_msg(msg, dst_peer_id).await
        } else {
            tracing::debug!(?dst_peer_id, "no gateway for peer");
            Err(Error::RouteError(None))
        };

        if send_result.is_ok()
            && let Some(metrics) = direct_tx_metrics
        {
            metrics.record_tx(dst_peer_id, packet_type, msg_len).await;
        }

        send_result
    }

    pub async fn get_msg_dst_peer(&self, addr: &IpAddr) -> (Vec<PeerId>, bool) {
        match addr {
            IpAddr::V4(ipv4_addr) => self.get_msg_dst_peer_ipv4(ipv4_addr).await,
            IpAddr::V6(ipv6_addr) => self.get_msg_dst_peer_ipv6(ipv6_addr).await,
        }
    }

    fn is_all_peers_broadcast_ipv4(&self, ipv4_addr: &Ipv4Addr) -> bool {
        let network_length = self
            .global_ctx
            .get_ipv4()
            .map(|x| x.network_length())
            .unwrap_or(24);
        let ipv4_inet = cidr::Ipv4Inet::new(*ipv4_addr, network_length).unwrap();
        ipv4_addr.is_broadcast()
            || ipv4_addr.is_multicast()
            || *ipv4_addr == ipv4_inet.last_address()
    }

    fn is_all_peers_broadcast_ipv6(&self, ipv6_addr: &Ipv6Addr) -> bool {
        let network_length = self
            .global_ctx
            .get_ipv6()
            .map(|x| x.network_length())
            .unwrap_or(64);
        let ipv6_inet = cidr::Ipv6Inet::new(*ipv6_addr, network_length).unwrap();
        ipv6_addr.is_multicast() || *ipv6_addr == ipv6_inet.last_address()
    }

    fn select_ipv4_broadcast_peers<'a>(
        routes: impl IntoIterator<Item = &'a instance::Route>,
        my_peer_id: PeerId,
    ) -> Vec<PeerId> {
        routes
            .into_iter()
            .filter_map(|route| {
                (route.peer_id != my_peer_id && route.ipv4_addr.is_some()).then_some(route.peer_id)
            })
            .collect()
    }

    pub async fn get_msg_dst_peer_ipv4(&self, ipv4_addr: &Ipv4Addr) -> (Vec<PeerId>, bool) {
        let mut is_exit_node = false;
        let mut dst_peers = vec![];
        if self.is_all_peers_broadcast_ipv4(ipv4_addr) {
            dst_peers.extend(Self::select_ipv4_broadcast_peers(
                &self.peers.list_route_infos().await,
                self.my_peer_id,
            ));
        } else if let Some(peer_id) = self.peers.get_peer_id_by_ipv4(ipv4_addr).await {
            dst_peers.push(peer_id);
        } else if !self
            .global_ctx
            .is_ip_in_same_network(&std::net::IpAddr::V4(*ipv4_addr))
        {
            for exit_node in self.exit_nodes.read().await.iter() {
                let IpAddr::V4(exit_node) = exit_node else {
                    continue;
                };
                if let Some(peer_id) = self.peers.get_peer_id_by_ipv4(exit_node).await {
                    dst_peers.push(peer_id);
                    is_exit_node = true;
                    break;
                }
            }
        }
        #[cfg(target_env = "ohos")]
        {
            if dst_peers.is_empty()
                && !self
                    .global_ctx
                    .is_ip_in_same_network(&std::net::IpAddr::V4(*ipv4_addr))
            {
                tracing::trace!("no peer id for ipv4: {}, set exit_node for ohos", ipv4_addr);
                dst_peers.push(self.my_peer_id.clone());
                is_exit_node = true;
            }
        }
        (dst_peers, is_exit_node)
    }

    pub async fn get_msg_dst_peer_ipv6(&self, ipv6_addr: &Ipv6Addr) -> (Vec<PeerId>, bool) {
        let mut is_exit_node = false;
        let mut dst_peers = vec![];
        if self.is_all_peers_broadcast_ipv6(ipv6_addr) {
            dst_peers.extend(self.peers.list_routes().await.iter().map(|x| *x.key()));
        } else if let Some(peer_id) = self.peers.get_peer_id_by_ipv6(ipv6_addr).await {
            dst_peers.push(peer_id);
        } else if !ipv6_addr.is_unicast_link_local()
            && let Some(peer_id) = self.get_route().get_public_ipv6_gateway_peer_id().await
        {
            dst_peers.push(peer_id);
        } else if !ipv6_addr.is_unicast_link_local() {
            // NOTE: never route link local address to exit node.
            for exit_node in self.exit_nodes.read().await.iter() {
                let IpAddr::V6(exit_node) = exit_node else {
                    continue;
                };
                if let Some(peer_id) = self.peers.get_peer_id_by_ipv6(exit_node).await {
                    dst_peers.push(peer_id);
                    is_exit_node = true;
                    break;
                }
            }
        }

        (dst_peers, is_exit_node)
    }

    pub async fn try_compress_and_encrypt(
        compress_algo: CompressorAlgo,
        encryptor: &Arc<dyn Encryptor + 'static>,
        msg: &mut ZCPacket,
        secure_mode_enabled: bool,
    ) -> Result<(), Error> {
        let compressor = DefaultCompressor {};
        compressor
            .compress(msg, compress_algo)
            .await
            .with_context(|| "compress failed")?;
        if !secure_mode_enabled {
            encryptor.encrypt(msg).with_context(|| "encrypt failed")?;
        }
        Ok(())
    }

    pub async fn send_msg_by_ip(
        &self,
        mut msg: ZCPacket,
        ip_addr: IpAddr,
        not_send_to_self: bool,
    ) -> Result<(), Error> {
        tracing::trace!(
            "do send_msg in peer manager, msg: {:?}, ip_addr: {}",
            msg,
            ip_addr
        );

        msg.fill_peer_manager_hdr(
            self.my_peer_id,
            0,
            tunnel::packet_def::PacketType::Data as u8,
        );
        if !self.run_nic_packet_process_pipeline(&mut msg).await {
            return Ok(());
        }
        // §9.3: derive the per-flow hash while the inner packet is still plaintext
        // (before compression/encryption below), for sticky multipath selection.
        // `packet_flow_hash` short-circuits to None when weighted MP is off, so
        // the default data path pays nothing.
        let flow_hash = self.packet_flow_hash(&msg);
        // MP_SQM_PLAN.md S2.10 / CAKE_SQM_PLAN.md B2: classify while the inner
        // packet is still plaintext. The class and the inner flow hash ride in
        // memory to the mpquic pipe, where the flow hash tells the egress
        // queue (CAKE) which flow a packet belongs to; every other tunnel
        // ignores the tag.
        #[cfg(feature = "mpquic")]
        if let Some(policy) = self.mp_session_manager.data_plane_hint() {
            let (class, inner_flow) = policy.classify_ip(msg.payload());
            msg.set_mp_dataplane_tag(Some((class.tag(), inner_flow)));
        } else if self.mp_session_manager.sqm_enabled_hint() {
            // No data plane, but SQM queues the single stream's frames per
            // inner flow in the mpquic driver (`mpquic::fair_pipe`): it needs
            // the flow hash, not a class.
            let inner_flow = crate::tunnel::mp_dataplane::inner_flow_hash(msg.payload());
            msg.set_mp_dataplane_tag(Some((0, inner_flow)));
        }
        let cur_to_peer_id = msg.peer_manager_header().unwrap().to_peer_id.into();
        if cur_to_peer_id != 0 {
            self.mark_recent_traffic(cur_to_peer_id);
            return Self::send_msg_internal_with_flow(
                &self.peers,
                &self.foreign_network_client,
                &self.relay_peer_map,
                Some(&self.traffic_metrics),
                msg,
                cur_to_peer_id,
                flow_hash,
            )
            .await;
        }

        let (dst_peers, is_exit_node) = match ip_addr {
            IpAddr::V4(ipv4_addr) => self.get_msg_dst_peer_ipv4(&ipv4_addr).await,
            IpAddr::V6(ipv6_addr) => self.get_msg_dst_peer_ipv6(&ipv6_addr).await,
        };

        if dst_peers.is_empty() {
            tracing::info!("no peer id for ip: {}", ip_addr);
            return Ok(());
        }

        #[cfg(feature = "mpquic")]
        if let [peer_id] = dst_peers.as_slice()
            && self.answer_with_packet_too_big(*peer_id, &msg).await
        {
            return Ok(());
        }

        self.self_tx_counters
            .compress_tx_bytes_before
            .add(msg.buf_len() as u64);

        Self::try_compress_and_encrypt(
            self.data_compress_algo,
            &self.encryptor,
            &mut msg,
            self.is_secure_mode_enabled,
        )
        .await?;

        self.self_tx_counters
            .compress_tx_bytes_after
            .add(msg.buf_len() as u64);

        let is_latency_first = self.global_ctx.latency_first();
        msg.mut_peer_manager_header()
            .unwrap()
            .set_latency_first(is_latency_first)
            .set_exit_node(is_exit_node);

        let mut errs: Vec<Error> = vec![];
        let mut msg = Some(msg);
        let total_dst_peers = dst_peers.len();
        let should_mark_recent_traffic =
            Self::should_mark_recent_traffic_for_fanout(total_dst_peers);
        for (i, peer_id) in dst_peers.iter().enumerate() {
            if should_mark_recent_traffic {
                self.mark_recent_traffic(*peer_id);
            }
            if let Err(e) = self.check_p2p_only_before_send(*peer_id) {
                errs.push(e);
                continue;
            }

            let mut msg = if i == total_dst_peers - 1 {
                msg.take().unwrap()
            } else {
                msg.clone().unwrap()
            };

            let hdr = msg.mut_peer_manager_header().unwrap();
            hdr.to_peer_id.set(*peer_id);

            #[cfg(not(target_env = "ohos"))]
            {
                if not_send_to_self
                    && *peer_id == self.my_peer_id
                    && !self.global_ctx.is_ip_local_virtual_ip(&ip_addr)
                {
                    // Keep the loop-prevention flags for proxy-induced self-delivery where
                    // the destination is not this node's own EasyTier-managed IP.
                    hdr.set_not_send_to_tun(true);
                    hdr.set_no_proxy(true);
                }
            }

            self.self_tx_counters
                .self_tx_bytes
                .add(msg.buf_len() as u64);
            self.self_tx_counters.self_tx_packets.inc();

            if let Err(e) = Self::send_msg_internal_with_flow(
                &self.peers,
                &self.foreign_network_client,
                &self.relay_peer_map,
                Some(&self.traffic_metrics),
                msg,
                *peer_id,
                flow_hash,
            )
            .await
            {
                errs.push(e);
            }
        }

        tracing::trace!(?dst_peers, "do send_msg in peer manager done");

        if errs.is_empty() {
            Ok(())
        } else {
            tracing::error!(?errs, "send_msg has error");
            Err(anyhow::anyhow!("send_msg has error: {:?}", errs).into())
        }
    }

    async fn run_clean_peer_without_conn_routine(&self) {
        let peer_map = self.peers.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                peer_map.clean_peer_without_conn().await;
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        });
    }

    async fn run_relay_session_gc_routine(&self) {
        let relay_peer_map = self.relay_peer_map.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                relay_peer_map.evict_idle_sessions(std::time::Duration::from_secs(60));
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        });
    }

    async fn run_recent_traffic_gc_routine(&self) {
        let recent_have_traffic = self.recent_have_traffic.clone();
        let peers = self.peers.clone();
        let foreign_network_client = self.foreign_network_client.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                PeerManager::gc_recent_traffic_entries(
                    recent_have_traffic.as_ref(),
                    Instant::now(),
                    |peer_id| {
                        if let Some(peer) = peers.get_peer_by_id(peer_id) {
                            peer.has_directly_connected_conn()
                        } else {
                            foreign_network_client.get_peer_map().has_peer(peer_id)
                        }
                    },
                );
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        });
    }

    async fn run_peer_session_gc_routine(&self) {
        let peer_session_store = self.peer_session_store.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                peer_session_store.evict_unused_sessions();
            }
        });
    }

    async fn run_credential_gc_routine(&self) {
        let global_ctx = self.global_ctx.clone();
        let peer_map = self.peers.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                if global_ctx.get_network_identity().network_secret.is_some() {
                    if global_ctx
                        .get_credential_manager()
                        .remove_expired_credentials()
                    {
                        global_ctx.issue_event(GlobalCtxEvent::CredentialChanged);
                    }

                    Self::close_untrusted_credential_peers(&peer_map, &global_ctx).await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }

    async fn run_traffic_metrics_gc_routine(&self) {
        let mut event_receiver = self.global_ctx.subscribe();
        let traffic_metrics = self.traffic_metrics.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                match event_receiver.recv().await {
                    Ok(GlobalCtxEvent::PeerRemoved(peer_id)) => {
                        traffic_metrics.remove_peer(peer_id);
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(
                            skipped,
                            "traffic metrics GC receiver lagged; clearing peer cache to avoid stale metric attribution"
                        );
                        traffic_metrics.clear_peer_cache();
                        event_receiver = event_receiver.resubscribe();
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    /// Keep the MP layer strictly subordinate to EasyTier's peer lifecycle.
    /// A `PeerRemoved` event is emitted only after EasyTier has decided its
    /// peer connection is no longer usable (including ping/pong failure).
    /// MP must therefore retire its session instead of independently keeping a
    /// carrier alive or allowing a later `PathAdded` to bypass a fresh ET
    /// handshake.
    #[cfg(feature = "mpquic")]
    async fn run_mp_peer_lifecycle_routine(&self) {
        let mut event_receiver = self.global_ctx.subscribe();
        let manager = self.mp_session_manager.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                match event_receiver.recv().await {
                    Ok(GlobalCtxEvent::PeerRemoved(peer_id)) => {
                        manager.forget_peer(peer_id).await;
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        // We cannot safely infer which PeerRemoved event was
                        // missed. Clear only MP state; EasyTier keeps normal
                        // reachability/reconnect ownership and will rebuild
                        // valid paths on demand.
                        let forgotten = manager.forget_all_peers().await;
                        tracing::warn!(
                            skipped,
                            forgotten,
                            "MP peer lifecycle receiver lagged; discarded MP state so EasyTier remains authoritative"
                        );
                        event_receiver = event_receiver.resubscribe();
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    #[cfg(feature = "mpquic")]
    fn wake_p2p_after_egress_reconcile(p2p_demand_notify: &ExternalTaskSignal) {
        // A carrier retired on an inventory transition must be replaced without
        // waiting for the ordinary p2p polling interval.
        p2p_demand_notify.notify();
    }

    /// Retire every `common::egress_quality::EgressQualityManager` scope entry
    /// whose interface generation no longer matches the just-reconciled
    /// inventory snapshot (MP_SQM_PLAN.md §4.3 item 3: a NIC remove/reuse must
    /// invalidate the old handle/permit/sample, not just the MP carrier
    /// table). This lives here — not in `common/egress_inventory.rs` — because
    /// wiring the inventory to the quality manager would give `common`'s
    /// leaf-level inventory module an upward dependency on another `common`
    /// consumer; `PeerManager` already owns both `EgressInventory` and (via
    /// `GlobalCtx`) `Arc<EgressQualityManager>`, so it is the natural place to
    /// bridge the two.
    #[cfg(feature = "mpquic")]
    fn invalidate_stale_egress_quality_scopes(
        global_ctx: &ArcGlobalCtx,
        snapshot: &crate::common::egress_inventory::EgressInventorySnapshot,
        changed_or_removed: impl Iterator<Item = crate::common::egress_inventory::EgressStableId>,
    ) {
        use crate::common::transport_quality::budget::EgressDirection;

        let egress_quality = global_ctx.egress_quality_manager();
        for stable_id in changed_or_removed {
            // A changed interface keeps its stable_id but bumps `generation`
            // (see `egress_inventory::reconcile`). A removed interface is no
            // longer present in `snapshot` at all, so nothing can be
            // "current" for it: `u64::MAX` can never equal a real generation
            // counter, which forces every existing scope entry for that
            // stable_id to be treated as stale and retired.
            let current_generation = snapshot
                .interfaces
                .get(&stable_id)
                .map(|interface| interface.generation)
                .unwrap_or(u64::MAX);
            for direction in [EgressDirection::Egress, EgressDirection::Ingress] {
                egress_quality.invalidate_stale_generations(&stable_id, direction, current_generation);
            }
        }
    }

    #[cfg(feature = "mpquic")]
    fn wake_p2p_after_closed_mp_session_reap(
        p2p_demand_notify: &ExternalTaskSignal,
        reaped_sessions: usize,
    ) {
        if reaped_sessions > 0 {
            // Reaping also removes the old carrier table.  Waking the existing
            // task manager lets its normal bounded UDP-punch backoff create a
            // fresh raw/TQUIC offer on the same stable egress generation.
            p2p_demand_notify.notify();
        }
    }

    #[cfg(feature = "mpquic")]
    async fn run_mp_egress_inventory_lifecycle(&self, inventory: EgressInventory) {
        let mut event_receiver = inventory.subscribe();
        let manager = self.mp_session_manager.clone();
        let p2p_demand_notify = self.p2p_demand_notify.clone();
        let global_ctx = self.global_ctx.clone();
        self.tasks.lock().await.spawn(async move {
            let initial = inventory.snapshot();
            if let Err(error) = manager.reconcile_egress_bindings(&initial).await {
                tracing::warn!(
                    revision = initial.revision,
                    ?error,
                    "failed to reconcile MP carriers with initial egress inventory"
                );
            }

            loop {
                match event_receiver.recv().await {
                    Ok(EgressInventoryEvent::Reconciled { snapshot, diff, .. }) => {
                        Self::invalidate_stale_egress_quality_scopes(
                            &global_ctx,
                            &snapshot,
                            diff.changed.iter().chain(diff.removed.iter()).cloned(),
                        );
                        match manager.reconcile_egress_bindings(&snapshot).await {
                            Ok(retired) if retired > 0 => tracing::info!(
                                revision = snapshot.revision,
                                retired,
                                "retired MP carriers whose egress disappeared or changed generation"
                            ),
                            Ok(_) => {}
                            Err(error) => tracing::warn!(
                                revision = snapshot.revision,
                                ?error,
                                "failed to reconcile MP carriers with egress inventory"
                            ),
                        }
                        if global_ctx.get_feature_flags().mp_enabled {
                            Self::wake_p2p_after_egress_reconcile(&p2p_demand_notify);
                        }
                    }
                    Ok(EgressInventoryEvent::RefreshFailed { .. })
                    | Ok(EgressInventoryEvent::WatchFailed { .. }) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        event_receiver = event_receiver.resubscribe();
                        let snapshot = inventory.snapshot();
                        // No diff survives a lagged/dropped broadcast, so
                        // re-derive "changed" from every interface still
                        // present at its current generation; this is a no-op
                        // for anything untouched. An interface that vanished
                        // entirely during the gap is not covered here and
                        // relies on the manager's background strong-count
                        // reclaim instead of immediate invalidation.
                        Self::invalidate_stale_egress_quality_scopes(
                            &global_ctx,
                            &snapshot,
                            snapshot.interfaces.keys().cloned(),
                        );
                        match manager.reconcile_egress_bindings(&snapshot).await {
                            Ok(retired) => tracing::warn!(
                                skipped,
                                revision = snapshot.revision,
                                retired,
                                "egress inventory receiver lagged; reconciled all MP carrier bindings from the current snapshot"
                            ),
                            Err(error) => tracing::warn!(
                                skipped,
                                revision = snapshot.revision,
                                ?error,
                                "egress inventory receiver lagged and full MP carrier reconciliation failed"
                            ),
                        }
                        if global_ctx.get_feature_flags().mp_enabled {
                            Self::wake_p2p_after_egress_reconcile(&p2p_demand_notify);
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    #[cfg(feature = "mpquic")]
    async fn run_mp_control_routine(self: &Arc<Self>) {
        let manager = self.mp_session_manager.clone();
        let global_ctx = self.global_ctx.clone();
        // MP_SQM_PLAN.md S2.4 rate negotiation (consume half): `manager`
        // (`MpSessionManager`) is deliberately decoupled from `PeerMap`'s
        // async route-table API, and the injected lookup it calls every
        // control tick must be synchronous. Bridge the two with a small
        // cache this same loop refreshes (below, every iteration, before
        // `run_control_tick`) from `PeerMap::get_route_peer_info` --
        // `RoutePeerInfo.mp_max_rx_bps` is exactly the peer's announced
        // Brutal receive-rate ceiling `peer_ospf_route.rs` publishes.
        let remote_rx_bps_cache: Arc<DashMap<PeerId, u64>> = Arc::new(DashMap::new());
        {
            let cache = remote_rx_bps_cache.clone();
            manager
                .set_remote_rx_bps_lookup(Some(Arc::new(move |peer_id: PeerId| {
                    cache.get(&peer_id).map(|entry| *entry)
                })))
                .await;
        }
        // MP_SQM_PLAN.md S2.10: `RoutePeerInfo.mp_dataplane_caps`, same bridge.
        let remote_caps_cache: Arc<DashMap<PeerId, u32>> = Arc::new(DashMap::new());
        {
            let cache = remote_caps_cache.clone();
            manager
                .set_remote_dataplane_caps_lookup(Some(Arc::new(move |peer_id: PeerId| {
                    cache.get(&peer_id).map(|entry| *entry)
                })))
                .await;
        }
        // Weak, not Arc::clone: this task lives in `self.tasks`, a field of
        // `PeerManager` itself. Holding a strong `Arc<PeerManager>` here
        // would be a self-cycle — `self.tasks` (a JoinSet) only aborts its
        // tasks on Drop, and Drop only runs once the strong count reaches
        // zero, which this task's own strong ref would forever prevent. Each
        // iteration re-upgrades and drops the strong ref before sleeping, so
        // there is a window every tick where the task holds nothing and an
        // external drop of the last other `Arc<PeerManager>` can actually
        // free it; the next upgrade then fails and the loop exits cleanly.
        let peer_manager_weak = Arc::downgrade(self);
        self.tasks.lock().await.spawn(async move {
            let mut applied = None;
            loop {
                let Some(peer_manager) = peer_manager_weak.upgrade() else {
                    break;
                };
                // Refresh before this tick's `run_control_tick` so a peer's
                // changed announcement (or its removal) applies hot, per
                // MP_SQM_PLAN.md S2.4.
                {
                    let peer_map = peer_manager.get_peer_map();
                    let known_peers: std::collections::HashSet<PeerId> =
                        peer_map.list_peers().into_iter().collect();
                    for peer_id in &known_peers {
                        let info = peer_map.get_route_peer_info(*peer_id).await;
                        match info.as_ref().and_then(|info| info.mp_max_rx_bps) {
                            Some(rx_bps) => {
                                remote_rx_bps_cache.insert(*peer_id, rx_bps);
                            }
                            None => {
                                remote_rx_bps_cache.remove(peer_id);
                            }
                        }
                        match info.as_ref().and_then(|info| info.mp_dataplane_caps) {
                            Some(caps) => {
                                remote_caps_cache.insert(*peer_id, caps);
                            }
                            None => {
                                remote_caps_cache.remove(peer_id);
                            }
                        }
                    }
                    remote_rx_bps_cache.retain(|peer_id, _| known_peers.contains(peer_id));
                    remote_caps_cache.retain(|peer_id, _| known_peers.contains(peer_id));
                }
                let config = global_ctx
                    .get_flags()
                    .mp
                    .clone()
                    .unwrap_or_else(crate::common::config::gen_default_mp_config);
                if applied.as_ref() != Some(&config) {
                    match manager.set_config(config.clone()).await {
                        Ok(()) => {
                            if !config.enabled
                                || !config
                                    .providers
                                    .iter()
                                    .any(|provider| provider == "relay-next-hop")
                            {
                                let bridge_entries = peer_manager
                                    .mp_relay_transport
                                    .retire_all_paths()
                                    .len();
                                if bridge_entries > 0 {
                                    tracing::info!(
                                        bridge_entries,
                                        "removed relay MP bridge entries after provider configuration change"
                                    );
                                }
                            }
                            applied = Some(config.clone());
                        }
                        Err(error) => {
                            tracing::error!(?error, "failed to apply MP runtime config");
                        }
                    }
                }
                let manual_manager = manager.clone();
                let manual_global_ctx = global_ctx.clone();
                let manual_peer_manager_weak = Arc::downgrade(&peer_manager);
                tokio::spawn(async move {
                    let Some(manual_peer_manager) = manual_peer_manager_weak.upgrade() else {
                        return;
                    };
                    let offers = match manual_manager
                        .reconcile_manual_paths(
                            &manual_global_ctx,
                            manual_peer_manager.my_peer_id(),
                        )
                        .await
                    {
                        Ok(offers) => offers,
                        Err(error) => {
                            tracing::warn!(?error, "manual MP path reconciliation failed");
                            return;
                        }
                    };
                    for offer in offers {
                        let OfferPathResult::NewTunnel(tunnel) = offer.outcome else {
                            tracing::info!(
                                source = %offer.source,
                                peer_id = offer.peer_id,
                                "manual MP path added to an existing TQUIC session"
                            );
                            continue;
                        };
                        let Some(manual_peer_manager) = manual_peer_manager_weak.upgrade() else {
                            break;
                        };
                        let result = if offer.is_server {
                            manual_peer_manager
                                .add_tunnel_as_server(tunnel, false)
                                .await
                                .map(|_| ())
                        } else {
                            manual_peer_manager
                                .add_client_tunnel_with_peer_id_hint(
                                    tunnel,
                                    false,
                                    Some(offer.peer_id),
                                )
                                .await
                                .map(|_| ())
                        };
                        if let Err(error) = result {
                            tracing::warn!(
                                ?error,
                                source = %offer.source,
                                peer_id = offer.peer_id,
                                "manual MP tunnel handshake failed; retiring path"
                            );
                            if let Err(remove_error) =
                                manual_manager.remove_manual_path(&offer.source).await
                            {
                                tracing::warn!(
                                    ?remove_error,
                                    source = %offer.source,
                                    "failed to retire rejected manual MP path"
                                );
                            }
                        }
                    }
                });
                if config.enabled {
                    // The selection and the relay path budget both read the
                    // first hops' ping loss, so refresh it before either runs.
                    manager.set_first_hop_loss(
                        peer_manager
                            .relay_first_hop_qualities()
                            .await
                            .into_iter()
                            .filter_map(|(peer_id, quality)| Some((peer_id, quality?.loss)))
                            .collect(),
                    );
                    // A pass waits out an establishment timeout per unanswered
                    // first hop; the control tick (path promotion, TopK,
                    // scheduler targets) must not wait behind it.
                    if !peer_manager.mp_relay_reconciling.swap(true, Ordering::AcqRel) {
                        let reconciling = peer_manager.clone();
                        tokio::spawn(async move {
                            // Cleared on drop, so a panicking pass cannot stop later ones.
                            struct ClearOnDrop(Arc<AtomicBool>);
                            impl Drop for ClearOnDrop {
                                fn drop(&mut self) {
                                    self.0.store(false, Ordering::Release);
                                }
                            }
                            let _clear = ClearOnDrop(reconciling.mp_relay_reconciling.clone());
                            reconciling.reconcile_mp_relay_next_hops().await;
                        });
                    }
                    match manager.run_control_tick().await {
                        Ok(tick) => {
                            if tick.reaped_sessions > 0
                                && config
                                    .providers
                                    .iter()
                                    .any(|provider| provider == "udp-punch")
                            {
                                Self::wake_p2p_after_closed_mp_session_reap(
                                    &peer_manager.p2p_demand_notify,
                                    tick.reaped_sessions,
                                );
                                tracing::info!(
                                    reaped_sessions = tick.reaped_sessions,
                                    "reaped closed MP sessions; woke UDP-punch supervisor for controlled rebuild"
                                );
                            }
                            for snapshot in tick.snapshots {
                                tracing::debug!(
                                    active_paths = ?snapshot.active_paths,
                                    "MP path selection control tick"
                                );
                            }
                        }
                        Err(error) => tracing::warn!(?error, "MP control tick failed"),
                    }
                }
                let sleep_duration =
                    std::time::Duration::from_millis(config.control_interval_ms.max(1));
                // Drop the strong ref before sleeping (see the comment on
                // `peer_manager_weak` above) so a concurrent external drop of
                // the last other `Arc<PeerManager>` can actually reach zero
                // instead of being held open for the whole sleep interval.
                drop(peer_manager);
                tokio::time::sleep(sleep_duration).await;
            }
        });
    }

    #[cfg(feature = "mpquic")]
    async fn relay_next_hop_candidates(&self) -> Vec<PeerId> {
        Self::relay_next_hop_candidates_from_maps(
            &self.peers,
            &self.foreign_network_client,
            self.my_peer_id,
        )
        .await
    }

    /// What each relay first hop currently offers (`None`: no live
    /// connection).
    #[cfg(feature = "mpquic")]
    async fn relay_first_hop_qualities(
        &self,
    ) -> Vec<(PeerId, Option<crate::connector::mp_path::FirstHopQuality>)> {
        self.relay_next_hop_candidates()
            .await
            .into_iter()
            .map(|peer_id| {
                let quality =
                    Self::relay_first_hop_peer(&self.peers, &self.foreign_network_client, peer_id)
                        .and_then(|peer| {
                            crate::connector::mp_path::FirstHopQuality::best_of(
                                &peer.non_mpquic_link_quality(),
                            )
                        });
                (peer_id, quality)
            })
            .collect()
    }

    /// Relay first hops, best first: only `MP_RELAY_PATH_BUDGET` of them get a
    /// path to each peer. ET (no code to copy): reachable and not lossy, then
    /// reachable but lossy, then unreachable (every ping of the loss window
    /// lost), each by latency. The old latency-only order put a first hop that
    /// answered nothing ahead because `latency_us` keeps its last answered
    /// value (MP weak-network plan E2), and a hop with no answer yet (0) first
    /// of all.
    #[cfg(feature = "mpquic")]
    fn rank_relay_first_hops(
        hops: &[(PeerId, Option<crate::connector::mp_path::FirstHopQuality>)],
    ) -> Vec<PeerId> {
        use crate::connector::mp_path::FirstHopHealth;
        let mut ranked = hops
            .iter()
            .map(|&(peer_id, quality)| match quality {
                Some(quality) => (quality.health(), quality.latency_micros, peer_id),
                None => (FirstHopHealth::Unreachable, u64::MAX, peer_id),
            })
            .collect::<Vec<_>>();
        ranked.sort_unstable();
        ranked.into_iter().map(|(_, _, peer_id)| peer_id).collect()
    }

    /// The public-server connection lives in `ForeignNetworkClient`, not in
    /// the local network's `PeerMap`.  Both maps contain physical first hops
    /// which this node can send to directly, so the relay carrier selector must
    /// consider their live union.
    #[cfg(feature = "mpquic")]
    async fn relay_next_hop_candidates_from_maps(
        peers: &PeerMap,
        foreign_network_client: &ForeignNetworkClient,
        my_peer_id: PeerId,
    ) -> Vec<PeerId> {
        let primary = peers.list_peers_with_non_mpquic_conn().await;
        let foreign = foreign_network_client
            .get_peer_map()
            .list_peers_with_non_mpquic_conn()
            .await;
        Self::merge_relay_next_hop_candidates(my_peer_id, primary, foreign)
    }

    /// A physical first hop: a peer of the local network's `PeerMap`, else
    /// the public-server connection in `ForeignNetworkClient`.
    #[cfg(feature = "mpquic")]
    fn relay_first_hop_peer(
        peers: &PeerMap,
        foreign_network_client: &ForeignNetworkClient,
        peer_id: PeerId,
    ) -> Option<Arc<super::peer::Peer>> {
        peers
            .get_peer_by_id(peer_id)
            .or_else(|| foreign_network_client.get_peer_map().get_peer_by_id(peer_id))
    }

    /// The NIC carrying this node's EasyTier connection to `first_hop`, which
    /// a relay MP path through that peer physically leaves by: the default
    /// connection unless it is an mpquic one, as relay datagrams never ride
    /// mpquic (`send_msg_directly_non_mpquic`).
    #[cfg(feature = "mpquic")]
    async fn relay_first_hop_egress_device(
        peers: &PeerMap,
        foreign_network_client: &ForeignNetworkClient,
        first_hop: PeerId,
    ) -> Option<String> {
        let peer = Self::relay_first_hop_peer(peers, foreign_network_client, first_hop)?;
        let default_conn = peer.get_default_conn_id().to_string();
        let conns = peer.list_peer_conns().await;
        let is_mpquic = |conn: &&crate::proto::api::instance::PeerConnInfo| {
            conn.tunnel
                .as_ref()
                .is_some_and(|tunnel| tunnel.tunnel_type.starts_with("mpquic"))
        };
        let conn = conns
            .iter()
            .filter(|conn| !is_mpquic(conn))
            .find(|conn| conn.conn_id == default_conn)
            .or_else(|| conns.iter().find(|conn| !is_mpquic(conn)))?;
        let tunnel = conn.tunnel.as_ref()?;
        let socket_addr = |url: &crate::proto::common::Url| -> Option<std::net::SocketAddr> {
            let url = url::Url::parse(&url.url).ok()?;
            let port = url.port()?;
            match url.host()? {
                url::Host::Ipv4(ip) => Some((ip, port).into()),
                url::Host::Ipv6(ip) => Some((ip, port).into()),
                // `tcp://`/`udp://` are not special schemes to `url`: an IPv4
                // host stays an opaque host name.
                url::Host::Domain(host) => Some((host.parse::<std::net::IpAddr>().ok()?, port).into()),
            }
        };
        let remote = tunnel
            .resolved_remote_addr
            .as_ref()
            .and_then(socket_addr)
            .or_else(|| tunnel.remote_addr.as_ref().and_then(socket_addr))?;
        let local = tunnel.local_addr.as_ref().and_then(socket_addr);
        tokio::task::spawn_blocking(move || {
            crate::connector::mp_relay::first_hop_egress_device(local, remote)
        })
        .await
        .ok()
        .flatten()
    }

    #[cfg(feature = "mpquic")]
    fn merge_relay_next_hop_candidates(
        my_peer_id: PeerId,
        primary: Vec<PeerId>,
        foreign: Vec<PeerId>,
    ) -> Vec<PeerId> {
        let mut candidates: BTreeSet<_> = primary.into_iter().collect();
        candidates.extend(foreign);
        candidates.remove(&my_peer_id);
        candidates.into_iter().collect()
    }

    /// Return the MP destinations for which a relay carrier may be offered.
    ///
    /// A first relay carrier cannot depend on an existing MP session: that
    /// session may only have existed through a direct UDP/TCP path which has
    /// just disappeared.  The regular route table already proves that a
    /// destination is reachable through a live first hop, so use it to seed
    /// the first TQUIC session.  Direct destinations are excluded here because
    /// their route's next hop is the destination itself; those sessions are
    /// created by the direct providers instead.  Only destinations known to
    /// run MP are seeded: an active session, or a route that advertises
    /// `PeerFeatureFlag.mp_enabled`.  Any other peer (an official build) never
    /// answers, and offering it a carrier over every first hop only costs a
    /// TQUIC handshake that idles out each time -- the same rule MP punching
    /// follows (`connector::peer_runs_mp`).
    #[cfg(feature = "mpquic")]
    fn relay_seed_destinations(
        my_peer_id: PeerId,
        active_sessions: Vec<(PeerId, bool)>,
        routes: Vec<(PeerId, PeerId, bool)>,
        first_hops: &[PeerId],
    ) -> Vec<PeerId> {
        let first_hops = first_hops.iter().copied().collect::<BTreeSet<_>>();
        // Only a session's client opens new paths: a path its server adds is
        // only registered, waiting for a PATH_CHALLENGE that never comes, as
        // the client never learns of it. So with a session, its client offers
        // the relay paths, whichever end has the lower peer id.
        let served = active_sessions
            .iter()
            .filter(|(_, is_server)| *is_server)
            .map(|(peer_id, _)| *peer_id)
            .collect::<BTreeSet<_>>();
        let mut destinations = active_sessions
            .into_iter()
            .filter(|(_, is_server)| !is_server)
            .map(|(peer_id, _)| peer_id)
            .collect::<BTreeSet<_>>();
        for (peer_id, next_hop_peer_id, mp_enabled) in routes {
            // Without a session, a relay TQUIC path is bidirectional: let only
            // the lower peer id create the first client session; the other end
            // receives that same path as a server. Without this tie-break,
            // both ends repeatedly create client sessions and neither gets a
            // stable server-side stream under loss.
            if mp_enabled
                && peer_id > my_peer_id
                && !served.contains(&peer_id)
                && peer_id != next_hop_peer_id
                && first_hops.contains(&next_hop_peer_id)
            {
                destinations.insert(peer_id);
            }
        }
        destinations.into_iter().collect()
    }

    /// Wait before re-offering a relay path that has not come up: 10 s after
    /// the first offer, doubling up to 1 min.
    #[cfg(feature = "mpquic")]
    fn relay_offer_backoff(offers: u32) -> std::time::Duration {
        std::time::Duration::from_secs(10u64 << offers.saturating_sub(1).min(5))
            .min(std::time::Duration::from_secs(60))
    }

    #[cfg(feature = "mpquic")]
    fn relay_next_hop_is_live(
        peers: &PeerMap,
        foreign_network_client: &ForeignNetworkClient,
        peer_id: PeerId,
    ) -> bool {
        peers
            .get_peer_by_id(peer_id)
            .is_some_and(|peer| peer.has_live_non_mpquic_conns())
            || foreign_network_client
                .get_peer_map()
                .get_peer_by_id(peer_id)
                .is_some_and(|peer| peer.has_live_non_mpquic_conns())
    }

    #[cfg(feature = "mpquic")]
    async fn send_relay_datagram_to_first_hop(
        peers: &Arc<PeerMap>,
        foreign_network_client: &Arc<ForeignNetworkClient>,
        packet: ZCPacket,
        first_hop_peer_id: PeerId,
    ) -> Result<(), Error> {
        if peers.has_peer(first_hop_peer_id) {
            return peers
                .send_msg_directly_non_mpquic(packet, first_hop_peer_id)
                .await;
        }
        if foreign_network_client.has_next_hop(first_hop_peer_id) {
            return foreign_network_client
                .get_peer_map()
                .send_msg_directly_non_mpquic(packet, first_hop_peer_id)
                .await;
        }
        Err(Error::RouteError(Some(format!(
            "relay MP first hop is no longer directly sendable: {first_hop_peer_id}"
        ))))
    }

    #[cfg(feature = "mpquic")]
    async fn run_mp_relay_data_plane(self: &Arc<Self>) {
        let Some(mut outbound_rx) = self.mp_relay_outbound_rx.lock().await.take() else {
            return;
        };
        let peers = self.peers.clone();
        let foreign_network_client = self.foreign_network_client.clone();
        let my_peer_id = self.my_peer_id;
        self.tasks.lock().await.spawn(async move {
            while let Some(datagram) = outbound_rx.recv().await {
                if datagram.egress_first_hop_peer_id == my_peer_id {
                    tracing::warn!(
                        destination_peer_id = datagram.destination_peer_id,
                        "dropping relay MP datagram whose selected first hop is self"
                    );
                    continue;
                }
                let first_hop_peer_id = datagram.egress_first_hop_peer_id;
                let destination_peer_id = datagram.destination_peer_id;
                let route_generation = datagram.route_generation;
                let mut packet = ZCPacket::new_with_payload(&datagram.encode());
                packet.fill_peer_manager_hdr(
                    my_peer_id,
                    destination_peer_id,
                    PacketType::MpRelayDatagram as u8,
                );
                packet
                    .mut_peer_manager_header()
                    .expect("fresh relay MP packet has a peer manager header")
                    .set_not_send_to_tun(true);
                if let Err(error) = PeerManager::send_relay_datagram_to_first_hop(
                    &peers,
                    &foreign_network_client,
                    packet,
                    first_hop_peer_id,
                )
                .await
                {
                    tracing::warn!(
                        ?error,
                        first_hop_peer_id,
                        destination_peer_id,
                        route_generation,
                        "relay MP first-hop delivery failed; TQUIC will recover through its path lifecycle"
                    );
                }
            }
        });
    }

    #[cfg(feature = "mpquic")]
    async fn run_mp_relay_tunnel_attach(self: &Arc<Self>) {
        let Some(mut tunnel_rx) = self.mp_relay_tunnel_rx.lock().await.take() else {
            return;
        };
        // Weak, not Arc::clone: same self-cycle hazard as
        // `run_mp_control_routine` above — this task lives in `self.tasks`,
        // a field of the very `PeerManager` a strong clone would keep alive
        // forever. `mp_relay_tunnel_tx` (the sender half) is itself a
        // `PeerManager` field, so once every other `Arc<PeerManager>` is
        // gone the channel closes on its own and `recv()` returns `None`;
        // the `upgrade()` here only guards the brief window between
        // receiving a tunnel and finishing its handshake.
        let peer_manager_weak = Arc::downgrade(self);
        self.tasks.lock().await.spawn(async move {
            while let Some(tunnel) = tunnel_rx.recv().await {
                let Some(peer_manager) = peer_manager_weak.upgrade() else {
                    break;
                };
                if let Err(error) = peer_manager.add_tunnel_as_server(tunnel, false).await {
                    tracing::warn!(?error, "relay MP server tunnel handshake failed");
                }
            }
        });
    }

    #[cfg(feature = "mpquic")]
    async fn reconcile_mp_relay_next_hops(self: &Arc<Self>) {
        let config = self
            .global_ctx
            .get_flags()
            .mp
            .clone()
            .unwrap_or_else(crate::common::config::gen_default_mp_config);
        if !config.enabled
            || !config
                .providers
                .iter()
                .any(|provider| provider == "relay-next-hop")
        {
            return;
        }

        let first_hops = Self::rank_relay_first_hops(&self.relay_first_hop_qualities().await);
        let destinations = Self::relay_seed_destinations(
            self.my_peer_id,
            self.mp_session_manager.active_sessions().await,
            self.list_routes()
                .await
                .into_iter()
                .map(|route| {
                    let mp_enabled = route.feature_flag.is_some_and(|flag| flag.mp_enabled);
                    (route.peer_id, route.next_hop_peer_id, mp_enabled)
                })
                .collect(),
            &first_hops,
        );
        self.mp_relay_offer_backoff
            .retain(|(destination, _), _| destinations.contains(destination));
        let route_generation = self.mp_relay_route_generation.load(Ordering::Relaxed);
        for destination_peer_id in destinations {
            let mut relay_paths = self
                .mp_session_manager
                .live_relay_path_count(destination_peer_id)
                .await;
            for &first_hop_peer_id in &first_hops {
                if first_hop_peer_id == self.my_peer_id || first_hop_peer_id == destination_peer_id
                {
                    continue;
                }
                let backoff_key = (destination_peer_id, first_hop_peer_id);
                if self
                    .mp_session_manager
                    .has_live_relay_egress(destination_peer_id, first_hop_peer_id)
                    .await
                {
                    self.mp_relay_offer_backoff.remove(&backoff_key);
                    continue;
                }
                if relay_paths >= MP_RELAY_PATH_BUDGET {
                    continue;
                }
                let now = std::time::Instant::now();
                let offers = match self.mp_relay_offer_backoff.get(&backoff_key) {
                    Some(entry) => {
                        let (last_offer, offers) = *entry;
                        if now < last_offer + Self::relay_offer_backoff(offers) {
                            continue;
                        }
                        offers
                    }
                    None => 0,
                };
                self.mp_relay_offer_backoff
                    .insert(backoff_key, (now, offers.saturating_add(1)));
                let identity = crate::connector::mp_relay::RelayPathIdentity::from_origin(
                    self.my_peer_id,
                    destination_peer_id,
                    first_hop_peer_id,
                    route_generation,
                );
                let egress_device = Self::relay_first_hop_egress_device(
                    &self.peers,
                    &self.foreign_network_client,
                    first_hop_peer_id,
                )
                .await;
                let spec = relay_path_spec(
                    identity,
                    self.mp_relay_transport.open_source_path(identity),
                    first_hop_peer_id,
                    egress_device.as_deref(),
                );
                let key = spec.key;
                let remote_url = crate::tunnel::build_url_from_socket_addr(
                    &identity.remote_addr.to_string(),
                    "mpquic",
                );
                relay_paths += 1;
                tracing::info!(
                    my_peer_id = self.my_peer_id,
                    destination_peer_id,
                    first_hop_peer_id,
                    route_generation,
                    "offering relay MP client TQUIC path"
                );
                match self
                    .mp_session_manager
                    .offer_path_spec(
                        destination_peer_id,
                        false,
                        spec,
                        remote_url,
                        "mpquic_relay_next_hop",
                    )
                    .await
                {
                    Ok(OfferPathResult::PathAdded) => {}
                    Ok(OfferPathResult::NewTunnel(tunnel)) => {
                        if let Err(error) = self
                            .add_client_tunnel_with_peer_id_hint(
                                tunnel,
                                false,
                                Some(destination_peer_id),
                            )
                            .await
                        {
                            tracing::warn!(
                                ?error,
                                destination_peer_id,
                                first_hop_peer_id,
                                "relay MP client tunnel handshake failed; retiring carrier"
                            );
                            let _ = self
                                .mp_session_manager
                                .retire_path(destination_peer_id, &key)
                                .await;
                            self.mp_relay_transport.retire_path(&identity);
                        }
                    }
                    Err(error) => {
                        tracing::debug!(
                            ?error,
                            destination_peer_id,
                            first_hop_peer_id,
                            "relay MP candidate is not usable yet"
                        );
                        self.mp_relay_transport.retire_path(&identity);
                    }
                }
            }
        }
    }

    #[cfg(feature = "mpquic")]
    async fn run_mp_relay_lifecycle(self: &Arc<Self>) {
        let mut event_receiver = self.global_ctx.subscribe();
        let peers = self.peers.clone();
        let foreign_network_client = self.foreign_network_client.clone();
        let manager = self.mp_session_manager.clone();
        let transport = self.mp_relay_transport.clone();
        let route_generation = self.mp_relay_route_generation.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                let removed_peer_id = match event_receiver.recv().await {
                    Ok(GlobalCtxEvent::PeerConnAdded(_)) => {
                        route_generation.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    Ok(GlobalCtxEvent::PeerConnRemoved(conn)) => {
                        route_generation.fetch_add(1, Ordering::Relaxed);
                        conn.peer_id
                    }
                    Ok(GlobalCtxEvent::PeerRemoved(peer_id)) => {
                        route_generation.fetch_add(1, Ordering::Relaxed);
                        peer_id
                    }
                    Ok(_) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(skipped, "relay MP lifecycle event receiver lagged");
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                };
                if PeerManager::relay_next_hop_is_live(
                    &peers,
                    &foreign_network_client,
                    removed_peer_id,
                ) {
                    continue;
                }
                let (retired, kept) =
                    retire_relay_paths_for_first_hop(&manager, &transport, removed_peer_id).await;
                if kept > 0 {
                    tracing::info!(
                        first_hop_peer_id = removed_peer_id,
                        kept,
                        "relay MP path is the session's last path; keeping it while its                          first hop recovers, QUIC's idle timeout decides whether the                          session lives"
                    );
                }
                if retired > 0 {
                    tracing::info!(
                        first_hop_peer_id = removed_peer_id,
                        carrier_count = retired,
                        "removed relay MP carriers after direct first-hop disconnect"
                    );
                }
            }
        });
    }

    async fn run_foriegn_network(&self) {
        self.peer_rpc_tspt
            .foreign_peers
            .lock()
            .await
            .replace(Arc::downgrade(&self.foreign_network_client));

        self.foreign_network_client.run().await;
    }

    pub async fn run(self: &Arc<Self>) -> Result<(), Error> {
        match self.start_egress_inventory().await {
            Ok(_inventory) => {
                #[cfg(feature = "mpquic")]
                self.run_mp_egress_inventory_lifecycle(_inventory.clone())
                    .await;
            }
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "failed to start egress inventory; read-only egress API unavailable"
                );
            }
        }

        match &self.route_algo_inst {
            RouteAlgoInst::Ospf(route) => self.add_route(route.clone()).await,
            RouteAlgoInst::None => {}
        };

        self.init_packet_process_pipeline().await;
        self.peer_rpc_mgr.run();

        #[cfg(feature = "mpquic")]
        self.run_mp_relay_data_plane().await;
        #[cfg(feature = "mpquic")]
        self.run_mp_relay_tunnel_attach().await;
        #[cfg(feature = "mpquic")]
        self.run_mp_relay_lifecycle().await;
        self.start_peer_recv().await;
        self.run_clean_peer_without_conn_routine().await;
        self.run_relay_session_gc_routine().await;
        self.run_recent_traffic_gc_routine().await;
        self.run_peer_session_gc_routine().await;
        self.run_credential_gc_routine().await;
        self.run_traffic_metrics_gc_routine().await;
        #[cfg(feature = "mpquic")]
        self.run_mp_peer_lifecycle_routine().await;
        #[cfg(feature = "mpquic")]
        self.run_mp_control_routine().await;

        self.run_foriegn_network().await;

        Ok(())
    }

    pub fn get_peer_map(&self) -> Arc<PeerMap> {
        self.peers.clone()
    }

    pub fn get_relay_peer_map(&self) -> Arc<RelayPeerMap> {
        self.relay_peer_map.clone()
    }

    pub fn get_peer_rpc_mgr(&self) -> Arc<PeerRpcManager> {
        self.peer_rpc_mgr.clone()
    }

    pub fn get_peer_session_store(&self) -> Arc<PeerSessionStore> {
        self.peer_session_store.clone()
    }

    #[cfg(feature = "mpquic")]
    pub(crate) fn get_mp_session_manager(&self) -> Arc<MpSessionManager> {
        self.mp_session_manager.clone()
    }

    pub fn my_node_id(&self) -> uuid::Uuid {
        self.global_ctx.get_id()
    }

    pub fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    pub fn get_global_ctx(&self) -> ArcGlobalCtx {
        self.global_ctx.clone()
    }

    pub fn get_global_ctx_ref(&self) -> &ArcGlobalCtx {
        &self.global_ctx
    }

    pub async fn start_egress_inventory(&self) -> Result<&EgressInventory, InventoryError> {
        self.egress_inventory
            .get_or_try_init(|| async {
                let inventory = EgressInventory::start(
                    self.global_ctx.net_ns.clone(),
                    EgressInventoryConfig::default(),
                )
                .await?;
                // MP_SQM_PLAN.md S1.3 (remainder): also publish onto
                // `GlobalCtx`, the one handle every connector/listener
                // factory already holds (even those built with no
                // `PeerManager` reference at all), so `scope_for` can resolve
                // a real binding via `best_route_to` instead of always
                // falling back.
                self.global_ctx.set_egress_inventory(inventory.clone());
                Ok(inventory)
            })
            .await
    }

    pub fn get_egress_inventory(&self) -> Option<&EgressInventory> {
        self.egress_inventory.get()
    }

    pub fn get_nic_channel(&self) -> PacketRecvChan {
        self.nic_channel.clone()
    }

    pub fn get_foreign_network_manager(&self) -> Arc<ForeignNetworkManager> {
        self.foreign_network_manager.clone()
    }

    pub fn get_foreign_network_client(&self) -> Arc<ForeignNetworkClient> {
        self.foreign_network_client.clone()
    }

    pub async fn get_my_info(&self) -> instance::NodeInfo {
        instance::NodeInfo {
            peer_id: self.my_peer_id,
            ipv4_addr: self
                .global_ctx
                .get_ipv4()
                .map(|x| x.to_string())
                .unwrap_or_default(),
            proxy_cidrs: self
                .global_ctx
                .config
                .get_proxy_cidrs()
                .into_iter()
                .map(|x| match x.mapped_cidr {
                    None => x.cidr.to_string(),
                    Some(mapped) => format!("{}->{}", x.cidr, mapped),
                })
                .collect(),
            hostname: self.global_ctx.get_hostname(),
            stun_info: Some(self.global_ctx.get_stun_info_collector().get_stun_info()),
            inst_id: self.global_ctx.get_id().to_string(),
            listeners: self
                .global_ctx
                .get_running_listeners()
                .iter()
                .map(|x| x.to_string())
                .collect(),
            config: self.global_ctx.config.dump(),
            version: EASYTIER_VERSION.to_string(),
            feature_flag: Some(self.global_ctx.get_feature_flags()),
            ip_list: Some(self.global_ctx.get_ip_collector().collect_ip_addrs().await),
            public_ipv6_addr: self.get_my_public_ipv6_addr().await.map(Into::into),
            ipv6_public_addr_prefix: self
                .global_ctx
                .get_advertised_ipv6_public_addr_prefix()
                .map(|prefix| {
                    cidr::Ipv6Inet::new(prefix.first_address(), prefix.network_length())
                        .unwrap()
                        .into()
                }),
        }
    }

    pub async fn wait(&self) {
        while !self.tasks.lock().await.is_empty() {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    pub async fn clear_resources(&self) {
        let mut peer_pipeline = self.peer_packet_process_pipeline.write().await;
        peer_pipeline.clear();
        let mut nic_pipeline = self.nic_packet_process_pipeline.write().await;
        nic_pipeline.clear();

        self.peer_rpc_mgr.rpc_server().registry().unregister_all();
    }

    pub async fn close_peer_conn(
        &self,
        peer_id: PeerId,
        conn_id: &PeerConnId,
    ) -> Result<(), Error> {
        let ret = self.peers.close_peer_conn(peer_id, conn_id).await;
        tracing::info!("close_peer_conn in peer map: {:?}", ret);
        if ret.is_ok() || !matches!(ret.as_ref().unwrap_err(), Error::NotFound) {
            return ret;
        }

        let ret = self
            .foreign_network_client
            .get_peer_map()
            .close_peer_conn(peer_id, conn_id)
            .await;
        tracing::info!("close_peer_conn in foreign network client: {:?}", ret);
        if ret.is_ok() || !matches!(ret.as_ref().unwrap_err(), Error::NotFound) {
            return ret;
        }

        let ret = self
            .foreign_network_manager
            .close_peer_conn(peer_id, conn_id)
            .await;
        tracing::info!("close_peer_conn in foreign network manager done: {:?}", ret);
        ret
    }

    pub async fn check_allow_kcp_to_dst(&self, dst_ip: &IpAddr) -> bool {
        let route = self.get_route();
        let Some(dst_peer_id) = route.get_peer_id_by_ip(dst_ip).await else {
            return false;
        };
        let Some(peer_info) = route.get_peer_info(dst_peer_id).await else {
            return false;
        };

        // check dst allow kcp input
        if !peer_info.feature_flag.map(|x| x.kcp_input).unwrap_or(false) {
            return false;
        }

        let next_hop_policy = Self::get_next_hop_policy(
            self.global_ctx.get_flags().latency_first,
            None,
            !self.peers.endpoint_mp_owns_routing(dst_peer_id),
        );
        // check relay node allow relay kcp.
        let Some(next_hop_id) = route
            .get_next_hop_with_policy(dst_peer_id, next_hop_policy)
            .await
        else {
            return false;
        };

        if next_hop_id == dst_peer_id {
            // dst p2p, no need to relay
            return true;
        }

        let Some(next_hop_info) = route.get_peer_info(next_hop_id).await else {
            return false;
        };

        // check next hop allow kcp relay
        if next_hop_info
            .feature_flag
            .map(|x| x.no_relay_kcp)
            .unwrap_or(false)
        {
            return false;
        }

        true
    }

    pub async fn check_allow_quic_to_dst(&self, dst_ip: &IpAddr) -> bool {
        let route = self.get_route();
        let Some(dst_peer_id) = route.get_peer_id_by_ip(dst_ip).await else {
            return false;
        };
        let Some(peer_info) = route.get_peer_info(dst_peer_id).await else {
            return false;
        };

        // check dst allow quic input
        if !peer_info
            .feature_flag
            .map(|x| x.quic_input)
            .unwrap_or(false)
        {
            return false;
        }

        let next_hop_policy = Self::get_next_hop_policy(
            self.global_ctx.get_flags().latency_first,
            None,
            !self.peers.endpoint_mp_owns_routing(dst_peer_id),
        );
        // check relay node allow relay quic.
        let Some(next_hop_id) = route
            .get_next_hop_with_policy(dst_peer_id, next_hop_policy)
            .await
        else {
            return false;
        };

        if next_hop_id == dst_peer_id {
            // dst p2p, no need to relay
            return true;
        }

        let Some(next_hop_info) = route.get_peer_info(next_hop_id).await else {
            return false;
        };

        // check next hop allow quic relay
        if next_hop_info
            .feature_flag
            .map(|x| x.no_relay_quic)
            .unwrap_or(false)
        {
            return false;
        }

        true
    }

    pub async fn update_exit_nodes(&self) {
        let exit_nodes = self.global_ctx.config.get_exit_nodes();
        *self.exit_nodes.write().await = exit_nodes;
    }
}

/// A relay first hop went away: gives up the relay MP carriers that leave
/// through it, except those whose session refuses to let the path go because
/// it is the session's last open one. The session decides, per carrier and
/// every time, so a repeated event for the same hop (`PeerConnRemoved`, then
/// `PeerRemoved`) cannot take what the first one kept. Returns
/// `(retired, kept)` carrier counts.
#[cfg(feature = "mpquic")]
async fn retire_relay_paths_for_first_hop(
    manager: &MpSessionManager,
    transport: &RelayNextHopTransport,
    first_hop_peer_id: PeerId,
) -> (usize, usize) {
    let (mut retired, mut kept) = (0, 0);
    for identity in transport.paths_for_egress_first_hop(first_hop_peer_id) {
        match manager
            .retire_path_by_addresses(
                identity.destination_peer_id,
                identity.local_addr,
                identity.remote_addr,
            )
            .await
        {
            Ok(true) => {
                transport.retire_path(&identity);
                retired += 1;
            }
            Ok(false) => kept += 1,
            Err(error) => tracing::warn!(
                ?error,
                first_hop_peer_id,
                "failed to retire relay MP path after direct first-hop disconnect"
            ),
        }
    }
    (retired, kept)
}

#[cfg(all(test, feature = "mpquic"))]
mod relay_lifecycle_tests {
    use super::*;
    use crate::common::egress_quality::{EgressQualityConfig, EgressQualityManager};
    use crate::connector::mp_relay::RelayPathIdentity;

    /// The session's only validated relay path has no candidate left (its
    /// validation timed out); the first hop's two events both find the driver
    /// refusing, so the carrier stays through both.
    #[tokio::test]
    async fn the_last_path_keeps_its_carrier_through_repeated_first_hop_events() {
        let manager = MpSessionManager::new(EgressQualityManager::new(EgressQualityConfig::default()));
        manager.insert_refusing_session_for_test(202);
        let (transport, _outbound) = RelayNextHopTransport::new();
        let identity = RelayPathIdentity::from_origin(101, 202, 303, 7);
        let _carrier = transport.open_source_path(identity);

        for _ in 0..2 {
            assert_eq!(
                retire_relay_paths_for_first_hop(&manager, &transport, 303).await,
                (0, 1)
            );
            assert_eq!(transport.paths_for_egress_first_hop(303), vec![identity]);
        }
    }

    /// With no session left to refuse, the carrier goes with its first hop.
    #[tokio::test]
    async fn a_carrier_without_a_session_goes_with_its_first_hop() {
        let manager = MpSessionManager::new(EgressQualityManager::new(EgressQualityConfig::default()));
        let (transport, _outbound) = RelayNextHopTransport::new();
        let identity = RelayPathIdentity::from_origin(101, 202, 303, 7);
        let _carrier = transport.open_source_path(identity);

        assert_eq!(
            retire_relay_paths_for_first_hop(&manager, &transport, 303).await,
            (1, 0)
        );
        assert!(transport.paths_for_egress_first_hop(303).is_empty());
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use std::{
        collections::HashMap,
        fmt::Debug,
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
        time::Duration,
    };

    use hotpath::instant::Instant;

    use crate::{
        common::{
            PeerId,
            config::{Flags, gen_default_mp_config},
            global_ctx::{NetworkIdentity, tests::get_mock_global_ctx},
            stats_manager::{LabelSet, LabelType, MetricName},
        },
        connector::{
            create_connector_by_url,
            direct::PeerManagerForDirectConnector,
            udp_hole_punch::tests::{
                create_mock_peer_manager_with_mock_stun, replace_stun_info_collector,
            },
        },
        instance::listeners::create_listener_by_url,
        peers::{
            create_packet_recv_chan,
            peer_conn::tests::set_secure_mode_cfg,
            peer_manager::RouteAlgoType,
            peer_rpc::tests::register_service,
            route_trait::{NextHopPolicy, RouteCostCalculatorInterface},
            tests::{
                connect_peer_manager, create_mock_peer_manager_with_name,
                wait_route_appear, wait_route_appear_with_cost,
            },
        },
        proto::{
            common::{CompressionAlgoPb, NatType, SecureModeConfig},
            peer_rpc::SecureAuthLevel,
        },
        tunnel::{
            TunnelConnector, TunnelListener,
            common::tests::wait_for_condition,
            filter::{TunnelWithFilter, tests::DropSendTunnelFilter},
            packet_def::{PacketType, ZCPacket},
            ring::create_ring_tunnel_pair,
        },
    };

    use super::PeerManager;

    #[cfg(feature = "mpquic")]
    use crate::connector::{
        mp_relay::{RelayDatagram, RelayPathIdentity, relay_path_spec},
        mp_session::OfferPathResult,
    };

    async fn create_lazy_peer_manager() -> Arc<PeerManager> {
        let peer_mgr = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let mut flags = peer_mgr.get_global_ctx().get_flags();
        flags.lazy_p2p = true;
        peer_mgr.get_global_ctx().set_flags(flags);
        peer_mgr
    }

    #[cfg(feature = "mpquic")]
    async fn create_relay_mp_peer_manager(
        ipv4: &str,
    ) -> (Arc<PeerManager>, crate::peers::PacketRecvChanReceiver) {
        // The production controller ticks immediately at startup and then
        // periodically.  Keep the test deterministic: it drives precisely
        // one hand-picked first-hop carrier below, rather than racing an
        // independently discovered one.
        create_relay_mp_peer_manager_ticking_every(ipv4, 60_000).await
    }

    #[cfg(feature = "mpquic")]
    async fn create_relay_mp_peer_manager_ticking_every(
        ipv4: &str,
        control_interval_ms: u64,
    ) -> (Arc<PeerManager>, crate::peers::PacketRecvChanReceiver) {
        let global_ctx = get_mock_global_ctx();
        let mut flags = global_ctx.get_flags();
        let mut mp = gen_default_mp_config();
        mp.enabled = true;
        mp.providers = vec!["relay-next-hop".to_string()];
        mp.control_interval_ms = control_interval_ms;
        flags.mp = Some(mp);
        flags.disable_upnp = true;
        global_ctx.set_flags(flags);
        global_ctx.set_ipv4(Some(ipv4.parse().unwrap()));

        let (nic_tx, nic_rx) = create_packet_recv_chan();
        let peer_mgr = Arc::new(PeerManager::new(RouteAlgoType::Ospf, global_ctx, nic_tx));
        replace_stun_info_collector(peer_mgr.clone(), NatType::Unknown);
        peer_mgr.run().await.unwrap();
        (peer_mgr, nic_rx)
    }

    #[cfg(feature = "mpquic")]
    fn ipv4_tcp_syn(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
        fn checksum(bytes: &[u8]) -> u16 {
            let mut sum = 0u32;
            for chunk in bytes.chunks(2) {
                let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
                sum = sum.wrapping_add(u32::from(word));
            }
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            !(sum as u16)
        }

        // A minimal wire-valid IPv4/TCP SYN: no payload, IPv4 IHL=5,
        // TCP data offset=5, and checksums populated from the pseudo header.
        let mut packet = vec![
            0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0xff, 0x3b, 0x61, 0x01, 0x02, 0x03, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        ];
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        let ipv4_checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ipv4_checksum.to_be_bytes());

        let mut pseudo_header = Vec::with_capacity(12 + 20);
        pseudo_header.extend_from_slice(&source.octets());
        pseudo_header.extend_from_slice(&destination.octets());
        pseudo_header.extend_from_slice(&[0, 6, 0, 20]);
        pseudo_header.extend_from_slice(&packet[20..]);
        let tcp_checksum = checksum(&pseudo_header);
        packet[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());
        packet
    }

    /// A minimal wire-valid IPv4/UDP datagram (IHL=5, no payload). Unlike
    /// `ipv4_tcp_syn`, the UDP checksum is left at `0` -- a legal "no
    /// checksum" for IPv4 UDP -- so this does not need a pseudo-header
    /// checksum pass; `packet_flow_hash`'s `UdpPacket::new` parse only reads
    /// source/destination port, never validates the checksum.
    #[cfg(feature = "mpquic")]
    fn ipv4_udp_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        dest_port: u16,
    ) -> Vec<u8> {
        fn checksum(bytes: &[u8]) -> u16 {
            let mut sum = 0u32;
            for chunk in bytes.chunks(2) {
                let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
                sum = sum.wrapping_add(u32::from(word));
            }
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            !(sum as u16)
        }

        let mut packet = vec![
            0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
        ];
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dest_port.to_be_bytes());
        let ipv4_checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ipv4_checksum.to_be_bytes());
        packet
    }

    #[test]
    fn endpoint_mp_bypass_never_selects_overlay_weighted_policy() {
        assert!(matches!(
            PeerManager::get_next_hop_policy(false, Some(123), false),
            NextHopPolicy::LeastHop
        ));
        assert!(matches!(
            PeerManager::get_next_hop_policy(true, Some(123), false),
            NextHopPolicy::LeastCost
        ));
    }

    #[test]
    fn relay_datagram_direct_send_excludes_endpoint_mp_carrier() {
        assert!(PeerManager::direct_send_requires_non_mpquic_carrier(
            PacketType::MpRelayDatagram as u8
        ));
        assert!(!PeerManager::direct_send_requires_non_mpquic_carrier(
            PacketType::Data as u8
        ));
    }

    #[test]
    fn relay_datagram_never_uses_overlay_weighted_reroute() {
        assert!(PeerManager::allow_overlay_weighted_for_packet(
            false,
            PacketType::Data as u8,
        ));
        assert!(!PeerManager::allow_overlay_weighted_for_packet(
            true,
            PacketType::Data as u8,
        ));
        assert!(
            !PeerManager::allow_overlay_weighted_for_packet(
                false,
                PacketType::MpRelayDatagram as u8,
            ),
            "an intermediate node must forward relay MP datagrams through the normal ET path"
        );
    }

    #[cfg(feature = "mpquic")]
    #[test]
    fn relay_datagram_transit_packet_is_not_consumed_at_first_hop() {
        let source_peer_id = 101;
        let destination_peer_id = 202;
        let first_hop_peer_id = 303;
        let datagram = RelayDatagram::from_identity(
            RelayPathIdentity::from_origin(
                source_peer_id,
                destination_peer_id,
                first_hop_peer_id,
                1,
            ),
            vec![1, 2, 3],
        );

        assert!(
            !PeerManager::relay_datagram_is_local_terminal(
                first_hop_peer_id,
                source_peer_id,
                destination_peer_id,
                &datagram,
            )
            .expect("a well-formed transit relay datagram is not an error"),
            "the selected first hop must pass the relay datagram into normal forwarding"
        );
    }

    fn metric_value(peer_mgr: &PeerManager, metric: MetricName, labels: &LabelSet) -> u64 {
        peer_mgr
            .get_global_ctx()
            .stats_manager()
            .get_metric(metric, labels)
            .map(|metric| metric.value)
            .unwrap_or(0)
    }

    fn network_labels(peer_mgr: &PeerManager) -> LabelSet {
        LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr.get_global_ctx().get_network_name(),
        ))
    }

    struct TestCostCalculator {
        costs: HashMap<(PeerId, PeerId), i32>,
    }

    impl RouteCostCalculatorInterface for TestCostCalculator {
        fn calculate_cost(&self, src: PeerId, dst: PeerId) -> i32 {
            *self.costs.get(&(src, dst)).unwrap_or(&1)
        }
    }

    #[test]
    fn recent_traffic_fanout_policy_only_marks_single_peer() {
        assert!(PeerManager::should_mark_recent_traffic_for_fanout(0));
        assert!(PeerManager::should_mark_recent_traffic_for_fanout(1));
        assert!(!PeerManager::should_mark_recent_traffic_for_fanout(2));
    }

    #[cfg(all(feature = "mpquic", target_os = "linux"))]
    #[tokio::test]
    async fn egress_change_does_not_wake_p2p_workers_while_mp_is_off() {
        let peer_mgr = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let signal = peer_mgr.p2p_demand_notify();
        let inventory = peer_mgr.get_egress_inventory().unwrap().clone();
        let initial_version = signal.version();
        let initial_revision = inventory.snapshot().revision;

        let ip = |args: &[&str]| {
            assert!(
                std::process::Command::new("ip")
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            )
        };
        ip(&["link", "add", "etdummy0", "type", "dummy"]);
        ip(&["addr", "add", "10.77.0.1/24", "dev", "etdummy0"]);
        ip(&["link", "set", "etdummy0", "up"]);

        wait_for_condition(
            || {
                let inventory = inventory.clone();
                async move { inventory.snapshot().revision > initial_revision }
            },
            Duration::from_secs(10),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        ip(&["link", "del", "etdummy0"]);

        assert_eq!(
            signal.version(),
            initial_version,
            "with MP off an interface change must not wake the native p2p workers"
        );
    }

    #[cfg(feature = "mpquic")]
    #[test]
    fn egress_reconcile_wakes_p2p_workers_for_each_consumed_snapshot() {
        use crate::peers::peer_task::ExternalTaskSignal;

        let signal = ExternalTaskSignal::new();
        let initial_version = signal.version();
        PeerManager::wake_p2p_after_egress_reconcile(&signal);
        PeerManager::wake_p2p_after_egress_reconcile(&signal);
        assert_eq!(
            signal.version(),
            initial_version + 2,
            "both normal reconciliation and lag-recovery reconciliation must prompt a fresh p2p collection"
        );
    }

    #[cfg(feature = "mpquic")]
    #[test]
    fn closed_mp_session_reap_wakes_udp_punch_supervisor_only_when_needed() {
        use crate::peers::peer_task::ExternalTaskSignal;

        let signal = ExternalTaskSignal::new();
        let initial_version = signal.version();
        PeerManager::wake_p2p_after_closed_mp_session_reap(&signal, 0);
        assert_eq!(
            signal.version(),
            initial_version,
            "a healthy control tick must not reset UDP-punch backoff"
        );

        PeerManager::wake_p2p_after_closed_mp_session_reap(&signal, 1);
        assert_eq!(
            signal.version(),
            initial_version + 1,
            "a closed MP session must immediately schedule one normal supervisor recollection"
        );
    }

    fn route_with_ipv4(
        peer_id: u32,
        ipv4_addr: Option<std::net::Ipv4Addr>,
    ) -> crate::proto::api::instance::Route {
        crate::proto::api::instance::Route {
            peer_id,
            ipv4_addr: ipv4_addr.map(|addr| cidr::Ipv4Inet::new(addr, 24).unwrap().into()),
            ..Default::default()
        }
    }

    #[test]
    fn ipv4_broadcast_peer_selection_skips_peers_without_ipv4() {
        let routes = vec![
            route_with_ipv4(1, Some(std::net::Ipv4Addr::new(10, 126, 126, 1))),
            route_with_ipv4(2, None),
            route_with_ipv4(3, Some(std::net::Ipv4Addr::new(10, 126, 126, 3))),
            route_with_ipv4(4, None),
        ];

        assert_eq!(
            PeerManager::select_ipv4_broadcast_peers(&routes, 3),
            vec![1]
        );
    }

    #[test]
    fn gc_recent_traffic_removes_expired_and_connected_entries() {
        let stale_peer = 1;
        let direct_peer = 2;
        let active_peer = 3;
        let recent_have_traffic = dashmap::DashMap::new();

        recent_have_traffic.insert(
            stale_peer,
            Instant::now() - PeerManager::RECENT_HAVE_TRAFFIC_TTL - Duration::from_millis(1),
        );
        recent_have_traffic.insert(direct_peer, Instant::now());
        recent_have_traffic.insert(active_peer, Instant::now());

        let future_peer = 4;

        recent_have_traffic.insert(future_peer, Instant::now() + Duration::from_secs(1));

        PeerManager::gc_recent_traffic_entries(&recent_have_traffic, Instant::now(), |peer_id| {
            peer_id == direct_peer
        });

        assert!(!recent_have_traffic.contains_key(&stale_peer));
        assert!(!recent_have_traffic.contains_key(&direct_peer));
        assert!(recent_have_traffic.contains_key(&active_peer));
        assert!(recent_have_traffic.contains_key(&future_peer));
    }

    #[tokio::test]
    async fn recent_traffic_skips_direct_peers_and_clears_after_direct_connect() {
        let peer_mgr_a = create_lazy_peer_manager().await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_b_id = peer_mgr_b.my_peer_id();

        peer_mgr_a.mark_recent_traffic(peer_b_id);
        assert!(peer_mgr_a.has_recent_traffic(peer_b_id, Instant::now()));

        let (a_ring, b_ring) = create_ring_tunnel_pair();
        let (client_ret, server_ret) = tokio::join!(
            peer_mgr_a.add_client_tunnel(a_ring, true),
            peer_mgr_b.add_tunnel_as_server(b_ring, true)
        );
        client_ret.unwrap();
        server_ret.unwrap();

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                async move { peer_mgr_a.has_directly_connected_conn(peer_b_id) }
            },
            Duration::from_secs(5),
        )
        .await;

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                async move { !peer_mgr_a.has_recent_traffic(peer_b_id, Instant::now()) }
            },
            Duration::from_secs(5),
        )
        .await;

        peer_mgr_a.mark_recent_traffic(peer_b_id);
        assert!(
            !peer_mgr_a.has_recent_traffic(peer_b_id, Instant::now()),
            "directly connected peers should not be tracked as lazy-p2p demand"
        );
    }

    #[tokio::test]
    async fn recent_traffic_notifies_only_when_demand_becomes_active() {
        let peer_mgr_a = create_lazy_peer_manager().await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_b_id = peer_mgr_b.my_peer_id();
        let signal = peer_mgr_a.p2p_demand_notify();

        let initial_version = signal.version();
        peer_mgr_a.mark_recent_traffic(peer_b_id);
        assert_eq!(signal.version(), initial_version + 1);

        let first_seen = *peer_mgr_a.recent_have_traffic.get(&peer_b_id).unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        peer_mgr_a.mark_recent_traffic(peer_b_id);
        assert_eq!(
            signal.version(),
            initial_version + 1,
            "fresh demand should not wake all p2p workers again"
        );
        let refreshed_seen = *peer_mgr_a.recent_have_traffic.get(&peer_b_id).unwrap();
        assert!(refreshed_seen > first_seen);

        if let Some(mut last_seen) = peer_mgr_a.recent_have_traffic.get_mut(&peer_b_id) {
            *last_seen =
                Instant::now() - PeerManager::RECENT_HAVE_TRAFFIC_TTL - Duration::from_millis(1);
        }
        peer_mgr_a.mark_recent_traffic(peer_b_id);
        assert_eq!(signal.version(), initial_version + 2);
    }

    #[test]
    fn disable_relay_data_classifies_data_plane_packets_only() {
        for packet_type in [
            PacketType::Data,
            PacketType::KcpSrc,
            PacketType::KcpDst,
            PacketType::QuicSrc,
            PacketType::QuicDst,
            PacketType::DataWithKcpSrcModified,
            PacketType::DataWithQuicSrcModified,
            PacketType::ForeignNetworkPacket,
        ] {
            assert!(PeerManager::is_relay_data_packet(packet_type as u8));
        }

        for packet_type in [
            PacketType::RpcReq,
            PacketType::RpcResp,
            PacketType::Ping,
            PacketType::Pong,
            PacketType::HandShake,
            PacketType::NoiseHandshakeMsg1,
            PacketType::NoiseHandshakeMsg2,
            PacketType::NoiseHandshakeMsg3,
            PacketType::RelayHandshake,
            PacketType::RelayHandshakeAck,
        ] {
            assert!(!PeerManager::is_relay_data_packet(packet_type as u8));
        }
    }

    #[test]
    fn disable_relay_data_inspects_foreign_network_inner_packet_type() {
        let network_name = "net1".to_string();

        let mut rpc_packet = ZCPacket::new_with_payload(b"rpc");
        rpc_packet.fill_peer_manager_hdr(1, 2, PacketType::RpcReq as u8);
        let mut foreign_rpc_packet =
            ZCPacket::new_for_foreign_network(&network_name, 2, &rpc_packet);
        foreign_rpc_packet.fill_peer_manager_hdr(10, 20, PacketType::ForeignNetworkPacket as u8);

        assert_eq!(
            foreign_rpc_packet.foreign_network_inner_packet_type(),
            Some(PacketType::RpcReq as u8)
        );
        assert!(!PeerManager::is_relay_data_zc_packet(&foreign_rpc_packet));

        let mut data_packet = ZCPacket::new_with_payload(b"data");
        data_packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        let mut foreign_data_packet =
            ZCPacket::new_for_foreign_network(&network_name, 2, &data_packet);
        foreign_data_packet.fill_peer_manager_hdr(10, 20, PacketType::ForeignNetworkPacket as u8);

        assert_eq!(
            foreign_data_packet.foreign_network_inner_packet_type(),
            Some(PacketType::Data as u8)
        );
        assert!(PeerManager::is_relay_data_zc_packet(&foreign_data_packet));
    }

    #[tokio::test]
    async fn non_whitelisted_network_avoid_relay_survives_disable_relay_data_toggle() {
        let global_ctx = get_mock_global_ctx();
        let mut flags = global_ctx.get_flags();
        flags.disable_relay_data = true;
        flags.relay_network_whitelist = "other-network".to_string();
        global_ctx.set_flags(flags);

        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let _peer_mgr = PeerManager::new(RouteAlgoType::Ospf, global_ctx.clone(), packet_send);

        let mut flags = global_ctx.get_flags();
        flags.disable_relay_data = false;
        global_ctx.set_flags(flags);

        assert!(global_ctx.get_feature_flags().avoid_relay_data);
    }

    #[tokio::test]
    async fn send_msg_internal_does_not_record_tx_metrics_on_failed_delivery() {
        let peer_mgr = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let dst_peer_id = peer_mgr.my_peer_id().wrapping_add(1);
        let network_labels = LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr.get_global_ctx().get_network_name(),
        ));

        let mut pkt = ZCPacket::new_with_payload(b"tx");
        pkt.fill_peer_manager_hdr(peer_mgr.my_peer_id(), dst_peer_id, PacketType::Data as u8);

        let result = PeerManager::send_msg_internal(
            &peer_mgr.peers,
            &peer_mgr.foreign_network_client,
            &peer_mgr.relay_peer_map,
            Some(&peer_mgr.traffic_metrics),
            pkt,
            dst_peer_id,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(
            peer_mgr
                .get_global_ctx()
                .stats_manager()
                .get_metric(MetricName::TrafficBytesTx, &network_labels)
                .unwrap()
                .value,
            0
        );
        assert_eq!(
            peer_mgr
                .get_global_ctx()
                .stats_manager()
                .get_metric(MetricName::TrafficPacketsTx, &network_labels)
                .unwrap()
                .value,
            0
        );
        assert!(
            peer_mgr
                .get_global_ctx()
                .stats_manager()
                .get_metric(
                    MetricName::TrafficBytesTxByInstance,
                    &network_labels
                        .clone()
                        .with_label_type(LabelType::ToInstanceId("unknown".to_string())),
                )
                .is_none()
        );
        assert!(
            peer_mgr
                .get_global_ctx()
                .stats_manager()
                .get_metric(
                    MetricName::TrafficPacketsTxByInstance,
                    &network_labels.with_label_type(LabelType::ToInstanceId("unknown".to_string())),
                )
                .is_none()
        );
    }

    #[tokio::test]
    async fn send_msg_internal_does_not_record_tx_metrics_for_self_loop() {
        let (s, _r) = create_packet_recv_chan();
        let peer_mgr = Arc::new(PeerManager::new(
            RouteAlgoType::None,
            get_mock_global_ctx(),
            s,
        ));
        let dst_peer_id = peer_mgr.my_peer_id();
        let network_labels = LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr.get_global_ctx().get_network_name(),
        ));

        let mut pkt = ZCPacket::new_with_payload(b"tx");
        pkt.fill_peer_manager_hdr(peer_mgr.my_peer_id(), dst_peer_id, PacketType::Data as u8);

        PeerManager::send_msg_internal(
            &peer_mgr.peers,
            &peer_mgr.foreign_network_client,
            &peer_mgr.relay_peer_map,
            Some(&peer_mgr.traffic_metrics),
            pkt,
            dst_peer_id,
        )
        .await
        .unwrap();

        assert_eq!(
            metric_value(&peer_mgr, MetricName::TrafficBytesTx, &network_labels),
            0
        );
        assert_eq!(
            metric_value(&peer_mgr, MetricName::TrafficPacketsTx, &network_labels),
            0
        );
        assert_eq!(
            metric_value(
                &peer_mgr,
                MetricName::TrafficControlBytesTx,
                &network_labels
            ),
            0
        );
        assert_eq!(
            metric_value(
                &peer_mgr,
                MetricName::TrafficControlPacketsTx,
                &network_labels
            ),
            0
        );
        assert!(
            peer_mgr
                .get_global_ctx()
                .stats_manager()
                .get_metric(
                    MetricName::TrafficBytesTxByInstance,
                    &network_labels
                        .clone()
                        .with_label_type(LabelType::ToInstanceId("unknown".to_string())),
                )
                .is_none()
        );
        assert!(
            peer_mgr
                .get_global_ctx()
                .stats_manager()
                .get_metric(
                    MetricName::TrafficControlBytesTxByInstance,
                    &network_labels.with_label_type(LabelType::ToInstanceId("unknown".to_string())),
                )
                .is_none()
        );
    }

    #[tokio::test]
    async fn send_msg_internal_records_data_metrics_for_direct_peer() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        let a_network_labels = LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr_a.get_global_ctx().get_network_name(),
        ));
        let b_network_labels = LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr_b.get_global_ctx().get_network_name(),
        ));

        let a_data_tx_before =
            metric_value(&peer_mgr_a, MetricName::TrafficBytesTx, &a_network_labels);
        let b_data_rx_before =
            metric_value(&peer_mgr_b, MetricName::TrafficBytesRx, &b_network_labels);
        let mut pkt = ZCPacket::new_with_payload(b"data");
        pkt.fill_peer_manager_hdr(
            peer_mgr_a.my_peer_id(),
            peer_mgr_b.my_peer_id(),
            PacketType::Data as u8,
        );
        let pkt_len = pkt.buf_len() as u64;

        PeerManager::send_msg_internal(
            &peer_mgr_a.peers,
            &peer_mgr_a.foreign_network_client,
            &peer_mgr_a.relay_peer_map,
            Some(&peer_mgr_a.traffic_metrics),
            pkt,
            peer_mgr_b.my_peer_id(),
        )
        .await
        .unwrap();

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                let peer_mgr_b = peer_mgr_b.clone();
                let a_network_labels = a_network_labels.clone();
                let b_network_labels = b_network_labels.clone();
                async move {
                    metric_value(&peer_mgr_a, MetricName::TrafficBytesTx, &a_network_labels)
                        >= a_data_tx_before + pkt_len
                        && metric_value(&peer_mgr_b, MetricName::TrafficBytesRx, &b_network_labels)
                            >= b_data_rx_before + pkt_len
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn send_msg_internal_records_control_metrics_for_direct_peer() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        let a_network_labels = LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr_a.get_global_ctx().get_network_name(),
        ));
        let b_network_labels = LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr_b.get_global_ctx().get_network_name(),
        ));

        let a_control_tx_before = metric_value(
            &peer_mgr_a,
            MetricName::TrafficControlBytesTx,
            &a_network_labels,
        );
        let b_control_rx_before = metric_value(
            &peer_mgr_b,
            MetricName::TrafficControlBytesRx,
            &b_network_labels,
        );
        let a_data_tx_before =
            metric_value(&peer_mgr_a, MetricName::TrafficBytesTx, &a_network_labels);
        let b_data_rx_before =
            metric_value(&peer_mgr_b, MetricName::TrafficBytesRx, &b_network_labels);

        let mut pkt = ZCPacket::new_with_payload(b"ctrl");
        pkt.fill_peer_manager_hdr(
            peer_mgr_a.my_peer_id(),
            peer_mgr_b.my_peer_id(),
            PacketType::RpcReq as u8,
        );
        let pkt_len = pkt.buf_len() as u64;

        PeerManager::send_msg_internal(
            &peer_mgr_a.peers,
            &peer_mgr_a.foreign_network_client,
            &peer_mgr_a.relay_peer_map,
            Some(&peer_mgr_a.traffic_metrics),
            pkt,
            peer_mgr_b.my_peer_id(),
        )
        .await
        .unwrap();

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                let peer_mgr_b = peer_mgr_b.clone();
                let a_network_labels = a_network_labels.clone();
                let b_network_labels = b_network_labels.clone();
                async move {
                    metric_value(
                        &peer_mgr_a,
                        MetricName::TrafficControlBytesTx,
                        &a_network_labels,
                    ) >= a_control_tx_before + pkt_len
                        && metric_value(
                            &peer_mgr_b,
                            MetricName::TrafficControlBytesRx,
                            &b_network_labels,
                        ) >= b_control_rx_before + pkt_len
                }
            },
            Duration::from_secs(5),
        )
        .await;

        assert_eq!(
            metric_value(&peer_mgr_a, MetricName::TrafficBytesTx, &a_network_labels),
            a_data_tx_before
        );
        assert_eq!(
            metric_value(&peer_mgr_b, MetricName::TrafficBytesRx, &b_network_labels),
            b_data_rx_before
        );
    }

    #[tokio::test]
    async fn send_msg_internal_records_data_forwarded_metrics_for_transit_peer() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let b_network_labels = network_labels(&peer_mgr_b);
        let forwarded_bytes_before = metric_value(
            &peer_mgr_b,
            MetricName::TrafficBytesForwarded,
            &b_network_labels,
        );
        let forwarded_packets_before = metric_value(
            &peer_mgr_b,
            MetricName::TrafficPacketsForwarded,
            &b_network_labels,
        );

        let mut pkt = ZCPacket::new_with_payload(b"forward-data");
        pkt.fill_peer_manager_hdr(
            peer_mgr_a.my_peer_id(),
            peer_mgr_c.my_peer_id(),
            PacketType::Data as u8,
        );
        let pkt_len = pkt.buf_len() as u64;

        PeerManager::send_msg_internal(
            &peer_mgr_a.peers,
            &peer_mgr_a.foreign_network_client,
            &peer_mgr_a.relay_peer_map,
            Some(&peer_mgr_a.traffic_metrics),
            pkt,
            peer_mgr_c.my_peer_id(),
        )
        .await
        .unwrap();

        wait_for_condition(
            || {
                let peer_mgr_b = peer_mgr_b.clone();
                let b_network_labels = b_network_labels.clone();
                async move {
                    metric_value(
                        &peer_mgr_b,
                        MetricName::TrafficBytesForwarded,
                        &b_network_labels,
                    ) >= forwarded_bytes_before + pkt_len
                        && metric_value(
                            &peer_mgr_b,
                            MetricName::TrafficPacketsForwarded,
                            &b_network_labels,
                        ) > forwarded_packets_before
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn send_msg_internal_records_control_forwarded_metrics_for_transit_peer() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let b_network_labels = network_labels(&peer_mgr_b);
        let forwarded_bytes_before = metric_value(
            &peer_mgr_b,
            MetricName::TrafficControlBytesForwarded,
            &b_network_labels,
        );
        let forwarded_packets_before = metric_value(
            &peer_mgr_b,
            MetricName::TrafficControlPacketsForwarded,
            &b_network_labels,
        );

        let mut pkt = ZCPacket::new_with_payload(b"forward-control");
        pkt.fill_peer_manager_hdr(
            peer_mgr_a.my_peer_id(),
            peer_mgr_c.my_peer_id(),
            PacketType::RpcReq as u8,
        );
        let pkt_len = pkt.buf_len() as u64;

        PeerManager::send_msg_internal(
            &peer_mgr_a.peers,
            &peer_mgr_a.foreign_network_client,
            &peer_mgr_a.relay_peer_map,
            Some(&peer_mgr_a.traffic_metrics),
            pkt,
            peer_mgr_c.my_peer_id(),
        )
        .await
        .unwrap();

        wait_for_condition(
            || {
                let peer_mgr_b = peer_mgr_b.clone();
                let b_network_labels = b_network_labels.clone();
                async move {
                    metric_value(
                        &peer_mgr_b,
                        MetricName::TrafficControlBytesForwarded,
                        &b_network_labels,
                    ) >= forwarded_bytes_before + pkt_len
                        && metric_value(
                            &peer_mgr_b,
                            MetricName::TrafficControlPacketsForwarded,
                            &b_network_labels,
                        ) > forwarded_packets_before
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn recent_traffic_tolerates_future_timestamps() {
        let peer_mgr_a = create_lazy_peer_manager().await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_b_id = peer_mgr_b.my_peer_id();

        peer_mgr_a
            .recent_have_traffic
            .insert(peer_b_id, Instant::now() + Duration::from_secs(1));

        assert!(peer_mgr_a.has_recent_traffic(peer_b_id, Instant::now()));
        peer_mgr_a.mark_recent_traffic(peer_b_id);
    }

    #[tokio::test]
    async fn drop_peer_manager() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_c.clone()).await;

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        // wait mgr_a have 2 peers
        wait_for_condition(
            || async { peer_mgr_a.get_peer_map().list_peers_with_conn().await.len() == 2 },
            std::time::Duration::from_secs(5),
        )
        .await;

        drop(peer_mgr_b);

        wait_for_condition(
            || async { peer_mgr_a.get_peer_map().list_peers_with_conn().await.len() == 1 },
            std::time::Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn peer_manager_safe_mode_connect_between_peers() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        peer_mgr_a
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        peer_mgr_b
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));

        set_secure_mode_cfg(&peer_mgr_a.get_global_ctx(), true);
        set_secure_mode_cfg(&peer_mgr_b.get_global_ctx(), true);

        let (a_ring, b_ring) = create_ring_tunnel_pair();
        let (a_ret, b_ret) = tokio::join!(
            peer_mgr_a.add_client_tunnel(a_ring, false),
            peer_mgr_b.add_tunnel_as_server(b_ring, true)
        );
        let (peer_b_id, _) = a_ret.unwrap();
        b_ret.unwrap();

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                async move {
                    if !peer_mgr_a
                        .get_peer_map()
                        .list_peers_with_conn()
                        .await
                        .contains(&peer_b_id)
                    {
                        return false;
                    }
                    let Some(conns) = peer_mgr_a.get_peer_map().list_peer_conns(peer_b_id).await
                    else {
                        return false;
                    };
                    conns.iter().any(|c| {
                        c.noise_local_static_pubkey.len() == 32
                            && c.noise_remote_static_pubkey.len() == 32
                            && c.secure_auth_level == SecureAuthLevel::NetworkSecretConfirmed as i32
                    })
                }
            },
            Duration::from_secs(10),
        )
        .await;

        let peer_a_id = peer_mgr_a.my_peer_id();
        wait_for_condition(
            || {
                let peer_mgr_b = peer_mgr_b.clone();
                async move {
                    if !peer_mgr_b
                        .get_peer_map()
                        .list_peers_with_conn()
                        .await
                        .contains(&peer_a_id)
                    {
                        return false;
                    }
                    let Some(conns) = peer_mgr_b.get_peer_map().list_peer_conns(peer_a_id).await
                    else {
                        return false;
                    };
                    conns.iter().any(|c| {
                        c.noise_local_static_pubkey.len() == 32
                            && c.noise_remote_static_pubkey.len() == 32
                            && c.secure_auth_level == SecureAuthLevel::NetworkSecretConfirmed as i32
                    })
                }
            },
            Duration::from_secs(10),
        )
        .await;
    }

    #[tokio::test]
    async fn peer_manager_same_network_secure_mode_mismatch_rejected() {
        let peer_mgr_client = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_server = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        peer_mgr_client
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        peer_mgr_server
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));

        set_secure_mode_cfg(&peer_mgr_server.get_global_ctx(), true);

        let (c_ring, s_ring) = create_ring_tunnel_pair();
        let (c_ret, s_ret) = tokio::join!(
            peer_mgr_client.add_client_tunnel(c_ring, false),
            peer_mgr_server.add_tunnel_as_server(s_ring, true)
        );
        let _ = c_ret;
        assert!(
            s_ret.is_err(),
            "same-network peer with mismatched secure mode should be rejected"
        );

        wait_for_condition(
            || {
                let peer_mgr_server = peer_mgr_server.clone();
                async move {
                    peer_mgr_server
                        .get_peer_map()
                        .list_peers_with_conn()
                        .await
                        .is_empty()
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn credential_node_rejects_legacy_client() {
        let peer_mgr_client = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_server = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        peer_mgr_client
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        peer_mgr_server
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new_credential("net1".to_string()));

        set_secure_mode_cfg(&peer_mgr_server.get_global_ctx(), true);

        let (c_ring, s_ring) = create_ring_tunnel_pair();
        let (c_ret, s_ret) = tokio::join!(
            peer_mgr_client.add_client_tunnel(c_ring, false),
            peer_mgr_server.add_tunnel_as_server(s_ring, true)
        );

        let _ = c_ret;
        assert!(
            s_ret.is_err(),
            "credential server should reject legacy client"
        );

        wait_for_condition(
            || {
                let peer_mgr_server = peer_mgr_server.clone();
                async move {
                    peer_mgr_server
                        .get_peer_map()
                        .list_peers_with_conn()
                        .await
                        .is_empty()
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn peer_manager_safe_mode_shared_node_pinning_connect() {
        let peer_mgr_client = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_server = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        peer_mgr_client
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new("user".to_string(), "sec1".to_string()));
        peer_mgr_server
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity {
                network_name: "shared".to_string(),
                network_secret: None,
                network_secret_digest: None,
            });

        set_secure_mode_cfg(&peer_mgr_client.get_global_ctx(), true);
        set_secure_mode_cfg(&peer_mgr_server.get_global_ctx(), true);

        let server_pub_b64 = peer_mgr_server
            .get_global_ctx()
            .config
            .get_secure_mode()
            .unwrap()
            .local_public_key
            .unwrap();

        let (a_ring, b_ring) = create_ring_tunnel_pair();
        let server_remote_url: url::Url = a_ring
            .info()
            .unwrap()
            .remote_addr
            .unwrap()
            .url
            .parse()
            .unwrap();
        peer_mgr_client.get_global_ctx().config.set_peers(vec![
            crate::common::config::PeerConfig {
                uri: server_remote_url,
                peer_public_key: Some(server_pub_b64.clone()),
            },
        ]);

        let (c_ret, s_ret) = tokio::join!(
            peer_mgr_client.add_client_tunnel(a_ring, false),
            peer_mgr_server.add_tunnel_as_server(b_ring, true)
        );
        c_ret.unwrap();
        s_ret.unwrap();

        wait_for_condition(
            || {
                let peer_mgr_client = peer_mgr_client.clone();
                async move {
                    let foreign_peer_map =
                        peer_mgr_client.get_foreign_network_client().get_peer_map();
                    if foreign_peer_map.list_peers_with_conn().await.len() != 1 {
                        return false;
                    }
                    let Some(peer_id) = foreign_peer_map
                        .list_peers_with_conn()
                        .await
                        .into_iter()
                        .next()
                    else {
                        return false;
                    };
                    let Some(conns) = foreign_peer_map.list_peer_conns(peer_id).await else {
                        return false;
                    };
                    conns.iter().any(|c| {
                        c.secure_auth_level == SecureAuthLevel::PeerVerified as i32
                            && c.noise_local_static_pubkey.len() == 32
                            && c.noise_remote_static_pubkey.len() == 32
                    })
                }
            },
            Duration::from_secs(10),
        )
        .await;

        wait_for_condition(
            || {
                let peer_mgr_server = peer_mgr_server.clone();
                async move {
                    let foreigns = peer_mgr_server
                        .get_foreign_network_manager()
                        .list_foreign_networks()
                        .await;
                    let Some(entry) = foreigns.foreign_networks.get("user") else {
                        return false;
                    };
                    entry.peers.iter().any(|p| {
                        p.conns
                            .iter()
                            .any(|c| c.noise_local_static_pubkey.len() == 32)
                    })
                }
            },
            Duration::from_secs(10),
        )
        .await;
    }

    #[cfg(feature = "mpquic")]
    #[test]
    fn relay_next_hop_candidate_merge_keeps_live_public_peer() {
        assert_eq!(
            PeerManager::merge_relay_next_hop_candidates(7, vec![2, 7, 5], vec![5, 9, 7]),
            vec![2, 5, 9],
            "a live public/foreign peer must remain a relay first-hop candidate"
        );
    }

    /// MP weak-network plan R2/E2, the phone's first hops: 2080ti (38 and 45
    /// ms) and JDCloud (63 ms) answered nothing (loss 1.0) but kept their last
    /// latency; tencent and sniffer never had a ping answered recorded (latency
    /// 0) and lose 28-36%.
    #[cfg(feature = "mpquic")]
    #[test]
    fn relay_first_hops_are_ranked_by_health_before_latency() {
        use crate::connector::mp_path::FirstHopQuality;
        let q = |conns: &[(u64, f64)]| FirstHopQuality::best_of(conns);
        let (ms_2080ti, jdcloud, tencent, sniffer) = (1, 2, 3, 4);
        let hops = [
            (ms_2080ti, q(&[(45_769, 1.0), (38_356, 1.0)])),
            (jdcloud, q(&[(63_228, 1.0)])),
            (tencent, q(&[(0, 0.28), (0, 0.36)])),
            (sniffer, q(&[(0, 0.34)])),
        ];
        // Reachable (if lossy) hops first, by latency (both unmeasured: by id);
        // then the unreachable ones by latency.
        assert_eq!(
            PeerManager::rank_relay_first_hops(&hops),
            vec![tencent, sniffer, ms_2080ti, jdcloud]
        );

        // Clean beats lossy whatever the latency; unmeasured is not the fastest.
        let hops = [
            (1, q(&[(10_000, 0.5)])),
            (2, q(&[(0, 0.0)])),
            (3, q(&[(200_000, 0.0)])),
            (4, q(&[(20_000, 0.05)])),
            (5, None),
        ];
        assert_eq!(PeerManager::rank_relay_first_hops(&hops), vec![4, 3, 2, 1, 5]);

        // Everything unreachable: still a result, by latency.
        let hops = [(1, q(&[(63_000, 1.0)])), (2, q(&[(38_000, 1.0)]))];
        assert_eq!(PeerManager::rank_relay_first_hops(&hops), vec![2, 1]);

        // A first hop takes its best connection: the answering one.
        let hops = [(1, q(&[(10_000, 1.0), (90_000, 0.0)])), (2, q(&[(50_000, 0.0)]))];
        assert_eq!(PeerManager::rank_relay_first_hops(&hops), vec![2, 1]);
        assert!(FirstHopQuality::best_of(&[]).is_none());
    }

    #[cfg(feature = "mpquic")]
    #[tokio::test]
    async fn relay_mp_peer_conn_delivers_ipv4_tcp_syn_to_destination_nic_channel() {
        let (peer_mgr_a, _a_nic_rx) = create_relay_mp_peer_manager("10.77.17.1/24").await;
        let (peer_mgr_b, mut b_nic_rx) = create_relay_mp_peer_manager("10.77.17.2/24").await;
        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        // Only A<->C and C<->B are physical EasyTier peer connections.  The
        // A<->B PeerConn created below must therefore use the relay-next-hop
        // TQUIC tunnel, while C forwards the opaque relay datagrams normally.
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_c.clone()).await;
        connect_peer_manager(peer_mgr_c.clone(), peer_mgr_b.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        let identity = RelayPathIdentity::from_origin(
            peer_mgr_a.my_peer_id,
            peer_mgr_b.my_peer_id,
            peer_mgr_c.my_peer_id,
            1,
        );
        let path = relay_path_spec(
            identity,
            peer_mgr_a.mp_relay_transport.open_source_path(identity),
            peer_mgr_c.my_peer_id,
            None,
        );
        let remote_url =
            crate::tunnel::build_url_from_socket_addr(&identity.remote_addr.to_string(), "mpquic");
        let offer = peer_mgr_a
            .mp_session_manager
            .offer_path_spec(
                peer_mgr_b.my_peer_id,
                false,
                path,
                remote_url,
                "mpquic_relay_next_hop",
            )
            .await
            .unwrap();
        let OfferPathResult::NewTunnel(tunnel) = offer else {
            panic!("the first relay-next-hop carrier must create an EasyTier tunnel");
        };

        let a_for_attach = peer_mgr_a.clone();
        let b_peer_id = peer_mgr_b.my_peer_id;
        let attach_client = tokio::spawn(async move {
            a_for_attach
                .add_client_tunnel_with_peer_id_hint(tunnel, false, Some(b_peer_id))
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), attach_client)
            .await
            .expect("relay MP client tunnel handshake timed out")
            .expect("relay MP client tunnel task panicked")
            .expect("relay MP client tunnel handshake failed");

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                let peer_mgr_b = peer_mgr_b.clone();
                async move {
                    peer_mgr_a.get_peer_map().has_peer(peer_mgr_b.my_peer_id)
                        && peer_mgr_b.get_peer_map().has_peer(peer_mgr_a.my_peer_id)
                }
            },
            Duration::from_secs(5),
        )
        .await;

        let source = Ipv4Addr::new(10, 77, 17, 1);
        let destination = Ipv4Addr::new(10, 77, 17, 2);
        let syn = ipv4_tcp_syn(source, destination);
        peer_mgr_a
            .send_msg_by_ip(
                ZCPacket::new_with_payload(&syn),
                IpAddr::V4(destination),
                false,
            )
            .await
            .unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), b_nic_rx.recv())
            .await
            .expect("relay MP TCP SYN did not reach the destination nic channel")
            .expect("destination nic channel closed before receiving the TCP SYN");
        assert_eq!(
            received.peer_manager_header().unwrap().packet_type,
            PacketType::Data as u8
        );
        assert_eq!(received.payload(), syn.as_slice());

        // The carrier rides C. Announced as an A-B link, it would become the
        // next hop of the forwarding that carries it, so C's datagrams for B
        // could be routed back into it (the 2026-10-05 outage).
        assert!(
            !peer_mgr_a
                .get_peer_map()
                .list_peers_with_link_conn()
                .await
                .contains(&b_peer_id)
        );
        tokio::time::sleep(Duration::from_secs(3)).await;
        let route_to_b = peer_mgr_a
            .list_routes()
            .await
            .into_iter()
            .find(|route| route.peer_id == b_peer_id)
            .expect("A keeps a route to B");
        assert_eq!(route_to_b.next_hop_peer_id, peer_mgr_c.my_peer_id);
    }

    /// MP_WORKLIST row 95 (vivo, 2026-11-05): a relay MP session whose client
    /// is a phone on cellular: its first-hop links lose packets, stall
    /// without closing, and get replaced by new connections. In the incident
    /// the server's datagrams were lost for six minutes while the client's
    /// kept arriving. Here the production controller runs (reconcile and
    /// control ticks at the default interval) while A's links to both first
    /// hops stall in turn; both directions must keep delivering.
    #[cfg(feature = "mpquic")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn relay_mp_session_keeps_both_directions_through_first_hop_flaps() {
        use std::time::Instant;
        async fn ticking(ipv4: &str) -> (Arc<PeerManager>, crate::peers::PacketRecvChanReceiver) {
            create_relay_mp_peer_manager_ticking_every(
                ipv4,
                gen_default_mp_config().control_interval_ms,
            )
            .await
        }
        async fn is_mp_relay_peer(from: &Arc<PeerManager>, to: PeerId) -> bool {
            from.get_peer_map()
                .list_peer_conns(to)
                .await
                .unwrap_or_default()
                .iter()
                .any(|conn| {
                    conn.tunnel
                        .as_ref()
                        .is_some_and(|tunnel| tunnel.tunnel_type == "mpquic_relay_next_hop")
                })
        }
        /// Sends a SYN every 100 ms; the receiver records when each one lands.
        fn pump(
            from: Arc<PeerManager>,
            source: Ipv4Addr,
            destination: Ipv4Addr,
        ) -> tokio::task::JoinHandle<()> {
            tokio::spawn(async move {
                let syn = ipv4_tcp_syn(source, destination);
                loop {
                    let _ = from
                        .send_msg_by_ip(
                            ZCPacket::new_with_payload(&syn),
                            IpAddr::V4(destination),
                            false,
                        )
                        .await;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
        }
        fn arrivals(
            mut nic_rx: crate::peers::PacketRecvChanReceiver,
        ) -> Arc<std::sync::Mutex<Vec<Instant>>> {
            let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
            let sink = seen.clone();
            tokio::spawn(async move {
                while nic_rx.recv().await.is_some() {
                    sink.lock().unwrap().push(Instant::now());
                }
            });
            seen
        }
        fn longest_gap(seen: &[Instant], from: Instant, to: Instant) -> Duration {
            let mut edges = vec![from];
            edges.extend(seen.iter().copied().filter(|t| *t >= from && *t <= to));
            edges.push(to);
            edges
                .windows(2)
                .map(|w| w[1].saturating_duration_since(w[0]))
                .max()
                .unwrap_or_default()
        }

        /// The phone's end of a cellular first-hop link: some loss, and
        /// stalls that drop everything both ways without closing anything.
        /// The loss spares the first packets, the ET handshake: a real
        /// tunnel retransmits it, while a lost one here would leave the new
        /// connection dead and the test about something else.
        struct CellularLink {
            stalled: std::sync::atomic::AtomicBool,
            loss_per_mille: u32,
            packets: std::sync::atomic::AtomicU32,
        }
        impl CellularLink {
            fn passes(&self) -> bool {
                use std::sync::atomic::Ordering::Relaxed;
                let handshake = self.packets.fetch_add(1, Relaxed) < 4;
                !self.stalled.load(Relaxed)
                    && (handshake || rand::random::<u32>() % 1000 >= self.loss_per_mille)
            }
        }
        impl crate::tunnel::filter::TunnelFilter for CellularLink {
            type FilterOutput = ();
            fn before_send(&self, data: crate::tunnel::SinkItem) -> Option<crate::tunnel::SinkItem> {
                self.passes().then_some(data)
            }
            fn after_received(
                &self,
                data: crate::tunnel::StreamItem,
            ) -> Option<crate::tunnel::StreamItem> {
                self.passes().then_some(data)
            }
            fn filter_output(&self) {}
        }
        fn connect_cellular(phone: Arc<PeerManager>, hop: Arc<PeerManager>) -> Arc<CellularLink> {
            let link = Arc::new(CellularLink {
                stalled: false.into(),
                loss_per_mille: 50,
                packets: 0.into(),
            });
            let (phone_end, hop_end) = create_ring_tunnel_pair();
            let phone_end = Box::new(TunnelWithFilter::new(phone_end, link.clone()));
            tokio::spawn(async move {
                let _ = phone.add_client_tunnel(phone_end, false).await;
            });
            tokio::spawn(async move {
                let _ = hop.add_tunnel_as_server(hop_end, true).await;
            });
            link
        }

        let (peer_mgr_a, a_nic_rx) = ticking("10.77.18.1/24").await;
        let (peer_mgr_b, b_nic_rx) = ticking("10.77.18.2/24").await;
        let c1 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let c2 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let mut links = Vec::new();
        for hop in [&c1, &c2] {
            links.push(connect_cellular(peer_mgr_a.clone(), hop.clone()));
            connect_peer_manager(hop.clone(), peer_mgr_b.clone()).await;
        }
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();
        let (a_id, b_id) = (peer_mgr_a.my_peer_id, peer_mgr_b.my_peer_id);
        wait_for_condition(
            || {
                let (a, b) = (peer_mgr_a.clone(), peer_mgr_b.clone());
                async move { is_mp_relay_peer(&a, b_id).await && is_mp_relay_peer(&b, a_id).await }
            },
            Duration::from_secs(20),
        )
        .await;

        let (a_ip, b_ip) = (Ipv4Addr::new(10, 77, 18, 1), Ipv4Addr::new(10, 77, 18, 2));
        let at_b = arrivals(b_nic_rx);
        let at_a = arrivals(a_nic_rx);
        let pumps = [
            pump(peer_mgr_a.clone(), a_ip, b_ip),
            pump(peer_mgr_b.clone(), b_ip, a_ip),
        ];
        tokio::time::sleep(Duration::from_secs(3)).await;
        let start = Instant::now();
        // Timeline for diagnosis: every MP path of both ends, once a second.
        let timeline = {
            let (a, b) = (peer_mgr_a.clone(), peer_mgr_b.clone());
            let names = [(c1.my_peer_id, "c1"), (c2.my_peer_id, "c2")];
            tokio::spawn(async move {
                let name = |id: PeerId| {
                    names
                        .iter()
                        .find(|(peer, _)| *peer == id)
                        .map_or("?", |(_, name)| *name)
                };
                loop {
                    for (end, mgr) in [("A", &a), ("B", &b)] {
                        let mut line = format!("{:>5.1}s {end}:", start.elapsed().as_secs_f64());
                        for peer in mgr.mp_session_manager.runtime_snapshots().await.unwrap_or_default() {
                            for path in peer.paths {
                                let relay = path.relay_metadata.map_or(String::new(), |m| {
                                    format!(
                                        "{}/eg {} g{}",
                                        name(m.first_hop_peer_id),
                                        name(m.egress_first_hop_peer_id),
                                        m.route_generation
                                    )
                                });
                                let t = path.telemetry.as_ref();
                                line += &format!(
                                    " [{relay} {:?} off={} tx={} rx={}]",
                                    path.state,
                                    t.is_some_and(|t| t.backed_off),
                                    t.map_or(0, |t| t.sent_bytes),
                                    t.map_or(0, |t| t.recv_bytes),
                                );
                            }
                        }
                        println!("{line}");
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            })
        };
        let mark = |what: &str| println!("{:>5.1}s ==== {what}", start.elapsed().as_secs_f64());

        // The phone's side, one first hop at a time: its link stalls; 2 s
        // later the phone opens a new connection to that hop beside it; the
        // stalled one comes back after 20 s (a cellular stall that recovers),
        // unless ET closed it first.
        for round in 0..4 {
            let (index, hop) = if round % 2 == 0 { (0, &c1) } else { (1, &c2) };
            let stalled = links[index].clone();
            let hop_name = if index == 0 { "c1" } else { "c2" };
            mark(&format!("stall A-{hop_name}"));
            stalled.stalled.store(true, std::sync::atomic::Ordering::Relaxed);
            tokio::time::sleep(Duration::from_secs(2)).await;
            mark(&format!("new link A-{hop_name}"));
            links[index] = connect_cellular(peer_mgr_a.clone(), hop.clone());
            tokio::time::sleep(Duration::from_secs(18)).await;
            mark(&format!("old A-{hop_name} link recovers"));
            stalled.stalled.store(false, std::sync::atomic::Ordering::Relaxed);
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        tokio::time::sleep(Duration::from_secs(20)).await;
        let end = Instant::now();
        for pump in pumps {
            pump.abort();
        }
        timeline.abort();
        for (direction, seen) in [("A->B", &at_b), ("B->A", &at_a)] {
            let seen = seen.lock().unwrap();
            let mut prev = start;
            for t in seen.iter().copied().filter(|t| *t >= start).chain([end]) {
                if t.saturating_duration_since(prev) > Duration::from_secs(2) {
                    println!(
                        "GAP {direction} {:.1}s..{:.1}s",
                        prev.duration_since(start).as_secs_f64(),
                        t.duration_since(start).as_secs_f64()
                    );
                }
                prev = t;
            }
        }

        let to_b = longest_gap(&at_b.lock().unwrap(), start, end);
        let to_a = longest_gap(&at_a.lock().unwrap(), start, end);
        println!(
            "client A={a_id} server-or-client B={b_id}: longest gap A->B {to_b:?} ({} arrivals), B->A {to_a:?} ({} arrivals)",
            at_b.lock().unwrap().len(),
            at_a.lock().unwrap().len()
        );
        assert!(
            to_b < Duration::from_secs(10) && to_a < Duration::from_secs(10),
            "a relay MP direction went silent: A->B {to_b:?}, B->A {to_a:?}"
        );
    }

    #[cfg(feature = "mpquic")]
    #[test]
    fn relay_seed_destinations_include_reachable_non_direct_route() {
        assert_eq!(
            PeerManager::relay_seed_destinations(
                7,
                vec![],
                vec![(3, 9, true), (9, 9, true), (42, 9, true), (100, 101, true)],
                &[9],
            ),
            vec![42],
            "only the lower peer id may seed a routed destination behind a live first hop"
        );
    }

    /// With a session, its client offers the relay paths whatever the peer ids: a
    /// path the server adds would wait forever for the client to validate it.
    #[cfg(feature = "mpquic")]
    #[test]
    fn relay_seed_destinations_follow_the_session_client() {
        assert_eq!(
            PeerManager::relay_seed_destinations(
                7,
                vec![(3, false), (42, true)],
                vec![(3, 9, true), (42, 9, true), (43, 9, true)],
                &[9],
            ),
            vec![3, 43],
            "the client of an existing session offers (3), its server does not (42)"
        );
    }

    /// A peer that does not advertise MP (an official build) never answers a
    /// relay carrier: it is not seeded, unless an MP session with it exists.
    #[cfg(feature = "mpquic")]
    #[test]
    fn relay_seed_destinations_skip_peers_that_do_not_advertise_mp() {
        assert_eq!(
            PeerManager::relay_seed_destinations(
                7,
                vec![(44, false)],
                vec![(42, 9, false), (43, 9, true), (44, 9, false)],
                &[9]
            ),
            vec![43, 44]
        );
    }

    #[cfg(feature = "mpquic")]
    #[test]
    fn relay_offer_backoff_doubles_from_ten_seconds_up_to_its_cap() {
        let secs = (1..=8)
            .map(|offers| PeerManager::relay_offer_backoff(offers).as_secs())
            .collect::<Vec<_>>();
        assert_eq!(secs, vec![10, 20, 40, 60, 60, 60, 60, 60]);
    }

    async fn connect_peer_manager_with<C: TunnelConnector + Debug + 'static, L: TunnelListener>(
        client_mgr: Arc<PeerManager>,
        server_mgr: &Arc<PeerManager>,
        mut client: C,
        server: &mut L,
    ) {
        server.listen().await.unwrap();

        tokio::spawn(async move {
            client.set_bind_addrs(vec![]);
            client_mgr.try_direct_connect(client).await.unwrap();
        });

        server_mgr
            .add_client_tunnel(server.accept().await.unwrap(), false)
            .await
            .unwrap();
    }

    #[rstest::rstest]
    #[tokio::test]
    #[serial_test::serial(forward_packet_test)]
    async fn forward_packet(
        #[values("tcp", "udp", "wg", "quic")] proto1: &str,
        #[values("tcp", "udp", "wg", "quic")] proto2: &str,
    ) {
        use crate::proto::{
            rpc_impl::RpcController,
            tests::{GreetingClientFactory, SayHelloRequest},
        };

        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        register_service(&peer_mgr_a.peer_rpc_mgr, "", 0, "hello a");

        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        register_service(&peer_mgr_c.peer_rpc_mgr, "", 0, "hello c");

        let mut listener1 = create_listener_by_url(
            &format!("{}://0.0.0.0:31013", proto1).parse().unwrap(),
            peer_mgr_b.get_global_ctx(),
        )
        .unwrap();
        let connector1 = create_connector_by_url(
            format!("{}://127.0.0.1:31013", proto1).as_str(),
            &peer_mgr_a.get_global_ctx(),
            crate::tunnel::IpVersion::Both,
        )
        .await
        .unwrap();
        connect_peer_manager_with(peer_mgr_a.clone(), &peer_mgr_b, connector1, &mut listener1)
            .await;

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        let mut listener2 = create_listener_by_url(
            &format!("{}://0.0.0.0:31014", proto2).parse().unwrap(),
            peer_mgr_c.get_global_ctx(),
        )
        .unwrap();
        let connector2 = create_connector_by_url(
            format!("{}://127.0.0.1:31014", proto2).as_str(),
            &peer_mgr_b.get_global_ctx(),
            crate::tunnel::IpVersion::Both,
        )
        .await
        .unwrap();
        connect_peer_manager_with(peer_mgr_b.clone(), &peer_mgr_c, connector2, &mut listener2)
            .await;

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let stub = peer_mgr_a
            .peer_rpc_mgr
            .rpc_client()
            .scoped_client::<GreetingClientFactory<RpcController>>(
                peer_mgr_a.my_peer_id,
                peer_mgr_c.my_peer_id,
                "".to_string(),
            );

        let ret = stub
            .say_hello(
                RpcController::default(),
                SayHelloRequest {
                    name: "abc".to_string(),
                },
            )
            .await
            .unwrap();

        assert_eq!(ret.greeting, "hello c abc!");
    }

    #[tokio::test]
    async fn communicate_between_enc_and_non_enc() {
        let create_mgr = |enable_encryption| async move {
            let (s, _r) = create_packet_recv_chan();
            let mock_global_ctx = get_mock_global_ctx();
            mock_global_ctx.set_flags(Flags {
                enable_encryption,
                data_compress_algo: CompressionAlgoPb::Zstd.into(),
                ..Default::default()
            });
            let peer_mgr = Arc::new(PeerManager::new(RouteAlgoType::Ospf, mock_global_ctx, s));
            peer_mgr.run().await.unwrap();
            peer_mgr
        };

        let peer_mgr_a = create_mgr(true).await;
        let peer_mgr_b = create_mgr(false).await;

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;

        // wait 5sec should not crash.
        tokio::time::sleep(Duration::from_secs(5)).await;

        // both mgr should alive
        let mgr_c = create_mgr(true).await;
        connect_peer_manager(peer_mgr_a.clone(), mgr_c.clone()).await;
        wait_route_appear(mgr_c, peer_mgr_a).await.unwrap();

        let mgr_d = create_mgr(false).await;
        connect_peer_manager(peer_mgr_b.clone(), mgr_d.clone()).await;
        wait_route_appear(mgr_d, peer_mgr_b).await.unwrap();
    }

    #[tokio::test]
    async fn test_avoid_relay_data() {
        // a->b->c
        // a->d->e->c
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_d = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_e = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        println!("peer_mgr_a: {}", peer_mgr_a.my_peer_id);
        println!("peer_mgr_b: {}", peer_mgr_b.my_peer_id);
        println!("peer_mgr_c: {}", peer_mgr_c.my_peer_id);
        println!("peer_mgr_d: {}", peer_mgr_d.my_peer_id);
        println!("peer_mgr_e: {}", peer_mgr_e.my_peer_id);

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_d.clone()).await;
        connect_peer_manager(peer_mgr_d.clone(), peer_mgr_e.clone()).await;
        connect_peer_manager(peer_mgr_e.clone(), peer_mgr_c.clone()).await;

        // when b's avoid_relay_data is false, a->c should route through b and cost is 2
        wait_route_appear_with_cost(peer_mgr_a.clone(), peer_mgr_c.my_peer_id, Some(2))
            .await
            .unwrap();
        let ret = peer_mgr_a
            .get_route()
            .get_next_hop_with_policy(peer_mgr_c.my_peer_id, NextHopPolicy::LeastCost)
            .await;
        assert_eq!(ret, Some(peer_mgr_b.my_peer_id));

        // when b's avoid_relay_data is true, a->c should route through d and e, cost is 3
        peer_mgr_b
            .get_global_ctx()
            .set_avoid_relay_data_preference(true);
        tokio::time::sleep(Duration::from_secs(2)).await;
        if wait_route_appear_with_cost(peer_mgr_a.clone(), peer_mgr_c.my_peer_id, Some(3))
            .await
            .is_err()
        {
            panic!(
                "route not appear, a route table: {}, table: {:#?}",
                peer_mgr_a.get_route().dump().await,
                peer_mgr_a.get_route().list_routes().await
            )
        }

        let ret = peer_mgr_a
            .get_route()
            .get_next_hop_with_policy(peer_mgr_c.my_peer_id, NextHopPolicy::LeastCost)
            .await;
        assert_eq!(ret, Some(peer_mgr_d.my_peer_id));

        println!("route table: {:#?}", peer_mgr_a.list_routes().await);

        // drop e, path should go back to through b
        drop(peer_mgr_e);
        wait_route_appear_with_cost(peer_mgr_a.clone(), peer_mgr_c.my_peer_id, Some(2))
            .await
            .unwrap();
        let ret = peer_mgr_a
            .get_route()
            .get_next_hop_with_policy(peer_mgr_c.my_peer_id, NextHopPolicy::LeastCost)
            .await;
        assert_eq!(ret, Some(peer_mgr_b.my_peer_id));
    }

    #[tokio::test]
    async fn test_client_inbound_blackhole() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        // a is client, b is server

        let (a_ring, b_ring) = create_ring_tunnel_pair();
        let a_ring = Box::new(TunnelWithFilter::new(
            a_ring,
            DropSendTunnelFilter::new(2, 50000),
        ));

        let a_mgr_copy = peer_mgr_a.clone();
        tokio::spawn(async move {
            a_mgr_copy.add_client_tunnel(a_ring, false).await.unwrap();
        });
        let b_mgr_copy = peer_mgr_b.clone();
        tokio::spawn(async move {
            b_mgr_copy.add_tunnel_as_server(b_ring, true).await.unwrap();
        });

        wait_for_condition(
            || async {
                let peers = peer_mgr_a.list_peers().await;
                peers.is_empty()
            },
            Duration::from_secs(10),
        )
        .await;
    }

    #[tokio::test]
    async fn close_conn_in_peer_map() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        let conns = peer_mgr_a
            .get_peer_map()
            .list_peer_conns(peer_mgr_b.my_peer_id)
            .await;
        assert!(conns.is_some());
        let conn_info = conns.as_ref().unwrap().first().unwrap();

        peer_mgr_a
            .close_peer_conn(peer_mgr_b.my_peer_id, &conn_info.conn_id.parse().unwrap())
            .await
            .unwrap();

        wait_for_condition(
            || async {
                let peers = peer_mgr_a.list_peers().await;
                peers.is_empty()
            },
            Duration::from_secs(10),
        )
        .await;
        // a is client, b is server
    }

    #[tokio::test]
    async fn expired_credential_peer_conn_is_closed_without_ospf() {
        let (admin_ch, _admin_rx) = create_packet_recv_chan();
        let admin_ctx = get_mock_global_ctx();
        admin_ctx.config.set_network_identity(NetworkIdentity::new(
            "net1".to_string(),
            "secret".to_string(),
        ));
        set_secure_mode_cfg(&admin_ctx, true);
        let admin = Arc::new(PeerManager::new(
            RouteAlgoType::None,
            admin_ctx.clone(),
            admin_ch,
        ));
        admin.run().await.unwrap();

        let (cred_id, cred_secret) = admin_ctx.get_credential_manager().generate_credential(
            vec![],
            false,
            vec![],
            Duration::from_secs(3600),
        );
        let privkey_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(&cred_secret)
            .unwrap()
            .try_into()
            .unwrap();
        let private = x25519_dalek::StaticSecret::from(privkey_bytes);
        let public = x25519_dalek::PublicKey::from(&private);
        let (credential_ch, _credential_rx) = create_packet_recv_chan();
        let credential_ctx = get_mock_global_ctx();
        credential_ctx
            .config
            .set_network_identity(NetworkIdentity::new_credential("net1".to_string()));
        credential_ctx
            .config
            .set_secure_mode(Some(SecureModeConfig {
                enabled: true,
                local_private_key: Some(
                    base64::engine::general_purpose::STANDARD.encode(private.as_bytes()),
                ),
                local_public_key: Some(
                    base64::engine::general_purpose::STANDARD.encode(public.as_bytes()),
                ),
            }));
        let credential = Arc::new(PeerManager::new(
            RouteAlgoType::None,
            credential_ctx,
            credential_ch,
        ));
        credential.run().await.unwrap();
        let credential_peer_id = credential.my_peer_id();

        connect_peer_manager(credential.clone(), admin.clone()).await;

        wait_for_condition(
            || {
                let admin = admin.clone();
                async move {
                    admin
                        .get_peer_map()
                        .list_peer_conns(credential_peer_id)
                        .await
                        .is_some_and(|conns| !conns.is_empty())
                }
            },
            Duration::from_secs(5),
        )
        .await;

        // Expire only after admission. A one-second TTL can elapse while the
        // handshake is being scheduled, so it tests rejection instead of GC.
        assert!(
            admin_ctx
                .get_credential_manager()
                .is_pubkey_trusted(public.as_bytes())
        );
        admin_ctx
            .get_credential_manager()
            .expire_credential_for_test(&cred_id);
        assert!(
            !admin_ctx
                .get_credential_manager()
                .is_pubkey_trusted(public.as_bytes())
        );

        wait_for_condition(
            || {
                let admin = admin.clone();
                async move {
                    admin
                        .get_peer_map()
                        .list_peer_conns(credential_peer_id)
                        .await
                        .is_none_or(|conns| conns.is_empty())
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn close_conn_in_foreign_network_client() {
        let peer_mgr_server = create_mock_peer_manager_with_name("server".to_string()).await;
        let peer_mgr_client = create_mock_peer_manager_with_name("client".to_string()).await;
        connect_peer_manager(peer_mgr_client.clone(), peer_mgr_server.clone()).await;
        wait_for_condition(
            || async {
                peer_mgr_client
                    .get_foreign_network_client()
                    .list_public_peers()
                    .await
                    .len()
                    == 1
            },
            Duration::from_secs(3),
        )
        .await;

        let peer_id = peer_mgr_client
            .foreign_network_client
            .list_public_peers()
            .await[0];
        let conns = peer_mgr_client
            .foreign_network_client
            .get_peer_map()
            .list_peer_conns(peer_id)
            .await;
        assert!(conns.is_some());
        let conn_info = conns.as_ref().unwrap().first().unwrap();
        peer_mgr_client
            .close_peer_conn(peer_id, &conn_info.conn_id.parse().unwrap())
            .await
            .unwrap();

        wait_for_condition(
            || async {
                peer_mgr_client
                    .get_foreign_network_client()
                    .list_public_peers()
                    .await
                    .is_empty()
            },
            Duration::from_secs(10),
        )
        .await;
    }

    #[tokio::test]
    async fn close_conn_in_foreign_network_manager() {
        let peer_mgr_server = create_mock_peer_manager_with_name("server".to_string()).await;
        let peer_mgr_client = create_mock_peer_manager_with_name("client".to_string()).await;
        connect_peer_manager(peer_mgr_client.clone(), peer_mgr_server.clone()).await;
        wait_for_condition(
            || async {
                peer_mgr_client
                    .get_foreign_network_client()
                    .list_public_peers()
                    .await
                    .len()
                    == 1
            },
            Duration::from_secs(3),
        )
        .await;

        let conns = peer_mgr_server
            .foreign_network_manager
            .list_foreign_networks()
            .await;
        let client_info = conns.foreign_networks["client"].peers[0].clone();
        let conn_info = client_info.conns[0].clone();
        peer_mgr_server
            .close_peer_conn(client_info.peer_id, &conn_info.conn_id.parse().unwrap())
            .await
            .unwrap();

        wait_for_condition(
            || async {
                peer_mgr_client
                    .get_foreign_network_client()
                    .list_public_peers()
                    .await
                    .is_empty()
            },
            Duration::from_secs(10),
        )
        .await;
    }
}

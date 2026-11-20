use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Error};
use hotpath::instant::Instant;
use rand::Rng as _;
use tokio::task::JoinSet;

use crate::{
    common::{
        PeerId, config::TcpHolePunchMode, join_joinset_background, stun::StunInfoCollectorTrait,
    },
    connector::{
        tcp_hole_punch_transport::{
            FinishOutcome, TcpPunchRole, attach_new_tunnel, configured_mode_for_flags,
            finish as finish_transport, negotiate_mode, parse_wire_mode,
        },
        udp_hole_punch::BackOff,
    },
    peers::{
        peer_manager::PeerManager,
        peer_task::{PeerTaskLauncher, PeerTaskManager},
    },
    proto::{
        common::NatType,
        peer_rpc::{
            TcpHolePunchRequest, TcpHolePunchResponse, TcpHolePunchRpc,
            TcpHolePunchRpcClientFactory, TcpHolePunchRpcServer,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::{
        TunnelConnector as _, TunnelListener as _,
        tcp::{TcpTunnelConnector, TcpTunnelListener},
    },
};

use crate::connector::{should_background_p2p_with_peer, should_try_p2p_with_peer};

pub const BLACKLIST_TIMEOUT_SEC: u64 = 3600;

fn tquic_role(my_peer_id: PeerId, remote_peer_id: PeerId) -> TcpPunchRole {
    if my_peer_id < remote_peer_id {
        TcpPunchRole::Client
    } else {
        TcpPunchRole::Server
    }
}

/// MP transport selection is a post-punch policy.  A bad/unsupported MP
/// setting must never reject the legacy TCP hole-punch RPC or suppress TCP
/// traversal; it merely means the established carrier is attached as TCP.
fn handoff_mode_for_flags(flags: &crate::common::config::Flags) -> TcpHolePunchMode {
    configured_mode_for_flags(flags).unwrap_or_else(|error| {
        tracing::warn!(
            ?error,
            "TCP punch keeps legacy transport because the MP carrier upgrade is unavailable"
        );
        TcpHolePunchMode::Tcp
    })
}

/// The post-punch transport this endpoint offers `peer_id`: the configured
/// mode, except that `auto` offers plain TCP while repeated FakeTCP upgrades
/// toward that peer have been failing.
fn local_mode_for_peer(peer_mgr: &PeerManager, peer_id: PeerId) -> TcpHolePunchMode {
    let mode = handoff_mode_for_flags(&peer_mgr.get_global_ctx().get_flags());
    #[cfg(all(feature = "faketcp", feature = "mpquic"))]
    if mode == TcpHolePunchMode::Auto
        && peer_mgr
            .get_mp_session_manager()
            .faketcp_plain_tcp_fallback(peer_id)
    {
        return TcpHolePunchMode::Tcp;
    }
    #[cfg(not(all(feature = "faketcp", feature = "mpquic")))]
    let _ = peer_id;
    mode
}

/// Plain TCP goes on the wire as the empty string, so a punch without MP
/// sends exactly the upstream request/response.
fn wire_mode(mode: TcpHolePunchMode) -> String {
    match mode {
        TcpHolePunchMode::Tcp => String::new(),
        mode => mode.to_string(),
    }
}

/// A forced `faketcp` endpoint facing a plain-TCP one does not punch at all;
/// keep the reason where `stats mp` shows FakeTCP upgrade failures.
fn record_negotiation_failure(peer_mgr: &PeerManager, peer_id: PeerId, error: &Error) {
    tracing::warn!(peer_id, ?error, "tcp hole punch skipped, transports do not match");
    #[cfg(all(feature = "faketcp", feature = "mpquic"))]
    peer_mgr
        .get_mp_session_manager()
        .record_faketcp_upgrade(peer_id, Err(error.to_string()));
    #[cfg(not(all(feature = "faketcp", feature = "mpquic")))]
    let _ = peer_mgr;
}

/// With a FakeTCP upgrade in play only one endpoint may initiate: two crossed
/// punches give each side a different carrier to build the MP session on, and
/// both then wait out the handshake on the wrong one. The higher peer id
/// leaves initiating to the peer whenever that peer can initiate at all.
fn leave_initiating_to_peer(
    mode: TcpHolePunchMode,
    my_peer_id: PeerId,
    peer_id: PeerId,
    peer_tcp_nat_type: NatType,
) -> bool {
    mode != TcpHolePunchMode::Tcp
        && my_peer_id > peer_id
        && !is_symmetric_tcp_nat(peer_tcp_nat_type)
        && peer_tcp_nat_type != NatType::Unknown
}

fn handle_rpc_result<T>(
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

fn is_symmetric_tcp_nat(nat_type: NatType) -> bool {
    matches!(
        nat_type,
        NatType::Symmetric | NatType::SymmetricEasyInc | NatType::SymmetricEasyDec
    )
}

fn bind_addr_for_port(port: u16, is_v6: bool) -> SocketAddr {
    if is_v6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
    }
}

async fn select_local_port(peer_mgr: &Arc<PeerManager>, is_v6: bool) -> Result<u16, Error> {
    let bind_addr = bind_addr_for_port(0, is_v6);
    tracing::trace!(?bind_addr, is_v6, "tcp hole punch select local port");
    let _g = peer_mgr.get_global_ctx().net_ns.guard();
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    let port = listener.local_addr()?.port();
    tracing::debug!(?bind_addr, port, "tcp hole punch selected local port");
    Ok(port)
}

// tcp support simultaneous connect, so initiator and server can both use connect.
async fn try_connect_to_remote(
    peer_mgr: Arc<PeerManager>,
    a_mapped_addr: SocketAddr,
    local_port: u16,
    is_client: bool,
    max_attempts: u32,
    mode: TcpHolePunchMode,
    remote_peer_id: PeerId,
) -> Result<(), Error> {
    tracing::info!(
        ?a_mapped_addr,
        local_port,
        "tcp hole punch server start connect loop"
    );

    let mut connector =
        TcpTunnelConnector::new(format!("tcp://{}", a_mapped_addr).parse().unwrap());
    connector.set_bind_addrs(vec![bind_addr_for_port(
        local_port,
        a_mapped_addr.is_ipv6(),
    )]);

    let start = tokio::time::Instant::now();
    let mut attempts: u32 = 0;
    while start.elapsed() < Duration::from_secs(10) && attempts < max_attempts {
        attempts = attempts.wrapping_add(1);
        let _g = peer_mgr.get_global_ctx().net_ns.guard();
        if mode == TcpHolePunchMode::Tcp {
            if let Ok(Ok(tunnel)) =
                tokio::time::timeout(Duration::from_secs(3), connector.connect()).await
            {
                let add_tunnel_ret = if is_client {
                    peer_mgr.add_client_tunnel(tunnel, false).await.map(|_| ())
                } else {
                    peer_mgr.add_tunnel_as_server(tunnel, false).await
                };
                if let Err(e) = add_tunnel_ret {
                    tracing::error!(
                        ?a_mapped_addr,
                        local_port,
                        attempts,
                        ?e,
                        "tcp hole punch server connected and added client tunnel failed"
                    );
                    continue;
                } else {
                    tracing::info!(
                        ?a_mapped_addr,
                        local_port,
                        attempts,
                        is_client,
                        "tcp hole punch server connected and added tunnel"
                    );
                    return Ok(());
                }
            }
        } else if let Ok(Ok(stream)) =
            tokio::time::timeout(Duration::from_secs(3), connector.connect_stream()).await
        {
            let outcome = finish_transport(
                &peer_mgr,
                remote_peer_id,
                stream,
                connector.remote_url(),
                mode,
                tquic_role(peer_mgr.my_peer_id(), remote_peer_id),
            )
            .await?;
            let FinishOutcome::NewTunnel { tunnel, mp_role } = outcome else {
                tracing::info!(
                    remote_peer_id,
                    "punched TCP carrier added to existing MPQUIC session"
                );
                return Ok(());
            };
            let legacy_role = if is_client {
                TcpPunchRole::Client
            } else {
                TcpPunchRole::Server
            };
            let add_tunnel_ret = attach_new_tunnel(
                &peer_mgr,
                remote_peer_id,
                tunnel,
                mp_role,
                legacy_role,
                false,
            )
            .await;
            if let Err(e) = add_tunnel_ret {
                tracing::error!(
                    ?a_mapped_addr,
                    local_port,
                    attempts,
                    ?e,
                    "tcp hole punch established a carrier but the EasyTier attach failed"
                );
                continue;
            }
            tracing::info!(
                ?a_mapped_addr,
                local_port,
                attempts,
                is_client,
                "tcp hole punch connected and added tunnel"
            );
            return Ok(());
        }
        tracing::trace!(
            ?a_mapped_addr,
            local_port,
            attempts,
            "tcp hole punch server connect attempt failed"
        );
        let sleep_ms = rand::thread_rng().gen_range(10..100);
        tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
    }

    tracing::warn!(
        ?a_mapped_addr,
        local_port,
        attempts,
        "tcp hole punch server connect loop timeout"
    );

    Err(anyhow::anyhow!(
        "tcp hole punch server connect loop timeout"
    ))
}

struct TcpHolePunchServer {
    peer_mgr: Arc<PeerManager>,
    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
}

impl TcpHolePunchServer {
    fn new(peer_mgr: Arc<PeerManager>) -> Arc<Self> {
        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "tcp hole punch server".to_string());
        Arc::new(Self { peer_mgr, tasks })
    }
}

#[async_trait::async_trait]
impl TcpHolePunchRpc for TcpHolePunchServer {
    type Controller = BaseController;

    #[tracing::instrument(skip(self), fields(a_mapped_addr = ?input.connector_mapped_addr), err)]
    async fn exchange_mapped_addr(
        &self,
        _ctrl: Self::Controller,
        input: TcpHolePunchRequest,
    ) -> rpc_types::error::Result<TcpHolePunchResponse> {
        let my_tcp_nat_type = NatType::try_from(
            self.peer_mgr
                .get_global_ctx()
                .get_stun_info_collector()
                .get_stun_info()
                .tcp_nat_type,
        )
        .unwrap_or(NatType::Unknown);
        tracing::debug!(?my_tcp_nat_type, "tcp hole punch rpc received");
        if matches!(my_tcp_nat_type, NatType::Unknown) {
            tracing::warn!(?my_tcp_nat_type, "tcp hole punch rpc rejected (unknown)");
            return Err(anyhow::anyhow!("tcp nat type unknown not supported").into());
        }

        let requester_peer_id = input.requester_peer_id;
        let local_mode = local_mode_for_peer(&self.peer_mgr, requester_peer_id);
        // A plain-TCP responder serves every request exactly as upstream does;
        // a forced-`faketcp` requester refuses the result on its own side.
        let mode = if local_mode == TcpHolePunchMode::Tcp {
            TcpHolePunchMode::Tcp
        } else {
            let remote_mode = parse_wire_mode(&input.transport_mode)?;
            negotiate_mode(local_mode, remote_mode).inspect_err(|error| {
                record_negotiation_failure(&self.peer_mgr, requester_peer_id, error);
            })?
        };

        let a_mapped_addr = input
            .connector_mapped_addr
            .ok_or(anyhow::anyhow!("connector_mapped_addr is required"))?;
        let a_mapped_addr: SocketAddr = a_mapped_addr.into();
        let a_ip = a_mapped_addr.ip();
        if a_ip.is_unspecified() || a_ip.is_multicast() {
            tracing::warn!(?a_mapped_addr, "tcp hole punch rpc invalid connector addr");
            return Err(anyhow::anyhow!("connector_mapped_addr is malformed").into());
        }

        let is_v6 = a_mapped_addr.is_ipv6();
        let local_port = select_local_port(&self.peer_mgr, is_v6).await?;
        let mapped_addr = self
            .peer_mgr
            .get_global_ctx()
            .get_stun_info_collector()
            .get_tcp_port_mapping(local_port)
            .await
            .with_context(|| "failed to get tcp port mapping")?;
        tracing::info!(
            ?a_mapped_addr,
            local_port,
            ?mapped_addr,
            "tcp hole punch rpc responding with listener mapped addr and start connecting"
        );

        let peer_mgr = self.peer_mgr.clone();
        self.tasks.lock().unwrap().spawn(async move {
            let _ = try_connect_to_remote(
                peer_mgr,
                a_mapped_addr,
                local_port,
                true,
                5,
                mode,
                requester_peer_id,
            )
            .await;
        });

        Ok(TcpHolePunchResponse {
            listener_mapped_addr: Some(mapped_addr.into()),
            // Both ends negotiate from the same pair of offers, so they agree
            // on whether the punched carrier becomes a FakeTCP MP path.
            transport_mode: wire_mode(local_mode),
        })
    }
}

struct TcpHolePunchConnectorData {
    peer_mgr: Arc<PeerManager>,
    blacklist: Arc<timedmap::TimedMap<PeerId, ()>>,
    #[cfg(feature = "mpquic")]
    mp_punch_progress: dashmap::DashMap<PeerId, crate::connector::mp_session::MpPunchProgress>,
}

impl TcpHolePunchConnectorData {
    fn new(peer_mgr: Arc<PeerManager>) -> Arc<Self> {
        Arc::new(Self {
            peer_mgr,
            blacklist: Arc::new(timedmap::TimedMap::new()),
            #[cfg(feature = "mpquic")]
            mp_punch_progress: dashmap::DashMap::new(),
        })
    }

    /// MP_SQM_PLAN.md S2.14: same per-peer attempt count and stop rule as
    /// UDP punching, counted over FakeTCP carriers.
    #[cfg(feature = "mpquic")]
    async fn mp_punch_slot(
        &self,
        peer_id: PeerId,
        mp: &crate::proto::common::MpConfig,
    ) -> Option<u32> {
        let summary = self
            .peer_mgr
            .get_mp_session_manager()
            .punch_wan_summary(peer_id, crate::connector::mp_path::CarrierKind::FakeTcpPunch)
            .await;
        let mut progress = self.mp_punch_progress.entry(peer_id).or_default();
        crate::connector::mp_session::next_mp_punch_slot(
            &summary,
            &mut progress,
            crate::common::config::effective_mp_punch_attempts(mp),
        )
    }

    async fn punch_as_initiator(self: Arc<Self>, dst_peer_id: PeerId) -> Result<(), Error> {
        let mut backoff = BackOff::new(vec![1000, 1000, 4000, 8000]);

        loop {
            backoff.sleep_for_next_backoff().await;
            if self.do_punch_as_initiator(dst_peer_id).await.is_ok() {
                break;
            }

            if self.blacklist.contains(&dst_peer_id) {
                tracing::warn!(
                    dst_peer_id,
                    "tcp hole punch initiator skipped (blacklisted)"
                );
                break;
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip(self), fields(dst_peer_id), err)]
    async fn do_punch_as_initiator(&self, dst_peer_id: PeerId) -> Result<(), Error> {
        let global_ctx = self.peer_mgr.get_global_ctx();
        let local_mode = local_mode_for_peer(&self.peer_mgr, dst_peer_id);
        let my_tcp_nat_type = NatType::try_from(
            global_ctx
                .get_stun_info_collector()
                .get_stun_info()
                .tcp_nat_type,
        )
        .unwrap_or(NatType::Unknown);
        tracing::debug!(?my_tcp_nat_type, "tcp hole punch initiator start");
        if is_symmetric_tcp_nat(my_tcp_nat_type) || my_tcp_nat_type == NatType::Unknown {
            tracing::debug!("tcp hole punch initiator skipped (symmetric)");
            return Ok(());
        }

        let local_port = select_local_port(&self.peer_mgr, false).await?;
        let mapped_addr = global_ctx
            .get_stun_info_collector()
            .get_tcp_port_mapping(local_port)
            .await
            .with_context(|| "failed to get tcp port mapping")?;
        tracing::info!(
            dst_peer_id,
            local_port,
            ?mapped_addr,
            "tcp hole punch initiator got mapped addr, start rpc exchange"
        );

        let rpc_stub = self
            .peer_mgr
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<TcpHolePunchRpcClientFactory<BaseController>>(
                self.peer_mgr.my_peer_id(),
                dst_peer_id,
                global_ctx.get_network_name(),
            );

        let resp = rpc_stub
            .exchange_mapped_addr(
                BaseController {
                    timeout_ms: 6000,
                    ..Default::default()
                },
                TcpHolePunchRequest {
                    connector_mapped_addr: Some(mapped_addr.into()),
                    requester_peer_id: self.peer_mgr.my_peer_id(),
                    transport_mode: wire_mode(local_mode),
                },
            )
            .await;
        let resp = handle_rpc_result(resp, dst_peer_id, &self.blacklist)?;
        let mode = if local_mode == TcpHolePunchMode::Tcp {
            TcpHolePunchMode::Tcp
        } else {
            negotiate_mode(local_mode, parse_wire_mode(&resp.transport_mode)?).inspect_err(
                |error| record_negotiation_failure(&self.peer_mgr, dst_peer_id, error),
            )?
        };
        let remote_mapped_addr = resp
            .listener_mapped_addr
            .ok_or(anyhow::anyhow!("listener_mapped_addr is required"))?;
        let remote_mapped_addr: SocketAddr = remote_mapped_addr.into();
        tracing::info!(
            dst_peer_id,
            ?remote_mapped_addr,
            "tcp hole punch initiator rpc returned"
        );

        if let Ok(()) = try_connect_to_remote(
            self.peer_mgr.clone(),
            remote_mapped_addr,
            local_port,
            false,
            1,
            mode,
            dst_peer_id,
        )
        .await
        {
            tracing::info!(
                dst_peer_id,
                local_port,
                ?remote_mapped_addr,
                "tcp hole punch initiator connected to remote mapped addr with simultaneous connection"
            );
            return Ok(());
        }

        tracing::debug!(
            dst_peer_id,
            local_port,
            ?remote_mapped_addr,
            "tcp hole punch initiator sent syn to remote mapped addr"
        );

        let mut listener =
            TcpTunnelListener::new(format!("tcp://0.0.0.0:{}", local_port).parse().unwrap());
        {
            let _g = self.peer_mgr.get_global_ctx().net_ns.guard();
            listener.listen().await?;
        }
        tracing::info!(
            dst_peer_id,
            local_port,
            url = %listener.local_url(),
            "tcp hole punch initiator listening"
        );

        tokio::time::timeout(
            Duration::from_secs(10),
            self.accept_loop(&mut listener, dst_peer_id, mode),
        )
        .await??;

        tracing::info!(
            dst_peer_id,
            "tcp hole punch initiator accepted and added server tunnel"
        );

        Ok(())
    }

    async fn accept_loop(
        &self,
        listener: &mut TcpTunnelListener,
        dst_peer_id: PeerId,
        mode: TcpHolePunchMode,
    ) -> Result<(), Error> {
        loop {
            if mode == TcpHolePunchMode::Tcp {
                match listener.accept().await {
                    Ok(tunnel) => {
                        if let Err(e) = self.peer_mgr.add_tunnel_as_server(tunnel, false).await {
                            tracing::error!("tcp hole punch add tunnel error: {}", e);
                            continue;
                        }

                        tracing::info!(
                            dst_peer_id,
                            "tcp hole punch initiator accepted and added server tunnel"
                        );
                    }
                    Err(e) => {
                        tracing::error!("tcp hole punch accept error: {}", e);
                    }
                }
                continue;
            }
            match listener.accept_stream().await {
                Ok(stream) => {
                    let remote_url = crate::tunnel::build_url_from_socket_addr(
                        &stream.peer_addr()?.to_string(),
                        "tcp",
                    );
                    let outcome = finish_transport(
                        &self.peer_mgr,
                        dst_peer_id,
                        stream,
                        remote_url,
                        mode,
                        tquic_role(self.peer_mgr.my_peer_id(), dst_peer_id),
                    )
                    .await?;
                    let FinishOutcome::NewTunnel { tunnel, mp_role } = outcome else {
                        tracing::info!(
                            dst_peer_id,
                            "accepted TCP carrier added to existing MPQUIC session"
                        );
                        return Ok(());
                    };
                    if let Err(e) = attach_new_tunnel(
                        &self.peer_mgr,
                        dst_peer_id,
                        tunnel,
                        mp_role,
                        TcpPunchRole::Server,
                        false,
                    )
                    .await
                    {
                        tracing::error!("tcp hole punch add tunnel error: {}", e);
                        continue;
                    }
                    tracing::info!(
                        dst_peer_id,
                        "tcp hole punch initiator accepted and added server tunnel"
                    );
                }
                Err(e) => {
                    tracing::error!("tcp hole punch accept error: {}", e);
                }
            }
        }
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct TcpPunchTaskInfo {
    dst_peer_id: PeerId,
    /// MP multi-punch slot; always 0 for native punching.
    slot: u32,
}

#[derive(Clone)]
struct TcpHolePunchPeerTaskLauncher {}

#[async_trait::async_trait]
impl PeerTaskLauncher for TcpHolePunchPeerTaskLauncher {
    type Data = Arc<TcpHolePunchConnectorData>;
    type CollectPeerItem = TcpPunchTaskInfo;
    type TaskRet = ();

    fn new_data(&self, peer_mgr: Arc<PeerManager>) -> Self::Data {
        TcpHolePunchConnectorData::new(peer_mgr)
    }

    #[tracing::instrument(skip(self, data))]
    async fn collect_peers_need_task(&self, data: &Self::Data) -> Vec<Self::CollectPeerItem> {
        let global_ctx = data.peer_mgr.get_global_ctx();
        let flags = global_ctx.get_flags();
        let lazy_p2p = flags.lazy_p2p;
        let my_tcp_nat_type = NatType::try_from(
            global_ctx
                .get_stun_info_collector()
                .get_stun_info()
                .tcp_nat_type,
        )
        .unwrap_or(NatType::Unknown);
        if is_symmetric_tcp_nat(my_tcp_nat_type) || my_tcp_nat_type == NatType::Unknown {
            tracing::trace!(
                ?my_tcp_nat_type,
                "tcp hole punch task collect skipped (symmetric)"
            );
            return vec![];
        }

        let my_peer_id = data.peer_mgr.my_peer_id();
        let now = Instant::now();

        data.blacklist.cleanup();

        #[cfg(feature = "mpquic")]
        let mut routed_peers = std::collections::HashSet::new();
        let mut peers_to_connect = Vec::new();
        for route in data.peer_mgr.list_routes().await.iter() {
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
            if !static_allowed && !dynamic_allowed {
                continue;
            }

            let peer_id: PeerId = route.peer_id;
            if peer_id == my_peer_id {
                tracing::trace!(peer_id, "tcp hole punch task collect skip self");
                continue;
            }

            if data.blacklist.contains(&peer_id) {
                tracing::debug!(peer_id, "tcp hole punch task collect skip blacklisted");
                continue;
            }

            let has_peer = data.peer_mgr.get_peer_map().has_peer(peer_id);
            let mp = flags
                .mp
                .clone()
                .unwrap_or_else(crate::common::config::gen_default_mp_config);
            let faketcp_punch_provider_enabled = mp
                .providers
                .iter()
                .any(|provider| provider == "faketcp-punch");
            #[cfg(feature = "mpquic")]
            routed_peers.insert(peer_id);
            let slot = if mp.enabled
                && faketcp_punch_provider_enabled
                && super::peer_runs_mp(route.feature_flag.as_ref())
            {
                #[cfg(feature = "mpquic")]
                let slot = data.mp_punch_slot(peer_id, &mp).await;
                #[cfg(not(feature = "mpquic"))]
                let slot = (!has_peer).then_some(0);
                slot
            } else {
                (!has_peer).then_some(0)
            };
            let Some(slot) = slot else {
                tracing::trace!(peer_id, "tcp hole punch task collect skip already has peer");
                continue;
            };

            let peer_tcp_nat_type = route
                .stun_info
                .as_ref()
                .map(|x| x.tcp_nat_type)
                .unwrap_or(0);
            let peer_tcp_nat_type =
                NatType::try_from(peer_tcp_nat_type).unwrap_or(NatType::Unknown);
            if matches!(peer_tcp_nat_type, NatType::Unknown) {
                tracing::debug!(
                    peer_id,
                    ?peer_tcp_nat_type,
                    "tcp hole punch task collect skip peer unknown"
                );
                continue;
            }
            if leave_initiating_to_peer(
                local_mode_for_peer(&data.peer_mgr, peer_id),
                my_peer_id,
                peer_id,
                peer_tcp_nat_type,
            ) {
                tracing::debug!(
                    peer_id,
                    ?peer_tcp_nat_type,
                    "tcp hole punch task collect skip, the peer initiates FakeTCP punches"
                );
                continue;
            }

            tracing::info!(
                peer_id,
                my_peer_id,
                ?my_tcp_nat_type,
                ?peer_tcp_nat_type,
                "tcp hole punch task collect add peer"
            );
            peers_to_connect.push(TcpPunchTaskInfo {
                dst_peer_id: peer_id,
                slot,
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
    ) -> tokio::task::JoinHandle<Result<Self::TaskRet, anyhow::Error>> {
        let data = data.clone();
        #[cfg(feature = "mpquic")]
        let in_flight = crate::connector::mp_session::MpPunchInFlight::new(
            data.clone(),
            |data| &data.mp_punch_progress,
            item.dst_peer_id,
            item.slot,
        );
        tokio::spawn(async move {
            #[cfg(feature = "mpquic")]
            let _in_flight = in_flight;
            data.punch_as_initiator(item.dst_peer_id).await.map(|_| ())
        })
    }

    async fn all_task_done(&self, _data: &Self::Data) {}

    fn loop_interval_ms(&self) -> u64 {
        5000
    }
}

pub struct TcpHolePunchConnector {
    server: Arc<TcpHolePunchServer>,
    client: PeerTaskManager<TcpHolePunchPeerTaskLauncher>,
    peer_mgr: Arc<PeerManager>,
}

impl TcpHolePunchConnector {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        Self {
            server: TcpHolePunchServer::new(peer_mgr.clone()),
            client: PeerTaskManager::new_with_external_signal(
                TcpHolePunchPeerTaskLauncher {},
                peer_mgr.clone(),
                Some(peer_mgr.p2p_demand_notify()),
            ),
            peer_mgr,
        }
    }

    pub async fn run_as_client(&mut self) -> Result<(), Error> {
        tracing::info!("tcp hole punch client start");
        self.client.start();
        Ok(())
    }

    pub async fn run_as_server(&mut self) -> Result<(), Error> {
        tracing::info!("tcp hole punch server register rpc");
        self.peer_mgr
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                TcpHolePunchRpcServer::new_arc(self.server.clone()),
                &self.peer_mgr.get_global_ctx().get_network_name(),
            );
        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        let flags = self.peer_mgr.get_global_ctx().get_flags();
        if flags.disable_tcp_hole_punching {
            tracing::debug!(
                "tcp hole punch disabled by disable_tcp_hole_punching(={});",
                flags.disable_tcp_hole_punching
            );
            return Ok(());
        }

        let mode = handoff_mode_for_flags(&flags);
        tracing::info!(?mode, "tcp hole punch transport mode");

        self.run_as_client().await?;
        self.run_as_server().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc, time::Duration};

    use crate::{
        common::{config::TcpHolePunchMode, error::Error, stun::StunInfoCollectorTrait},
        connector::tcp_hole_punch::TcpHolePunchConnector,
        peers::{
            peer_manager::PeerManager,
            peer_task::PeerTaskLauncher,
            tests::{connect_peer_manager, create_mock_peer_manager, wait_route_appear},
        },
        proto::common::{NatType, StunInfo},
        tunnel::common::tests::wait_for_condition,
    };

    use super::{
        TcpHolePunchPeerTaskLauncher, handoff_mode_for_flags, leave_initiating_to_peer,
        tquic_role, wire_mode,
    };

    #[test]
    fn plain_tcp_offers_nothing_on_the_wire() {
        use crate::connector::tcp_hole_punch_transport::parse_wire_mode;
        assert_eq!(wire_mode(TcpHolePunchMode::Tcp), "");
        for mode in [
            TcpHolePunchMode::Auto,
            TcpHolePunchMode::FakeTcp,
            TcpHolePunchMode::Tcp,
        ] {
            assert_eq!(parse_wire_mode(&wire_mode(mode)).unwrap(), mode);
        }
    }

    #[test]
    fn only_the_lower_peer_id_initiates_faketcp_punches_when_both_can() {
        use TcpHolePunchMode::*;
        // The higher id defers to a peer that can initiate...
        assert!(leave_initiating_to_peer(Auto, 20, 10, NatType::NoPat));
        assert!(leave_initiating_to_peer(FakeTcp, 20, 10, NatType::OpenInternet));
        // ...but not to one that cannot, and the lower id always initiates.
        assert!(!leave_initiating_to_peer(Auto, 20, 10, NatType::Symmetric));
        assert!(!leave_initiating_to_peer(Auto, 20, 10, NatType::Unknown));
        assert!(!leave_initiating_to_peer(Auto, 10, 20, NatType::NoPat));
        // Plain TCP keeps upstream's both-sides punching.
        assert!(!leave_initiating_to_peer(Tcp, 20, 10, NatType::NoPat));
    }

    #[test]
    fn tquic_role_is_deterministic_for_peer_pair() {
        assert_eq!(
            tquic_role(10, 20),
            crate::connector::tcp_hole_punch_transport::TcpPunchRole::Client
        );
        assert_eq!(
            tquic_role(20, 10),
            crate::connector::tcp_hole_punch_transport::TcpPunchRole::Server
        );
    }

    #[test]
    fn unavailable_mp_upgrade_never_rejects_the_tcp_punch_policy() {
        let mut flags = crate::common::config::gen_default_flags();
        flags.mp.as_mut().unwrap().enabled = true;
        flags.mp.as_mut().unwrap().providers.clear();
        flags.tcp_hole_punch_mode = "faketcp".into();

        assert_eq!(
            handoff_mode_for_flags(&flags),
            TcpHolePunchMode::Tcp,
            "MP configuration is post-punch policy, not a traversal precondition"
        );
    }

    struct MockStunInfoCollector {
        udp_nat_type: NatType,
        tcp_nat_type: NatType,
    }

    #[async_trait::async_trait]
    impl StunInfoCollectorTrait for MockStunInfoCollector {
        fn get_stun_info(&self) -> StunInfo {
            StunInfo {
                udp_nat_type: self.udp_nat_type as i32,
                tcp_nat_type: self.tcp_nat_type as i32,
                last_update_time: 0,
                public_ip: vec!["127.0.0.1".to_string(), "::1".to_string()],
                min_port: 100,
                max_port: 200,
            }
        }

        async fn get_udp_port_mapping(&self, mut port: u16) -> Result<SocketAddr, Error> {
            if port == 0 {
                port = 40144;
            }
            Ok(format!("127.0.0.1:{}", port).parse().unwrap())
        }

        async fn get_udp_port_mapping_with_socket(
            &self,
            udp: std::sync::Arc<tokio::net::UdpSocket>,
        ) -> Result<SocketAddr, Error> {
            self.get_udp_port_mapping(udp.local_addr()?.port()).await
        }

        async fn get_tcp_port_mapping(&self, mut port: u16) -> Result<SocketAddr, Error> {
            if port == 0 {
                port = 40144;
            }
            Ok(format!("127.0.0.1:{}", port).parse().unwrap())
        }
    }

    fn replace_stun_info_collector(peer_mgr: Arc<PeerManager>, tcp_nat_type: NatType) {
        let collector = Box::new(MockStunInfoCollector {
            udp_nat_type: NatType::Unknown,
            tcp_nat_type,
        });
        peer_mgr
            .get_global_ctx()
            .replace_stun_info_collector(collector);
    }

    async fn collect_lazy_punch_peers(peer_mgr: Arc<PeerManager>) -> Vec<u32> {
        let launcher = TcpHolePunchPeerTaskLauncher {};
        let data = launcher.new_data(peer_mgr);
        launcher
            .collect_peers_need_task(&data)
            .await
            .into_iter()
            .map(|task| task.dst_peer_id)
            .collect()
    }

    #[tokio::test]
    async fn tcp_hole_punch_connects() {
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;

        replace_stun_info_collector(p_a.clone(), NatType::PortRestricted);
        replace_stun_info_collector(p_b.clone(), NatType::PortRestricted);
        replace_stun_info_collector(p_c.clone(), NatType::PortRestricted);

        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let mut hole_punching_a = TcpHolePunchConnector::new(p_a.clone());
        let mut hole_punching_c = TcpHolePunchConnector::new(p_c.clone());
        hole_punching_a.run().await.unwrap();
        hole_punching_c.run().await.unwrap();

        hole_punching_a.client.run_immediately().await;
        hole_punching_c.client.run_immediately().await;

        wait_for_condition(
            || {
                let p_a = p_a.clone();
                let p_c = p_c.clone();
                async move {
                    let a_has = p_a
                        .get_peer_map()
                        .list_peer_conns(p_c.my_peer_id())
                        .await
                        .is_some_and(|c| !c.is_empty());
                    let c_has = p_c
                        .get_peer_map()
                        .list_peer_conns(p_a.my_peer_id())
                        .await
                        .is_some_and(|c| !c.is_empty());
                    a_has || c_has
                }
            },
            Duration::from_secs(15),
        )
        .await;
    }

    #[tokio::test]
    async fn tcp_hole_punch_skip_symmetric_peer() {
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;

        replace_stun_info_collector(p_a.clone(), NatType::Symmetric);
        replace_stun_info_collector(p_b.clone(), NatType::PortRestricted);
        replace_stun_info_collector(p_c.clone(), NatType::Symmetric);

        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let mut hole_punching_a = TcpHolePunchConnector::new(p_a.clone());
        let mut hole_punching_c = TcpHolePunchConnector::new(p_c.clone());
        hole_punching_a.run().await.unwrap();
        hole_punching_c.run().await.unwrap();

        hole_punching_a.client.run_immediately().await;
        hole_punching_c.client.run_immediately().await;

        tokio::time::sleep(Duration::from_secs(2)).await;

        assert!(
            p_a.get_peer_map()
                .list_peer_conns(p_c.my_peer_id())
                .await
                .map(|c| c.is_empty())
                .unwrap_or(true)
        );
        assert!(
            p_c.get_peer_map()
                .list_peer_conns(p_a.my_peer_id())
                .await
                .map(|c| c.is_empty())
                .unwrap_or(true)
        );
    }

    #[tokio::test]
    async fn plain_tcp_accept_loop_survives_a_connection_reset_before_accept() {
        use crate::tunnel::TunnelListener as _;

        let peer_mgr = create_mock_peer_manager().await;
        let data = super::TcpHolePunchConnectorData::new(peer_mgr);
        let mut listener =
            crate::tunnel::tcp::TcpTunnelListener::new("tcp://127.0.0.1:0".parse().unwrap());
        listener.listen().await.unwrap();
        let url = listener.local_url();
        let addr: SocketAddr = format!("{}:{}", url.host_str().unwrap(), url.port().unwrap())
            .parse()
            .unwrap();

        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client.set_linger(Some(Duration::ZERO)).unwrap();
        drop(client);
        tokio::time::sleep(Duration::from_millis(200)).await;

        let ret = tokio::time::timeout(
            Duration::from_secs(1),
            data.accept_loop(&mut listener, 1, TcpHolePunchMode::Tcp),
        )
        .await;
        assert!(
            ret.is_err(),
            "upstream logs a failed accept and keeps accepting, got {ret:?}"
        );
    }

    #[tokio::test]
    async fn lazy_p2p_collects_tcp_hole_punch_tasks_only_after_recent_traffic() {
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;

        replace_stun_info_collector(p_a.clone(), NatType::PortRestricted);
        replace_stun_info_collector(p_b.clone(), NatType::PortRestricted);
        replace_stun_info_collector(p_c.clone(), NatType::PortRestricted);

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
}

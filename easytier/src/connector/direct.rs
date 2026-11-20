// try connect peers directly, with either its public ip or lan ip

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use hotpath::instant::Instant;

use crate::{
    common::{
        PeerId, dns::socket_addrs, error::Error, global_ctx::ArcGlobalCtx,
        network::is_usable_interface_ipv4, stun::StunInfoCollectorTrait,
    },
    connector::udp_hole_punch::handle_rpc_result,
    peers::{
        peer_conn::PeerConnId,
        peer_manager::PeerManager,
        peer_rpc::PeerRpcManager,
        peer_rpc_service::DirectConnectorManagerRpcServer,
        peer_task::{PeerTaskLauncher, PeerTaskManager},
    },
    proto::{
        peer_rpc::{
            DirectConnectorRpc, DirectConnectorRpcClientFactory, DirectConnectorRpcServer,
            GetIpListRequest, GetIpListResponse, SendUdpHolePunchPacketRequest,
        },
        rpc_types::controller::BaseController,
    },
    tunnel::{IpVersion, matches_protocol, udp::UdpTunnelConnector},
    use_global_var,
};

use super::{
    create_connector_by_url, should_background_p2p_with_peer, should_try_p2p_with_peer,
    udp_hole_punch,
};
use crate::tunnel::{FromUrl, IpScheme, TunnelScheme, matches_scheme};
use anyhow::Context;
use rand::Rng;
use socket2::Protocol;
use tokio::{net::UdpSocket, task::JoinSet, time::timeout};
use url::Host;

#[cfg(feature = "mpquic")]
use tokio_util::task::AbortOnDropHandle;

#[cfg(feature = "mpquic")]
use crate::{
    connector::{
        mp_path::CarrierKind,
        udp_hole_punch::common::{HOLE_PUNCH_PACKET_BODY_LEN, wait_for_hole_punch_packet},
        udp_hole_punch_transport::{
            EstablishedUdpCarrier, FinishOutcome as UdpMpFinishOutcome, UdpPunchRole,
            attach_new_tunnel, finish_established, mp_udp_provider_enabled,
        },
    },
    proto::peer_rpc::{
        SelectPunchListenerRequest, SendPunchPacketConeRequest, UdpHolePunchRpcClientFactory,
    },
    tunnel::{
        common::{bind, get_interface_ipv4_by_name},
        udp::new_hole_punch_packet,
    },
};

pub const DIRECT_CONNECTOR_SERVICE_ID: u32 = 1;
pub const DIRECT_CONNECTOR_BLACKLIST_TIMEOUT_SEC: u64 = 300;

static TESTING: AtomicBool = AtomicBool::new(false);

fn mapped_listener_port(url: &url::Url) -> Option<u16> {
    url.port().or_else(|| {
        TunnelScheme::try_from(url)
            .ok()
            .and_then(|scheme| IpScheme::try_from(scheme).ok())
            .map(IpScheme::default_port)
    })
}

async fn resolve_mapped_listener_addrs(listener: &url::Url) -> Result<Vec<SocketAddr>, Error> {
    socket_addrs(listener, || mapped_listener_port(listener)).await
}

fn is_usable_public_ipv6_candidate(ip: &Ipv6Addr, global_ctx: &ArcGlobalCtx) -> bool {
    is_usable_public_ipv6_candidate_with_mode(ip, global_ctx, TESTING.load(Ordering::Relaxed))
}

fn is_usable_public_ipv6_candidate_with_mode(
    ip: &Ipv6Addr,
    global_ctx: &ArcGlobalCtx,
    testing: bool,
) -> bool {
    !global_ctx.is_ip_easytier_managed_ipv6(ip)
        && (testing
            || (!ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_unique_local()
                && !ip.is_unicast_link_local()
                && !ip.is_multicast()))
}

fn should_skip_existing_direct_peer(
    has_direct_peer: bool,
    mp_udp_direct_enabled: bool,
    has_live_udp_direct_carrier: bool,
) -> bool {
    has_direct_peer && (!mp_udp_direct_enabled || has_live_udp_direct_carrier)
}

/// Which udp-direct paths are still to build, given the live ones' devices:
/// one per configured NIC, or a single OS-routed one without NICs (the
/// behavior before per-NIC paths).
#[cfg(feature = "mpquic")]
fn missing_udp_direct_devices(configured: &[String], live: &[Option<String>]) -> Vec<Option<String>> {
    if configured.is_empty() {
        return if live.is_empty() { vec![None] } else { Vec::new() };
    }
    configured
        .iter()
        .filter(|device| !live.iter().any(|have| have.as_deref() == Some(device.as_str())))
        .map(|device| Some(device.clone()))
        .collect()
}

#[cfg(feature = "mpquic")]
fn udp_direct_ipv4_candidates(
    ip_list: &GetIpListResponse,
    listener_port: u16,
    testing: bool,
) -> Vec<SocketAddr> {
    // A public STUN mapping is the only cross-network candidate that is
    // expected to work without an existing LAN route. Try it first, then
    // retain usable interface addresses as LAN fallbacks. A HashSet-only
    // implementation both omitted the public mapping and made probe order
    // nondeterministic, so a private NIC address could repeatedly consume the
    // UDP-direct attempt before the actual WAN endpoint was considered.
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();
    let mut push = |ip: Ipv4Addr| {
        if seen.insert(ip) {
            candidates.push(SocketAddr::new(IpAddr::V4(ip), listener_port));
        }
    };

    if let Some(public_ip) = ip_list.public_ipv4.map(Ipv4Addr::from)
        && (testing || is_public_ipv4(public_ip))
    {
        push(public_ip);
    }

    for interface_ip in ip_list.interface_ipv4s.iter().map(|ip| Ipv4Addr::from(*ip)) {
        if !interface_ip.is_link_local() && (testing || is_usable_interface_ipv4(interface_ip)) {
            push(interface_ip);
        }
    }

    candidates
}

#[async_trait::async_trait]
pub trait PeerManagerForDirectConnector {
    async fn list_peers(&self) -> Vec<PeerId>;
    fn get_peer_rpc_mgr(&self) -> Arc<PeerRpcManager>;
}

#[async_trait::async_trait]
impl PeerManagerForDirectConnector for PeerManager {
    async fn list_peers(&self) -> Vec<PeerId> {
        let mut ret = vec![];
        let allow_public_server = use_global_var!(DIRECT_CONNECT_TO_PUBLIC_SERVER);
        let flags = self.get_global_ctx().get_flags();
        let lazy_p2p = flags.lazy_p2p;
        let now = Instant::now();

        let routes = self.list_routes().await;
        for route in routes.iter() {
            let static_allowed = should_background_p2p_with_peer(
                route.feature_flag.as_ref(),
                allow_public_server,
                lazy_p2p,
                flags.disable_p2p,
                flags.need_p2p,
            );
            let dynamic_allowed = should_try_p2p_with_peer(
                route.feature_flag.as_ref(),
                allow_public_server,
                flags.disable_p2p,
                flags.need_p2p,
            ) && self.has_recent_traffic(route.peer_id, now);
            if static_allowed || dynamic_allowed {
                ret.push(route.peer_id);
            }
        }

        ret
    }

    fn get_peer_rpc_mgr(&self) -> Arc<PeerRpcManager> {
        self.get_peer_rpc_mgr()
    }
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct DstBlackListItem(PeerId, String);

#[derive(Hash, Eq, PartialEq, Clone)]
struct DstListenerUrlBlackListItem(PeerId, String);

struct DirectConnectorManagerData {
    global_ctx: ArcGlobalCtx,
    peer_manager: Arc<PeerManager>,
    dst_listener_blacklist: timedmap::TimedMap<DstListenerUrlBlackListItem, ()>,
    peer_black_list: timedmap::TimedMap<PeerId, ()>,
}

impl DirectConnectorManagerData {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Self {
        Self {
            global_ctx,
            peer_manager,
            dst_listener_blacklist: timedmap::TimedMap::new(),
            peer_black_list: timedmap::TimedMap::new(),
        }
    }

    #[cfg(feature = "mpquic")]
    fn udp_direct_enabled(&self) -> bool {
        mp_udp_provider_enabled(&self.global_ctx.get_flags(), "udp-direct")
    }

    #[cfg(not(feature = "mpquic"))]
    fn udp_direct_enabled(&self) -> bool {
        false
    }

    /// `mp.egress_devices`: each listed NIC gets its own udp-direct path.
    #[cfg(feature = "mpquic")]
    fn udp_direct_egress_devices(&self) -> Vec<String> {
        self.global_ctx
            .get_flags()
            .mp
            .map(|mp| mp.egress_devices)
            .unwrap_or_default()
    }

    /// The NICs still missing a live udp-direct path to `peer_id`; `[None]`
    /// stands for the OS-routed path when no NIC is configured.
    #[cfg(feature = "mpquic")]
    async fn missing_udp_direct_devices(&self, peer_id: PeerId) -> Vec<Option<String>> {
        let live = self
            .peer_manager
            .get_mp_session_manager()
            .live_carrier_devices(peer_id, CarrierKind::UdpDirect)
            .await;
        missing_udp_direct_devices(&self.udp_direct_egress_devices(), &live)
    }

    async fn has_live_udp_direct_carrier(&self, peer_id: PeerId) -> bool {
        #[cfg(feature = "mpquic")]
        {
            self.missing_udp_direct_devices(peer_id).await.is_empty()
        }

        #[cfg(not(feature = "mpquic"))]
        {
            let _ = peer_id;
            false
        }
    }

    /// A udp-direct carrier only exists towards a peer that runs MP; any other
    /// peer is done once directly connected, as before MP.
    async fn udp_direct_wanted_for(&self, peer_id: PeerId) -> bool {
        self.udp_direct_enabled()
            && super::peer_runs_mp(
                self.peer_manager
                    .get_peer_map()
                    .get_route_peer_info(peer_id)
                    .await
                    .and_then(|info| info.feature_flag)
                    .as_ref(),
            )
    }

    async fn direct_goal_satisfied(&self, peer_id: PeerId) -> bool {
        should_skip_existing_direct_peer(
            self.peer_manager.has_directly_connected_conn(peer_id),
            self.udp_direct_wanted_for(peer_id).await,
            self.has_live_udp_direct_carrier(peer_id).await,
        )
    }

    #[cfg(feature = "mpquic")]
    async fn try_udp_direct_candidate(
        &self,
        dst_peer_id: PeerId,
        remote_ip: Ipv4Addr,
        egress_device: Option<&str>,
    ) -> Result<(), Error> {
        let global_ctx = self.peer_manager.get_global_ctx();
        let rpc_stub = self
            .peer_manager
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<UdpHolePunchRpcClientFactory<BaseController>>(
            self.peer_manager.my_peer_id(),
            dst_peer_id,
            global_ctx.get_network_name(),
        );
        let response = rpc_stub
            .select_punch_listener(
                BaseController::default(),
                SelectPunchListenerRequest {
                    force_new: true,
                    prefer_port_mapping: false,
                    use_mp: true,
                    requester_peer_id: self.peer_manager.my_peer_id(),
                    mp_provider: "udp-direct".into(),
                },
            )
            .await
            .with_context(|| format!("select raw UDP direct listener from peer {dst_peer_id}"))?;
        if !response.mp_accepted {
            return Err(
                anyhow::anyhow!("peer {dst_peer_id} rejected the udp-direct MP provider").into(),
            );
        }
        let listener_mapped_addr = response
            .listener_mapped_addr
            .ok_or_else(|| anyhow::anyhow!("udp-direct response missing mapped listener"))?;
        let listener_local_addr = response
            .listener_local_addr
            .ok_or_else(|| anyhow::anyhow!("udp-direct response missing local listener"))?;
        let listener_local_addr = SocketAddr::from(listener_local_addr);
        let remote_addr = SocketAddr::new(IpAddr::V4(remote_ip), listener_local_addr.port());

        let socket = match egress_device {
            // Bound like a manual MP path (`mp_manual.rs`) to the NIC's own address and the
            // NIC, so it leaves through that NIC; `bind` binds no device for 0.0.0.0.
            Some(device) => Arc::new(
                bind::<UdpSocket>()
                    .addr(SocketAddr::from((
                        {
                            let _guard = global_ctx.net_ns.guard();
                            get_interface_ipv4_by_name(device)
                        }
                        .ok_or_else(|| anyhow::anyhow!("egress device {device} has no IPv4"))?,
                        0,
                    )))
                    .dev(device)
                    .net_ns(global_ctx.net_ns.clone())
                    .maybe_socket_mark(global_ctx.get_flags().socket_mark)
                    .call()
                    .map_err(anyhow::Error::new)?,
            ),
            None => {
                let _guard = global_ctx.net_ns.guard();
                Arc::new(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?)
            }
        };
        socket.connect(remote_addr).await?;
        let local_addr = socket.local_addr()?;
        let transaction_id = rand::random();
        socket
            .send(&new_hole_punch_packet(transaction_id, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes())
            .await?;

        let requester_peer_id = self.peer_manager.my_peer_id();
        let _punch_task = AbortOnDropHandle::new(tokio::spawn(async move {
            rpc_stub
                .send_punch_packet_cone(
                    BaseController {
                        timeout_ms: 5000,
                        ..Default::default()
                    },
                    SendPunchPacketConeRequest {
                        listener_mapped_addr: Some(listener_mapped_addr),
                        dest_addr: Some(local_addr.into()),
                        transaction_id,
                        packet_count_per_batch: 2,
                        packet_batch_count: 5,
                        packet_interval_ms: 200,
                        use_mp: true,
                        requester_peer_id,
                        mp_provider: "udp-direct".into(),
                        mp_alt_dest_ips: Vec::new(),
                    },
                )
                .await
        }));

        let observed_remote =
            wait_for_hole_punch_packet(&socket, transaction_id, std::time::Duration::from_secs(3))
                .await?;
        if observed_remote != remote_addr {
            return Err(anyhow::anyhow!(
                "udp-direct endpoint changed from {remote_addr} to {observed_remote}"
            )
            .into());
        }

        // The peer's handoff is the TQUIC server (`spawn_confirmed_raw_mp_server_handoff`),
        // so this end must be the client whatever the peer ids: with the peer-id default,
        // a higher-id caller was a server too and both waited out the establishment.
        let carrier = EstablishedUdpCarrier::new(
            socket,
            observed_remote,
            "udp-direct",
            Some(UdpPunchRole::Client),
            None,
        )
        .with_egress_device(egress_device.map(str::to_owned));
        match finish_established(&self.peer_manager, dst_peer_id, true, carrier).await?
        {
            UdpMpFinishOutcome::NewTunnel { tunnel, mp_role } => {
                attach_new_tunnel(
                    &self.peer_manager,
                    dst_peer_id,
                    tunnel,
                    mp_role,
                    UdpPunchRole::Client,
                    true,
                )
                .await?;
            }
            UdpMpFinishOutcome::PathAdded => {}
        }

        Ok(())
    }

    #[cfg(feature = "mpquic")]
    async fn try_udp_direct_paths(
        &self,
        dst_peer_id: PeerId,
        ip_list: &GetIpListResponse,
    ) -> Result<usize, Error> {
        if !self.udp_direct_enabled() {
            return Ok(0);
        }
        let mut succeeded = 0;
        let mut last_error = None;
        for device in self.missing_udp_direct_devices(dst_peer_id).await {
            for candidate in udp_direct_ipv4_candidates(ip_list, 0, TESTING.load(Ordering::Relaxed))
            {
                let SocketAddr::V4(candidate) = candidate else {
                    continue;
                };
                match self
                    .try_udp_direct_candidate(dst_peer_id, *candidate.ip(), device.as_deref())
                    .await
                {
                    Ok(()) => succeeded += 1,
                    Err(error) => {
                        tracing::debug!(
                            ?error,
                            ?dst_peer_id,
                            ?device,
                            remote_ip = %candidate.ip(),
                            "udp-direct candidate failed"
                        );
                        last_error = Some(error);
                    }
                }
            }
        }
        if succeeded == 0
            && let Some(error) = last_error
        {
            return Err(error);
        }
        Ok(succeeded)
    }

    async fn remote_send_udp_hole_punch_packet(
        &self,
        dst_peer_id: PeerId,
        connector_addr: SocketAddr,
        remote_url: &url::Url,
    ) -> Result<(), Error> {
        if !matches_scheme!(remote_url, TunnelScheme::Ip(IpScheme::Udp)) {
            return Err(anyhow::anyhow!(
                "udp hole punch packet only applies to udp listener: {}",
                remote_url
            )
            .into());
        }

        let global_ctx = self.peer_manager.get_global_ctx();
        let listener_port = mapped_listener_port(remote_url).ok_or(anyhow::anyhow!(
            "failed to parse port from remote url: {}",
            remote_url
        ))?;

        let rpc_stub = self
            .peer_manager
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<DirectConnectorRpcClientFactory<BaseController>>(
            self.peer_manager.my_peer_id(),
            dst_peer_id,
            global_ctx.get_network_name(),
        );

        rpc_stub
            .send_udp_hole_punch_packet(
                BaseController::default(),
                SendUdpHolePunchPacketRequest {
                    listener_port: listener_port as u32,
                    connector_addr: Some(connector_addr.into()),
                },
            )
            .await
            .with_context(|| {
                format!(
                    "do rpc, send udp hole punch packet to peer {} at {}",
                    dst_peer_id, remote_url
                )
            })?;

        Ok(())
    }

    async fn connect_to_public_ipv6(
        &self,
        dst_peer_id: PeerId,
        remote_url: &url::Url,
    ) -> Result<(PeerId, PeerConnId), Error> {
        let local_socket = Arc::new(
            UdpSocket::bind("[::]:0")
                .await
                .with_context(|| format!("failed to bind local socket for {}", remote_url))?,
        );
        let connector_ip = self
            .global_ctx
            .get_stun_info_collector()
            .get_stun_info()
            .public_ip
            .iter()
            .filter_map(|ip| ip.parse::<Ipv6Addr>().ok())
            .find(|ip| !self.global_ctx.is_ip_easytier_managed_ipv6(ip));

        // ask remote to send v6 hole punch packet
        // and no matter what the result is, continue to connect
        if let Some(connector_ip) = connector_ip {
            let connector_addr =
                SocketAddr::new(IpAddr::V6(connector_ip), local_socket.local_addr()?.port());
            let _ = self
                .remote_send_udp_hole_punch_packet(dst_peer_id, connector_addr, remote_url)
                .await;
        } else {
            tracing::debug!(
                ?remote_url,
                "skip remote IPv6 hole-punch packet; no non-EasyTier public IPv6 in STUN info"
            );
        }

        let udp_connector = UdpTunnelConnector::new(remote_url.clone());
        let remote_addr = SocketAddr::from_url(remote_url.clone(), IpVersion::V6).await?;
        let ret = udp_connector
            .try_connect_with_socket(local_socket, remote_addr)
            .await?;

        // NOTICE: must add as directly connected tunnel
        self.peer_manager
            .add_client_tunnel_with_peer_id_hint(ret, true, Some(dst_peer_id))
            .await
    }

    async fn connect_to_public_ipv4(
        &self,
        dst_peer_id: PeerId,
        remote_url: &url::Url,
    ) -> Result<(PeerId, PeerConnId), Error> {
        let local_socket = {
            let _g = self.global_ctx.net_ns.guard();
            Arc::new(
                UdpSocket::bind("0.0.0.0:0")
                    .await
                    .with_context(|| format!("failed to bind local socket for {}", remote_url))?,
            )
        };
        let connector_addr = self
            .peer_manager
            .get_global_ctx()
            .get_stun_info_collector()
            .get_udp_port_mapping_with_socket(local_socket.clone())
            .await
            .with_context(|| format!("failed to get udp port mapping for {}", remote_url))?;

        let _ = self
            .remote_send_udp_hole_punch_packet(dst_peer_id, connector_addr, remote_url)
            .await;

        let udp_connector = UdpTunnelConnector::new(remote_url.clone());
        let remote_addr = SocketAddr::from_url(remote_url.clone(), IpVersion::V4).await?;
        let ret = udp_connector
            .try_connect_with_socket(local_socket, remote_addr)
            .await?;

        self.peer_manager
            .add_client_tunnel_with_peer_id_hint(ret, true, Some(dst_peer_id))
            .await
    }

    async fn do_try_connect_to_ip(&self, dst_peer_id: PeerId, addr: String) -> Result<(), Error> {
        let connector = create_connector_by_url(&addr, &self.global_ctx, IpVersion::Both).await?;
        let remote_url = connector.remote_url();
        let (peer_id, conn_id) = if matches_scheme!(remote_url, TunnelScheme::Ip(IpScheme::Udp)) {
            match remote_url.host() {
                Some(Host::Ipv6(_)) => {
                    self.connect_to_public_ipv6(dst_peer_id, &remote_url)
                        .await?
                }
                Some(Host::Ipv4(ip)) if is_public_ipv4(ip) => {
                    match self.connect_to_public_ipv4(dst_peer_id, &remote_url).await {
                        Ok(ret) => ret,
                        Err(err) => {
                            tracing::debug!(
                                ?err,
                                %remote_url,
                                "udp public ipv4 listener punch failed, falling back to direct connect"
                            );
                            timeout(
                                std::time::Duration::from_secs(3),
                                self.peer_manager.try_direct_connect_with_peer_id_hint(
                                    connector,
                                    Some(dst_peer_id),
                                ),
                            )
                            .await??
                        }
                    }
                }
                _ => {
                    timeout(
                        std::time::Duration::from_secs(3),
                        self.peer_manager
                            .try_direct_connect_with_peer_id_hint(connector, Some(dst_peer_id)),
                    )
                    .await??
                }
            }
        } else {
            timeout(
                std::time::Duration::from_secs(3),
                self.peer_manager
                    .try_direct_connect_with_peer_id_hint(connector, Some(dst_peer_id)),
            )
            .await??
        };

        if peer_id != dst_peer_id && !TESTING.load(Ordering::Relaxed) {
            tracing::info!(
                "connect to ip succ: {}, but peer id mismatch, expect: {}, actual: {}",
                addr,
                dst_peer_id,
                peer_id
            );
            self.peer_manager.close_peer_conn(peer_id, &conn_id).await?;
            return Err(Error::InvalidUrl(addr));
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn try_connect_to_ip(
        self: Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
        addr: String,
    ) -> Result<(), Error> {
        let mut rand_gen = rand::rngs::OsRng;
        let backoff_ms = [1000, 2000, 4000];
        let mut backoff_idx = 0;

        tracing::debug!(?dst_peer_id, ?addr, "try_connect_to_ip start");

        self.dst_listener_blacklist.cleanup();

        if self
            .dst_listener_blacklist
            .contains(&DstListenerUrlBlackListItem(dst_peer_id, addr.clone()))
        {
            return Err(Error::UrlInBlacklist);
        }

        loop {
            if self.peer_manager.has_directly_connected_conn(dst_peer_id) {
                return Ok(());
            }

            tracing::debug!(?dst_peer_id, ?addr, "try_connect_to_ip start one round");
            let ret = self.do_try_connect_to_ip(dst_peer_id, addr.clone()).await;
            tracing::debug!(?ret, ?dst_peer_id, ?addr, "try_connect_to_ip return");
            if ret.is_ok() {
                return Ok(());
            }

            if self.peer_manager.has_directly_connected_conn(dst_peer_id) {
                return Ok(());
            }

            if backoff_idx < backoff_ms.len() {
                let delta = backoff_ms[backoff_idx] >> 1;
                assert!(delta > 0);
                assert!(delta < backoff_ms[backoff_idx]);

                tokio::time::sleep(Duration::from_millis(
                    (backoff_ms[backoff_idx] + rand_gen.gen_range(-delta..delta)) as u64,
                ))
                .await;

                backoff_idx += 1;
                continue;
            } else {
                self.dst_listener_blacklist.insert(
                    DstListenerUrlBlackListItem(dst_peer_id, addr),
                    (),
                    std::time::Duration::from_secs(DIRECT_CONNECTOR_BLACKLIST_TIMEOUT_SEC),
                );
                return ret;
            }
        }
    }

    async fn spawn_direct_connect_task(
        self: &Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
        ip_list: &GetIpListResponse,
        listener: &url::Url,
        tasks: &mut JoinSet<Result<(), Error>>,
    ) {
        let Ok(mut addrs) = resolve_mapped_listener_addrs(listener).await else {
            tracing::error!(?listener, "failed to parse socket address from listener");
            return;
        };
        let listener_host = addrs.pop();
        tracing::info!(?listener_host, ?listener, "try direct connect to peer");

        let is_udp = matches_protocol!(listener, Protocol::UDP);
        // Snapshot running listeners once; used for cheap port pre-checks before the
        // expensive should_deny_proxy call (which binds a socket per IP) in the
        // unspecified-address expansion loops below.
        let local_listeners = self.global_ctx.get_running_listeners();
        let port_has_local_listener = |port: u16| -> bool {
            local_listeners
                .iter()
                .any(|l| l.port() == Some(port) && matches_protocol!(l, Protocol::UDP) == is_udp)
        };

        match listener_host {
            Some(SocketAddr::V4(s_addr)) => {
                if s_addr.ip().is_unspecified() {
                    // Only pay the should_deny_proxy cost (bind per IP) when a local
                    // listener actually uses this port+protocol; otherwise the check
                    // can never return true.
                    let check_self = port_has_local_listener(s_addr.port());
                    ip_list
                        .interface_ipv4s
                        .iter()
                        .chain(ip_list.public_ipv4.iter())
                        .for_each(|ip| {
                            let sock_addr = SocketAddr::new(
                                IpAddr::V4(std::net::Ipv4Addr::from(ip.addr)),
                                s_addr.port(),
                            );
                            if check_self && self.global_ctx.should_deny_proxy(&sock_addr, is_udp) {
                                tracing::debug!(
                                    ?ip,
                                    ?listener,
                                    "skip self-connection (0.0.0.0 expansion)"
                                );
                                return;
                            }
                            let mut addr = (*listener).clone();
                            if addr.set_host(Some(ip.to_string().as_str())).is_ok() {
                                tasks.spawn(Self::try_connect_to_ip(
                                    self.clone(),
                                    dst_peer_id,
                                    addr.to_string(),
                                ));
                            } else {
                                tracing::error!(
                                    ?ip,
                                    ?listener,
                                    ?dst_peer_id,
                                    "failed to set host for interface ipv4"
                                );
                            }
                        });
                } else if !s_addr.ip().is_loopback() || TESTING.load(Ordering::Relaxed) {
                    if self
                        .global_ctx
                        .should_deny_proxy(&SocketAddr::from(s_addr), is_udp)
                    {
                        tracing::debug!(?listener, "skip self-connection (specific IPv4)");
                    } else {
                        tasks.spawn(Self::try_connect_to_ip(
                            self.clone(),
                            dst_peer_id,
                            listener.to_string(),
                        ));
                    }
                }
            }
            Some(SocketAddr::V6(s_addr)) => {
                if s_addr.ip().is_unspecified() {
                    // for ipv6, only try public ip
                    // Same port pre-check as IPv4: avoid binding per IP when no local
                    // listener uses this port+protocol.
                    let check_self = port_has_local_listener(s_addr.port());
                    ip_list
                        .interface_ipv6s
                        .iter()
                        .chain(ip_list.public_ipv6.iter())
                        .filter_map(|x| Ipv6Addr::from_str(&x.to_string()).ok())
                        .filter(|x| is_usable_public_ipv6_candidate(x, &self.global_ctx))
                        .collect::<HashSet<_>>()
                        .iter()
                        .for_each(|ip| {
                            let sock_addr = SocketAddr::new(IpAddr::V6(*ip), s_addr.port());
                            if check_self && self.global_ctx.should_deny_proxy(&sock_addr, is_udp) {
                                tracing::debug!(
                                    ?ip,
                                    ?listener,
                                    "skip self-connection (:: expansion)"
                                );
                                return;
                            }
                            let mut addr = (*listener).clone();
                            if addr.set_host(Some(format!("[{}]", ip).as_str())).is_ok() {
                                tasks.spawn(Self::try_connect_to_ip(
                                    self.clone(),
                                    dst_peer_id,
                                    addr.to_string(),
                                ));
                            } else {
                                tracing::error!(
                                    ?ip,
                                    ?listener,
                                    ?dst_peer_id,
                                    "failed to set host for public ipv6"
                                );
                            }
                        });
                } else if self.global_ctx.is_ip_easytier_managed_ipv6(s_addr.ip()) {
                    tracing::debug!(
                        ?listener,
                        "skip EasyTier-managed IPv6 as direct-connect target"
                    );
                } else if !s_addr.ip().is_loopback() || TESTING.load(Ordering::Relaxed) {
                    if self
                        .global_ctx
                        .should_deny_proxy(&SocketAddr::from(s_addr), is_udp)
                    {
                        tracing::debug!(?listener, "skip self-connection (specific IPv6)");
                    } else {
                        tasks.spawn(Self::try_connect_to_ip(
                            self.clone(),
                            dst_peer_id,
                            listener.to_string(),
                        ));
                    }
                }
            }
            p => {
                tracing::error!(?p, ?listener, "failed to parse ip version from listener");
            }
        }
    }

    #[tracing::instrument(skip(self))]
    async fn do_try_direct_connect_internal(
        self: &Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
        ip_list: GetIpListResponse,
    ) -> Result<(), Error> {
        #[cfg(feature = "mpquic")]
        let mut udp_direct_error = None;
        #[cfg(feature = "mpquic")]
        if self.udp_direct_enabled() && !self.has_live_udp_direct_carrier(dst_peer_id).await {
            match self.try_udp_direct_paths(dst_peer_id, &ip_list).await {
                Ok(count) if count > 0 => {
                    tracing::info!(
                        dst_peer_id,
                        count,
                        "registered UDP direct paths in the unified TQUIC session"
                    );
                    return Ok(());
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::debug!(
                        ?error,
                        dst_peer_id,
                        "UDP direct MP discovery failed; ordinary direct connectors remain available"
                    );
                    udp_direct_error = Some(error);
                }
            }
        }

        let enable_ipv6 = self.global_ctx.get_flags().enable_ipv6;
        let available_listeners = ip_list
            .listeners
            .clone()
            .into_iter()
            .map(Into::<url::Url>::into)
            .filter_map(|l| if l.scheme() != "ring" { Some(l) } else { None })
            .filter(|l| mapped_listener_port(l).is_some() && l.host().is_some())
            .filter(|l| enable_ipv6 || !matches!(l.host().unwrap().to_owned(), Host::Ipv6(_)))
            .collect::<Vec<_>>();

        tracing::debug!(?available_listeners, "got available listeners");

        if available_listeners.is_empty() {
            #[cfg(feature = "mpquic")]
            if let Some(error) = udp_direct_error {
                return Err(error);
            }
            return Err(anyhow::anyhow!("peer {} have no valid listener", dst_peer_id).into());
        }

        let default_protocol = self.global_ctx.get_flags().default_protocol;
        // sort available listeners, default protocol has the highest priority, udp is second, others just random
        // highest priority is in the last
        let mut available_listeners = available_listeners;
        available_listeners.sort_by_key(|l| {
            let scheme = l.scheme();
            if scheme == default_protocol {
                3
            } else if scheme == "udp" {
                2
            } else {
                1
            }
        });

        while !available_listeners.is_empty() {
            let mut tasks = JoinSet::new();
            let mut listener_list = vec![];

            let cur_scheme = available_listeners.last().unwrap().scheme().to_owned();
            while let Some(listener) = available_listeners.last() {
                if listener.scheme() != cur_scheme {
                    break;
                }

                tracing::debug!("try direct connect to peer with listener: {}", listener);
                self.spawn_direct_connect_task(dst_peer_id, &ip_list, listener, &mut tasks)
                    .await;

                listener_list.push(listener.clone().to_string());
                available_listeners.pop();
            }

            let ret = tasks.join_all().await;
            tracing::debug!(
                ?ret,
                ?dst_peer_id,
                ?cur_scheme,
                ?listener_list,
                "all tasks finished for current scheme"
            );

            if self.peer_manager.has_directly_connected_conn(dst_peer_id) {
                tracing::info!(
                    "direct connect to peer {} success, has direct conn",
                    dst_peer_id
                );
                return Ok(());
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn do_try_direct_connect(
        self: Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        let mut backoff =
            udp_hole_punch::BackOff::new(vec![1000, 2000, 2000, 5000, 5000, 10000, 30000, 60000]);
        let mut attempt = 0;
        loop {
            if self.peer_black_list.contains(&dst_peer_id) {
                return Err(anyhow::anyhow!("peer {} is blacklisted", dst_peer_id).into());
            }

            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(backoff.next_backoff())).await;
            }
            attempt += 1;

            let peer_manager = self.peer_manager.clone();
            tracing::debug!("try direct connect to peer: {}", dst_peer_id);

            let rpc_stub = peer_manager
                .get_peer_rpc_mgr()
                .rpc_client()
                .scoped_client::<DirectConnectorRpcClientFactory<BaseController>>(
                peer_manager.my_peer_id(),
                dst_peer_id,
                self.global_ctx.get_network_name(),
            );

            let ip_list = rpc_stub
                .get_ip_list(BaseController::default(), GetIpListRequest {})
                .await;
            let ip_list = handle_rpc_result(ip_list, dst_peer_id, &self.peer_black_list)
                .with_context(|| format!("get ip list from peer {}", dst_peer_id))?;

            tracing::info!(ip_list = ?ip_list, dst_peer_id = ?dst_peer_id, "got ip list");

            let ret = self
                .do_try_direct_connect_internal(dst_peer_id, ip_list)
                .await;
            tracing::info!(?ret, ?dst_peer_id, "do_try_direct_connect return");

            if self.direct_goal_satisfied(dst_peer_id).await {
                tracing::info!(
                    "direct connect to peer {} satisfied direct/MP carrier goal",
                    dst_peer_id
                );
                return Ok(());
            }

            if peer_manager.has_directly_connected_conn(dst_peer_id)
                && self.udp_direct_wanted_for(dst_peer_id).await
            {
                // An ordinary direct PeerConn must not permanently suppress
                // discovery of the configured UDP direct TQUIC carrier. End
                // this attempt and let the task manager retry on its cadence.
                return Ok(());
            }
        }
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_broadcast()
        && !ip.is_unspecified()
}

impl std::fmt::Debug for DirectConnectorManagerData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectConnectorManagerData")
            .field("peer_manager", &self.peer_manager)
            .finish()
    }
}

pub struct DirectConnectorManager {
    global_ctx: ArcGlobalCtx,
    data: Arc<DirectConnectorManagerData>,
    client: PeerTaskManager<DirectConnectorLauncher>,
    tasks: JoinSet<()>,
}

#[derive(Clone)]
struct DirectConnectorLauncher(Arc<DirectConnectorManagerData>);

#[async_trait::async_trait]
impl PeerTaskLauncher for DirectConnectorLauncher {
    type Data = Arc<DirectConnectorManagerData>;
    type CollectPeerItem = PeerId;
    type TaskRet = ();

    fn new_data(&self, _peer_mgr: Arc<PeerManager>) -> Self::Data {
        self.0.clone()
    }

    async fn collect_peers_need_task(&self, data: &Self::Data) -> Vec<Self::CollectPeerItem> {
        data.peer_black_list.cleanup();
        let my_peer_id = data.peer_manager.my_peer_id();
        let mut peers = Vec::new();
        for peer_id in data.peer_manager.list_peers().await {
            if peer_id == my_peer_id || data.peer_black_list.contains(&peer_id) {
                continue;
            }
            let has_direct_peer = data.peer_manager.has_directly_connected_conn(peer_id);
            let has_live_udp_direct = data.has_live_udp_direct_carrier(peer_id).await;
            if !should_skip_existing_direct_peer(
                has_direct_peer,
                data.udp_direct_wanted_for(peer_id).await,
                has_live_udp_direct,
            ) {
                peers.push(peer_id);
            }
        }
        peers
    }

    async fn launch_task(
        &self,
        data: &Self::Data,
        item: Self::CollectPeerItem,
    ) -> tokio::task::JoinHandle<Result<Self::TaskRet, anyhow::Error>> {
        let data = data.clone();
        tokio::spawn(async move { data.do_try_direct_connect(item).await.map_err(Into::into) })
    }

    async fn all_task_done(&self, _data: &Self::Data) {}

    fn loop_interval_ms(&self) -> u64 {
        5000
    }
}

impl DirectConnectorManager {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Self {
        let data = Arc::new(DirectConnectorManagerData::new(
            global_ctx.clone(),
            peer_manager.clone(),
        ));
        let client = PeerTaskManager::new_with_external_signal(
            DirectConnectorLauncher(data.clone()),
            peer_manager.clone(),
            Some(peer_manager.p2p_demand_notify()),
        );
        Self {
            global_ctx,
            data,
            client,
            tasks: JoinSet::new(),
        }
    }

    pub fn run(&mut self) {
        self.run_as_server();
        self.run_as_client();
    }

    pub fn run_as_server(&mut self) {
        self.data
            .peer_manager
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                DirectConnectorRpcServer::new(DirectConnectorManagerRpcServer::new(
                    self.global_ctx.clone(),
                )),
                &self.data.global_ctx.get_network_name(),
            );
    }

    pub fn run_as_client(&mut self) {
        self.client.start();
    }

    #[cfg(test)]
    pub(crate) async fn try_direct_connect_with_ip_list(
        &self,
        dst_peer_id: PeerId,
        ip_list: GetIpListResponse,
    ) -> Result<(), Error> {
        self.data
            .do_try_direct_connect_internal(dst_peer_id, ip_list)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc};

    use crate::{
        common::global_ctx::tests::get_mock_global_ctx,
        connector::direct::{
            DirectConnectorManager, DirectConnectorManagerData, DstListenerUrlBlackListItem,
        },
        instance::listeners::ListenerManager,
        peers::tests::{
            connect_peer_manager, create_mock_peer_manager, wait_route_appear,
            wait_route_appear_with_cost,
        },
        proto::peer_rpc::GetIpListResponse,
        tunnel::{IpScheme, TunnelScheme, matches_scheme},
    };

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{TESTING, mapped_listener_port, resolve_mapped_listener_addrs};

    #[cfg(feature = "mpquic")]
    use crate::{
        connector::{mp_path::CarrierKind, udp_hole_punch::UdpHolePunchConnector},
        tunnel::common::tests::wait_for_condition,
    };

    #[tokio::test]
    async fn public_ipv6_candidate_rejects_easytier_managed_addr_even_in_tests() {
        let global_ctx = get_mock_global_ctx();
        let managed_ipv6: cidr::Ipv6Inet = "2001:db8::2/128".parse().unwrap();
        global_ctx.set_public_ipv6_routes(BTreeSet::from([managed_ipv6]));

        assert!(!super::is_usable_public_ipv6_candidate_with_mode(
            &"2001:db8::2".parse().unwrap(),
            &global_ctx,
            true,
        ));
        assert!(super::is_usable_public_ipv6_candidate_with_mode(
            &"::1".parse().unwrap(),
            &global_ctx,
            true,
        ));
    }

    #[test]
    fn udp_ipv6_url_matches_hole_punch_branch_condition() {
        let remote_url: url::Url = "udp://[2001:db8::1]:11010".parse().unwrap();
        let takes_udp_ipv6_hole_punch_branch =
            matches_scheme!(remote_url, TunnelScheme::Ip(IpScheme::Udp))
                && matches!(remote_url.host(), Some(url::Host::Ipv6(_)));

        assert!(takes_udp_ipv6_hole_punch_branch);
    }

    /// Each NIC in `mp.egress_devices` needs its own established udp-direct
    /// path; without NICs, one OS-routed path is enough.
    #[cfg(feature = "mpquic")]
    #[test]
    fn udp_direct_keeps_trying_until_every_configured_nic_has_a_path() {
        let nics = ["a1".to_string(), "a2".to_string()];
        let a1 = Some("a1".to_string());
        assert_eq!(super::missing_udp_direct_devices(&[], &[]), vec![None]);
        assert!(super::missing_udp_direct_devices(&[], &[None]).is_empty());
        assert_eq!(
            super::missing_udp_direct_devices(&nics, &[]),
            vec![Some("a1".to_string()), Some("a2".to_string())]
        );
        assert_eq!(
            super::missing_udp_direct_devices(&nics, &[a1.clone(), None]),
            vec![Some("a2".to_string())]
        );
        assert!(
            super::missing_udp_direct_devices(&nics, &[a1, Some("a2".to_string())]).is_empty()
        );
    }

    #[test]
    fn endpoint_mp_keeps_discovering_until_a_udp_direct_carrier_exists() {
        assert!(!super::should_skip_existing_direct_peer(true, true, false));
        assert!(super::should_skip_existing_direct_peer(true, true, true));
        assert!(super::should_skip_existing_direct_peer(true, false, false));
        assert!(!super::should_skip_existing_direct_peer(false, true, false));
    }

    #[cfg(feature = "mpquic")]
    #[test]
    fn udp_direct_candidates_reject_ipv4_link_local_addresses() {
        let mut ip_list = GetIpListResponse::default();
        ip_list.public_ipv4 = Some("203.0.113.7".parse::<Ipv4Addr>().unwrap().into());
        ip_list
            .interface_ipv4s
            .push("169.254.45.58".parse::<Ipv4Addr>().unwrap().into());
        ip_list
            .interface_ipv4s
            .push("192.168.6.159".parse::<Ipv4Addr>().unwrap().into());

        let candidates = super::udp_direct_ipv4_candidates(&ip_list, 11010, false);

        assert_eq!(
            candidates.first(),
            Some(&SocketAddr::new(
                IpAddr::V4("203.0.113.7".parse().unwrap()),
                11010
            )),
            "the STUN public mapping must be the first UDP-direct candidate"
        );
        assert!(
            !candidates
                .iter()
                .any(|candidate| candidate.ip() == IpAddr::V4("169.254.45.58".parse().unwrap()))
        );
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.ip() == IpAddr::V4("192.168.6.159".parse().unwrap()))
        );
    }

    #[test]
    fn mapped_listener_port_uses_ip_scheme_defaults() {
        assert_eq!(
            mapped_listener_port(&"ws://example.com".parse().unwrap()),
            Some(80)
        );
        assert_eq!(
            mapped_listener_port(&"wss://example.com".parse().unwrap()),
            Some(443)
        );
        assert_eq!(
            mapped_listener_port(&"tcp://127.0.0.1".parse().unwrap()),
            Some(11010)
        );
        assert_eq!(
            mapped_listener_port(&"udp://127.0.0.1".parse().unwrap()),
            Some(11010)
        );
    }

    #[tokio::test]
    async fn resolve_mapped_listener_addrs_uses_default_ports() {
        let wss_addrs = resolve_mapped_listener_addrs(&"wss://127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(
            wss_addrs,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)]
        );

        let tcp_addrs = resolve_mapped_listener_addrs(&"tcp://127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(
            tcp_addrs,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 11010)]
        );
    }

    async fn run_direct_connector_mapped_listener_test(
        mapped_listener: &str,
        target_listener: &str,
    ) {
        TESTING.store(true, std::sync::atomic::Ordering::Relaxed);
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;
        let p_x = create_mock_peer_manager().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        connect_peer_manager(p_c.clone(), p_x.clone()).await;

        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();
        wait_route_appear(p_a.clone(), p_x.clone()).await.unwrap();

        let mut f = p_a.get_global_ctx().get_flags();
        f.bind_device = false;
        p_a.get_global_ctx().set_flags(f);

        p_c.get_global_ctx()
            .config
            .set_mapped_listeners(Some(vec![mapped_listener.parse().unwrap()]));

        p_x.get_global_ctx()
            .config
            .set_listeners(vec![target_listener.parse().unwrap()]);
        let mut lis_x = ListenerManager::new(p_x.get_global_ctx(), p_x.clone());
        lis_x.prepare_listeners().await.unwrap();
        lis_x.run().await.unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let mut dm_a = DirectConnectorManager::new(p_a.get_global_ctx(), p_a.clone());
        let mut dm_c = DirectConnectorManager::new(p_c.get_global_ctx(), p_c.clone());
        dm_a.run_as_client();
        dm_c.run_as_server();
        // p_c's mapped listener is p_x's listener, so p_a should connect to p_x directly

        wait_route_appear_with_cost(p_a.clone(), p_x.my_peer_id(), Some(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn direct_connector_mapped_listener() {
        run_direct_connector_mapped_listener_test("tcp://127.0.0.1:11334", "tcp://0.0.0.0:11334")
            .await;
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn direct_connector_basic_test(
        #[values("tcp", "udp", "wg")] proto: &str,
        #[values("true", "false")] ipv6: bool,
    ) {
        TESTING.store(true, std::sync::atomic::Ordering::Relaxed);

        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;

        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        p_c.get_global_ctx()
            .get_ip_collector()
            .collect_ip_addrs()
            .await;

        tokio::time::sleep(std::time::Duration::from_secs(4)).await;

        let mut dm_a = DirectConnectorManager::new(p_a.get_global_ctx(), p_a.clone());
        let mut dm_c = DirectConnectorManager::new(p_c.get_global_ctx(), p_c.clone());

        dm_a.run_as_client();
        dm_c.run_as_server();

        let port = if proto == "wg" { 11040 } else { 11041 };
        if !ipv6 {
            p_c.get_global_ctx().config.set_listeners(vec![
                format!("{}://0.0.0.0:{}", proto, port).parse().unwrap(),
            ]);
        } else {
            p_c.get_global_ctx()
                .config
                .set_listeners(vec![format!("{}://[::]:{}", proto, port).parse().unwrap()]);
        }
        let mut f = p_c.get_global_ctx().config.get_flags();
        f.enable_ipv6 = ipv6;
        p_c.get_global_ctx().set_flags(f);
        let mut lis_c = ListenerManager::new(p_c.get_global_ctx(), p_c.clone());
        lis_c.prepare_listeners().await.unwrap();

        lis_c.run().await.unwrap();

        wait_route_appear_with_cost(p_a.clone(), p_c.my_peer_id(), Some(1))
            .await
            .unwrap();
    }

    #[cfg(feature = "mpquic")]
    #[rstest::rstest]
    #[case(true)]
    #[case(false)]
    #[tokio::test]
    async fn udp_direct_provider_creates_a_real_tquic_carrier_over_discovered_endpoint(
        #[case] caller_is_tquic_server: bool,
    ) {
        TESTING.store(true, std::sync::atomic::Ordering::Relaxed);
        let endpoint_a = create_mock_peer_manager().await;
        let relay = create_mock_peer_manager().await;
        let endpoint_b = create_mock_peer_manager().await;
        let a_is_server = endpoint_a.my_peer_id() > endpoint_b.my_peer_id();
        let (caller, target) = if a_is_server == caller_is_tquic_server {
            (endpoint_a, endpoint_b)
        } else {
            (endpoint_b, endpoint_a)
        };
        for peer in [&caller, &target] {
            let mut flags = peer.get_global_ctx().get_flags();
            flags.mp.as_mut().unwrap().enabled = true;
            flags.mp.as_mut().unwrap().providers = vec!["udp-direct".into()];
            flags.disable_upnp = true;
            peer.get_global_ctx().set_flags(flags);
        }
        connect_peer_manager(caller.clone(), relay.clone()).await;
        // Keep `relay` alive: dropping the last handle tears its connections down.
        connect_peer_manager(relay.clone(), target.clone()).await;
        wait_route_appear(caller.clone(), target.clone())
            .await
            .unwrap();

        let mut udp_server = UdpHolePunchConnector::new(target.clone());
        udp_server.run_as_server().await.unwrap();
        let direct = DirectConnectorManager::new(caller.get_global_ctx(), caller.clone());
        let mut ip_list = GetIpListResponse::default();
        ip_list.interface_ipv4s.push(Ipv4Addr::LOCALHOST.into());

        direct
            .try_direct_connect_with_ip_list(target.my_peer_id(), ip_list)
            .await
            .unwrap();

        wait_for_condition(
            || async {
                caller
                    .get_mp_session_manager()
                    .has_live_carrier(target.my_peer_id(), CarrierKind::UdpDirect)
                    .await
                    && target
                        .get_mp_session_manager()
                        .has_live_carrier(caller.my_peer_id(), CarrierKind::UdpDirect)
                        .await
            },
            std::time::Duration::from_secs(10),
        )
        .await;
        wait_route_appear_with_cost(caller.clone(), target.my_peer_id(), Some(1))
            .await
            .unwrap();
    }

    #[cfg(feature = "mpquic")]
    #[tokio::test]
    async fn udp_direct_provider_does_not_retry_an_already_direct_non_mp_peer() {
        use crate::peers::peer_task::PeerTaskLauncher;

        let local = create_mock_peer_manager().await;
        let plain = create_mock_peer_manager().await;
        let mut flags = local.get_global_ctx().get_flags();
        flags.mp.as_mut().unwrap().enabled = true;
        flags.mp.as_mut().unwrap().providers = vec!["udp-direct".into()];
        local.get_global_ctx().set_flags(flags);
        let (client_ring, server_ring) = crate::tunnel::ring::create_ring_tunnel_pair();
        let client = local.clone();
        tokio::spawn(async move { client.add_client_tunnel(client_ring, true).await.unwrap() });
        let server = plain.clone();
        tokio::spawn(async move { server.add_tunnel_as_server(server_ring, true).await.unwrap() });
        wait_route_appear(local.clone(), plain.clone()).await.unwrap();
        wait_for_condition(
            || {
                let local = local.clone();
                let plain_id = plain.my_peer_id();
                async move { local.has_directly_connected_conn(plain_id) }
            },
            std::time::Duration::from_secs(10),
        )
        .await;

        let data = Arc::new(DirectConnectorManagerData::new(
            local.get_global_ctx(),
            local.clone(),
        ));
        let launcher = super::DirectConnectorLauncher(data.clone());

        assert!(
            !launcher
                .collect_peers_need_task(&data)
                .await
                .contains(&plain.my_peer_id()),
            "a direct peer without MP can never hold a udp-direct carrier"
        );
        assert!(data.direct_goal_satisfied(plain.my_peer_id()).await);
    }

    #[tokio::test]
    async fn direct_connector_scheme_blacklist() {
        TESTING.store(true, std::sync::atomic::Ordering::Relaxed);
        let p_a = create_mock_peer_manager().await;
        let data = Arc::new(DirectConnectorManagerData::new(
            p_a.get_global_ctx(),
            p_a.clone(),
        ));
        let mut ip_list = GetIpListResponse::default();
        ip_list
            .listeners
            .push("tcp://127.0.0.1:10222".parse().unwrap());

        ip_list
            .interface_ipv4s
            .push("127.0.0.1".parse::<std::net::Ipv4Addr>().unwrap().into());

        data.do_try_direct_connect_internal(1, ip_list.clone())
            .await
            .unwrap();

        assert!(
            data.dst_listener_blacklist
                .contains(&DstListenerUrlBlackListItem(
                    1,
                    "tcp://127.0.0.1:10222".parse().unwrap()
                ))
        );
    }
}

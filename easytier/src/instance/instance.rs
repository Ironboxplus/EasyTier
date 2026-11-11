use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
#[cfg(feature = "tun")]
use std::time::Duration;

use anyhow::Context;
use cidr::{IpCidr, Ipv4Inet};
use futures::FutureExt;
use tokio::sync::{Mutex, Notify};
#[cfg(feature = "tun")]
use tokio::{sync::oneshot, task::JoinSet};
#[cfg(feature = "magic-dns")]
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

use crate::common::PeerId;
use crate::common::acl_processor::AclRuleBuilder;
use crate::common::config::ConfigLoader;
use crate::common::error::Error;
use crate::common::egress_inventory::EgressStableId;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtx, GlobalCtxEvent};
use crate::common::transport_quality::rate::WireBitrate;
use crate::connector::direct::DirectConnectorManager;
use crate::connector::manual::{ConnectorManagerRpcService, ManualConnectorManager};
use crate::connector::tcp_hole_punch::TcpHolePunchConnector;
use crate::connector::udp_hole_punch::UdpHolePunchConnector;
use crate::gateway::icmp_proxy::IcmpProxy;
#[cfg(feature = "kcp")]
use crate::gateway::kcp_proxy::{KcpProxyDst, KcpProxyDstRpcService, KcpProxySrc};
#[cfg(feature = "quic")]
use crate::gateway::quic_proxy::{QuicProxy, QuicProxyDstRpcService};
use crate::gateway::tcp_proxy::{NatDstTcpConnector, TcpProxy, TcpProxyRpcService};
use crate::gateway::udp_proxy::UdpProxy;
use crate::peer_center::instance::{PeerCenterInstance, PeerCenterInstanceService};
use crate::peers::peer_conn::PeerConnId;
use crate::peers::peer_manager::{PeerManager, RouteAlgoType};
#[cfg(feature = "tun")]
use crate::peers::recv_packet_from_chan;
use crate::peers::rpc_service::PeerManagerRpcService;
use crate::peers::{PacketRecvChanReceiver, create_packet_recv_chan};
use crate::proto::api::config::{
    ConfigPatchAction, ConfigRpc, GetConfigRequest, GetConfigResponse, MpSchedulerPluginSchema,
    MpTunableSchema, PatchConfigRequest, PatchConfigResponse, PortForwardPatch,
};
use crate::proto::api::instance::{
    GetPrometheusStatsRequest, GetPrometheusStatsResponse, GetStatsRequest, GetStatsResponse,
    GetVpnPortalInfoRequest, GetVpnPortalInfoResponse, ListMappedListenerRequest,
    ListMappedListenerResponse, ListPortForwardRequest, ListPortForwardResponse, MappedListener,
    MappedListenerManageRpc, MetricSnapshot, PortForwardManageRpc, StatsRpc, VpnPortalInfo,
    VpnPortalRpc,
};
#[cfg(feature = "mpquic")]
use crate::proto::api::instance::{
    MpEgressResourceStatus, MpPathIdentity, MpPathStatus, MpPeerStatus,
};
use crate::proto::api::manage::NetworkConfig;
use crate::proto::common::{PortForwardConfigPb, TunnelInfo};
use crate::proto::peer_rpc::PeerCenterRpc;
use crate::proto::rpc_impl::standalone::RpcServerHook;
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::rpc_service::InstanceRpcService;
use crate::utils::{debug_name_to_kebab, weak_upgrade};
use crate::vpn_portal::{self, VpnPortal};

#[cfg(feature = "magic-dns")]
use super::dns_server::{MAGIC_DNS_FAKE_IP, runner::DnsRunner};
use super::listeners::ListenerManager;
use super::public_ipv6_provider::{
    reconcile_public_ipv6_provider_runtime, run_public_ipv6_provider_reconcile_task,
    should_run_public_ipv6_provider_reconcile, validate_public_ipv6_config,
    validate_public_ipv6_config_values,
};

#[cfg(feature = "socks5")]
use crate::gateway::socks5::Socks5Server;

fn mp_scheduler_plugin_schemas() -> Vec<MpSchedulerPluginSchema> {
    // MP_SQM_PLAN.md S2.7: schedulers and congestion controls from the one
    // registry, in the same shape as the GUI snapshot `mp_plugins.json`.
    crate::tunnel::mp_plugin::MpPluginRegistry::with_builtins()
        .schema()
        .into_iter()
        .map(|plugin| MpSchedulerPluginSchema {
            name: plugin.name,
            description: plugin.description,
            kind: plugin.kind.as_str().to_string(),
            tunables: plugin
                .tunables
                .into_iter()
                .map(|tunable| {
                    let (kind, min, max, step, options) = tunable.kind.gui_parts();
                    MpTunableSchema {
                        key: tunable.key,
                        label: tunable.label,
                        kind: kind.to_string(),
                        min,
                        max,
                        step,
                        options,
                        default_json: serde_json::to_string(&tunable.default)
                            .unwrap_or_else(|_| "null".to_string()),
                        help: tunable.help,
                    }
                })
                .collect(),
        })
        .collect()
}

#[cfg(feature = "mpquic")]
fn mp_path_identity(key: crate::tunnel::mpquic::PathKey) -> MpPathIdentity {
    MpPathIdentity {
        carrier_id: key.carrier_id.0 as u64,
        local_addr: key.local_addr.to_string(),
        remote_addr: key.remote_addr.to_string(),
    }
}

#[cfg(feature = "mpquic")]
fn mp_path_status_from_snapshot(
    snapshot: crate::connector::mp_session::MpPathRuntimeSnapshot,
) -> MpPathStatus {
    let telemetry = snapshot.telemetry.as_ref();
    let relay_metadata = snapshot.relay_metadata;
    MpPathStatus {
        path: Some(mp_path_identity(snapshot.key)),
        carrier_kind: debug_name_to_kebab(snapshot.carrier_kind),
        lifecycle_state: snapshot.state.as_str().to_string(),
        local_resource: snapshot.local_resource.as_str().to_string(),
        local_resource_kind: debug_name_to_kebab(snapshot.local_resource.kind()),
        remote_resource: snapshot.remote_resource.as_str().to_string(),
        remote_resource_kind: debug_name_to_kebab(snapshot.remote_resource.kind()),
        btlbw_bps: telemetry
            .map(|path| path.btlbw)
            .unwrap_or(snapshot.measurements.btlbw),
        delivery_rate_bps: telemetry
            .map(|path| path.delivery_rate)
            .unwrap_or(snapshot.measurements.delivery_rate),
        srtt_micros: telemetry
            .map(|path| path.srtt_micros)
            .unwrap_or(snapshot.measurements.propagation_rtt_micros),
        loss_rate: snapshot.measurements.loss_rate,
        app_limited: telemetry
            .map(|path| path.app_limited)
            .unwrap_or(snapshot.measurements.app_limited),
        sample_age_micros: telemetry
            .and_then(|path| path.sample_age_micros)
            .or(snapshot.measurements.sample_age_micros),
        congestion_control_state: telemetry
            .map(|path| debug_name_to_kebab(path.congestion_control_state))
            .unwrap_or_else(|| debug_name_to_kebab(snapshot.measurements.congestion_control_state)),
        target_rate_bps: snapshot.target_rate_bps,
        // Relay-next-hop virtual ULA paths often stay in TQUIC ValidatingMTU
        // because the 1200-byte PMTU probe cannot complete over EasyTier
        // encapsulation. Once our lifecycle has accepted the path (peer
        // reachability proven), export validation as validated so operators
        // and dual-path gates see the effective state.
        validation_state: {
            let raw = telemetry
                .map(|path| debug_name_to_kebab(path.validation_state))
                .unwrap_or_default();
            let is_relay = matches!(
                snapshot.carrier_kind,
                crate::connector::mp_path::CarrierKind::RelayNextHop
            );
            let lifecycle_accepted = snapshot.state.is_established();
            if is_relay
                && lifecycle_accepted
                && (raw == "validating-m-t-u" || raw == "validatingmtu" || raw.is_empty())
            {
                "validated".to_string()
            } else {
                raw
            }
        },
        bandwidth_model_valid: telemetry.is_some_and(|path| path.bandwidth_model_valid),
        min_rtt_micros: telemetry
            .map(|path| path.min_rtt_micros)
            .unwrap_or_default(),
        sent_bytes: telemetry.map(|path| path.sent_bytes).unwrap_or_default(),
        recv_bytes: telemetry.map(|path| path.recv_bytes).unwrap_or_default(),
        lost_bytes: telemetry.map(|path| path.lost_bytes).unwrap_or_default(),
        first_hop_peer_id: relay_metadata.map(|metadata| metadata.first_hop_peer_id as u64),
        egress_first_hop_peer_id: relay_metadata
            .map(|metadata| metadata.egress_first_hop_peer_id as u64),
        route_generation: relay_metadata.map(|metadata| metadata.route_generation),
        cwnd_bytes: telemetry.map(|path| path.cwnd_bytes).unwrap_or_default(),
        pacing_rate_bps: telemetry
            .map(|path| path.pacing_rate_bps)
            .unwrap_or_default(),
        // TQUIC exposes no live current-inflight gauge, only this
        // high-water mark (`tquic::PathStats::max_inflight`). Best real
        // (non-fabricated) value available; documented on the telemetry
        // field itself.
        bytes_in_flight: telemetry
            .map(|path| path.max_inflight_bytes)
            .unwrap_or_default(),
        // MP_SQM_PLAN.md S2.4 lands Brutal ack-rate negotiation.
        brutal_ack_rate: None,
        user_policy: snapshot.user_policy,
        egress_device: snapshot.egress_device,
        observed_public_addr: telemetry
            .and_then(|path| path.observed_local_addr)
            .or(snapshot.measurements.observed_local_addr)
            .map(|addr| addr.to_string())
            .unwrap_or_default(),
        windowed_min_rtt_micros: telemetry
            .map(|path| path.windowed_min_rtt_micros)
            .unwrap_or_default(),
        recent_loss: snapshot.selection.recent_loss,
        first_hop_loss: snapshot.selection.first_hop_loss,
        backed_off: telemetry.is_some_and(|path| path.backed_off),
        not_selected_reason: snapshot.selection.not_selected_reason,
        tier: snapshot.selection.tier,
        rtt_bias_micros: snapshot.selection.rtt_bias_micros,
        ranked_rtt_micros: snapshot.selection.ranked_rtt_micros,
        selected: snapshot.selection.selected,
    }
}

#[cfg(feature = "mpquic")]
fn mp_peer_status_from_snapshot(
    snapshot: crate::connector::mp_session::MpPeerRuntimeSnapshot,
) -> MpPeerStatus {
    let path_count = snapshot.paths.len();
    let scheduler_state = crate::common::transport_quality::SchedulerState::for_path_count(
        path_count.min(u32::MAX as usize) as u32,
    );
    let (candidate_count, eligible_count, active_paths) =
        if let Some(optimization) = snapshot.optimization {
            (
                optimization.candidate_count.min(u32::MAX as usize) as u32,
                optimization.eligible_count.min(u32::MAX as usize) as u32,
                optimization
                    .active_paths
                    .into_iter()
                    .map(mp_path_identity)
                    .collect(),
            )
        } else {
            (
                snapshot.paths.len().min(u32::MAX as usize) as u32,
                0,
                Vec::new(),
            )
        };
    MpPeerStatus {
        peer_id: u64::from(snapshot.peer_id),
        candidate_count,
        eligible_count,
        paths: snapshot
            .paths
            .into_iter()
            .map(mp_path_status_from_snapshot)
            .collect(),
        active_paths,
        effective_engine: "tquic".to_string(),
        effective_congestion_control: if snapshot.effective_congestion_control.is_empty() {
            "engine-default".to_string()
        } else {
            snapshot.effective_congestion_control
        },
        path_mode: if path_count > 1 { "n>1" } else { "n=1" }.to_string(),
        scheduler_state: match scheduler_state {
            crate::common::transport_quality::SchedulerState::NoChoiceSinglePath => {
                "no-choice-single-path"
            }
            crate::common::transport_quality::SchedulerState::ActiveMultipath => "active-multipath",
        }
        .to_string(),
        unsupported_reason: None,
        // MP_SQM_PLAN.md S2.6: real data now, computed in
        // `MpSessionManager::runtime_snapshots` from the live session's
        // captured congestion control vs. the currently configured one.
        desired_congestion_control: snapshot.desired_congestion_control,
        reconnect_required: snapshot.reconnect_required,
        standalone: snapshot.standalone,
        effective_recovery: "tquic-rfc9002".to_string(),
        brutal_tx_bps: snapshot.brutal_tx_bps,
        peer_advertised_rx_bps: snapshot.peer_advertised_rx_bps,
        // MP_SQM_PLAN.md S2.10: straight from the session driver.
        data_plane: snapshot.data_plane,
        faketcp_upgrade: snapshot.faketcp_upgrade.map(|record| {
            crate::proto::api::instance::MpFakeTcpUpgradeStatus {
                plain_tcp_fallback: record.plain_tcp_fallback(std::time::Instant::now()),
                failures: record.failures,
                consecutive_failures: record.consecutive_failures,
                last_error: record.last_error,
            }
        }),
        switch_threshold_micros: snapshot.switch_threshold_micros,
        active_tier: snapshot.active_tier,
    }
}

#[cfg(feature = "mpquic")]
fn mp_egress_status_from_snapshot(
    snapshot: crate::connector::mp_session::EgressResourceEstimate,
) -> MpEgressResourceStatus {
    MpEgressResourceStatus {
        resource: snapshot.resource.as_str().to_string(),
        resource_kind: debug_name_to_kebab(snapshot.resource.kind()),
        capacity_bps: snapshot.capacity_bps,
        achieved_bps: snapshot.achieved_bps,
        achieved_source: snapshot.achieved_source.as_str().to_string(),
        queue_delay_micros: snapshot.queue_delay_micros,
        queue_delay_source: snapshot.queue_delay_source.as_str().to_string(),
        reflector_count: snapshot.reflector_count,
        path_count: snapshot.path_count.min(u32::MAX as usize) as u32,
        egress_device: snapshot.egress_device,
        ceiling_bps: snapshot.ceiling_bps.map(|bps| bps.0),
        ceiling_source: snapshot.ceiling_source.as_str().to_string(),
        autorate_estimate_bps: snapshot.autorate_estimate_bps,
        autorate_measured: snapshot.autorate_measured,
        cake: snapshot.cake,
        fallback_scope: snapshot.fallback_scope,
    }
}

#[derive(Clone)]
struct IpProxy {
    tcp_proxy: Arc<TcpProxy<NatDstTcpConnector>>,
    icmp_proxy: Arc<IcmpProxy>,
    udp_proxy: Arc<UdpProxy>,
    global_ctx: ArcGlobalCtx,
    started: Arc<AtomicBool>,
}

impl IpProxy {
    fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Result<Self, Error> {
        let tcp_proxy = TcpProxy::new(peer_manager.clone(), NatDstTcpConnector {});
        let icmp_proxy = IcmpProxy::new(global_ctx.clone(), peer_manager.clone())
            .with_context(|| "create icmp proxy failed")?;
        let udp_proxy = UdpProxy::new(global_ctx.clone(), peer_manager)
            .with_context(|| "create udp proxy failed")?;
        Ok(IpProxy {
            tcp_proxy,
            icmp_proxy,
            udp_proxy,
            global_ctx,
            started: Arc::new(AtomicBool::new(false)),
        })
    }

    async fn start(&self) -> Result<(), Error> {
        if (self.global_ctx.config.get_proxy_cidrs().is_empty()
            || self.started.load(Ordering::Relaxed))
            && !self.global_ctx.enable_exit_node()
            && !self.global_ctx.no_tun()
        {
            return Ok(());
        }

        // Actually, if this node is enabled as an exit node,
        // we still can use the system stack to forward packets.
        if self.global_ctx.proxy_forward_by_system() && !self.global_ctx.no_tun() {
            return Ok(());
        }

        self.started.store(true, Ordering::Relaxed);
        self.tcp_proxy.start(true).await?;
        if let Err(e) = self.icmp_proxy.start().await {
            tracing::error!("start icmp proxy failed: {:?}", e);
            if cfg!(not(any(
                target_os = "android",
                any(
                    target_os = "ios",
                    all(target_os = "macos", feature = "macos-ne")
                ),
                target_env = "ohos"
            ))) {
                // android, ios and ohos not support icmp proxy
                return Err(e);
            }
        }
        self.udp_proxy.start().await?;
        Ok(())
    }
}

#[cfg(feature = "tun")]
type NicCtx = super::virtual_nic::NicCtx;

/// How long a failing first TUN setup is retried before the instance gives up.
/// While Windows is still starting its network stack (boot: VMware bridge,
/// Hyper-V vswitch and Npcap bind to every new adapter), a new Wintun adapter
/// can take longer than Wintun's own creation timeout to come up, so the first
/// attempt fails with "Failed to create adapter" and the next one succeeds.
/// Elsewhere TUN creation is immediate and a first failure is permanent
/// (permissions, missing /dev/net/tun), so it stays fatal right away.
#[cfg(all(not(mobile), feature = "tun"))]
const FIRST_NIC_SETUP_RETRY_WINDOW: Duration = if cfg!(target_os = "windows") {
    Duration::from_secs(60)
} else {
    Duration::ZERO
};

#[cfg(all(not(mobile), feature = "tun"))]
fn retry_first_nic_setup(elapsed: Duration, window: Duration) -> bool {
    elapsed < window
}

#[cfg(feature = "magic-dns")]
struct MagicDnsContainer {
    dns_runner_task: AbortOnDropHandle<()>,
    dns_runner_cancel_token: CancellationToken,
}

// nic container will be cleared when dhcp ip changed
#[cfg(feature = "tun")]
pub struct NicCtxContainer {
    nic_ctx: Option<Box<NicCtx>>,
    packet_drain: Option<JoinSet<()>>,
    #[cfg(feature = "magic-dns")]
    magic_dns: Option<MagicDnsContainer>,
}

#[cfg(feature = "tun")]
impl NicCtxContainer {
    #[cfg(not(feature = "magic-dns"))]
    fn new(nic_ctx: NicCtx) -> Self {
        Self {
            nic_ctx: Some(Box::new(nic_ctx)),
            packet_drain: None,
        }
    }

    #[cfg(feature = "magic-dns")]
    fn new(nic_ctx: NicCtx, dns_runner: Option<DnsRunner>) -> Self {
        if let Some(mut dns_runner) = dns_runner {
            let token = CancellationToken::new();
            let token_clone = token.clone();
            let task = tokio::spawn(async move {
                let _ = dns_runner.run(token_clone).await;
            });
            Self {
                nic_ctx: Some(Box::new(nic_ctx)),
                packet_drain: None,
                magic_dns: Some(MagicDnsContainer {
                    dns_runner_task: AbortOnDropHandle::new(task),
                    dns_runner_cancel_token: token,
                }),
            }
        } else {
            Self {
                nic_ctx: Some(Box::new(nic_ctx)),
                packet_drain: None,
                magic_dns: None,
            }
        }
    }

    fn packet_drain(tasks: JoinSet<()>) -> Self {
        Self {
            nic_ctx: None,
            packet_drain: Some(tasks),
            #[cfg(feature = "magic-dns")]
            magic_dns: None,
        }
    }

    /// Wait until every task that owns the TUN device has released it, so that
    /// the device name can be reused by the next NIC.
    async fn shutdown(mut self) {
        #[cfg(feature = "magic-dns")]
        if let Some(dns_runner) = self.magic_dns.take() {
            dns_runner.dns_runner_cancel_token.cancel();
            tracing::debug!("cancelling dns runner task");
            let ret = dns_runner.dns_runner_task.await;
            tracing::debug!("dns runner task cancelled, ret: {:?}", ret);
        }
        if let Some(mut nic_ctx) = self.nic_ctx.take() {
            nic_ctx.shutdown().await;
        }
        if let Some(mut tasks) = self.packet_drain.take() {
            tasks.shutdown().await;
        }
    }
}

#[cfg(feature = "tun")]
type ArcNicCtx = Arc<Mutex<Option<NicCtxContainer>>>;

pub struct InstanceRpcServerHook {
    rpc_portal_whitelist: Vec<IpCidr>,
}

impl InstanceRpcServerHook {
    pub fn new(rpc_portal_whitelist: Option<Vec<IpCidr>>) -> Self {
        let rpc_portal_whitelist = rpc_portal_whitelist
            .unwrap_or_else(|| vec!["127.0.0.0/8".parse().unwrap(), "::1/128".parse().unwrap()]);
        InstanceRpcServerHook {
            rpc_portal_whitelist,
        }
    }
}

#[async_trait::async_trait]
impl RpcServerHook for InstanceRpcServerHook {
    async fn on_new_client(
        &self,
        tunnel_info: Option<TunnelInfo>,
    ) -> Result<Option<TunnelInfo>, anyhow::Error> {
        let tunnel_info = tunnel_info.ok_or_else(|| anyhow::anyhow!("tunnel info is None"))?;

        let remote_url = tunnel_info
            .remote_addr
            .clone()
            .ok_or_else(|| anyhow::anyhow!("remote_addr is None"))?;

        let url_str = &remote_url.url;
        let url = url::Url::parse(url_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse remote URL '{}': {}", url_str, e))?;

        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("No host found in remote URL '{}'", url_str))?;

        let ip_addr: IpAddr = host
            .parse()
            .map_err(|e| anyhow::anyhow!("Failed to parse IP address '{}': {}", host, e))?;

        for cidr in &self.rpc_portal_whitelist {
            if cidr.contains(&ip_addr) {
                return Ok(Some(tunnel_info));
            }
        }
        return Err(anyhow::anyhow!(
            "Rpc portal client IP {} not in whitelist: {:?}, ignoring client.",
            ip_addr,
            self.rpc_portal_whitelist
        ));
    }
}

#[derive(Clone)]
pub struct InstanceConfigPatcher {
    global_ctx: Weak<GlobalCtx>,
    #[cfg(feature = "socks5")]
    socks5_server: Weak<Socks5Server>,
    peer_manager: Weak<PeerManager>,
    conn_manager: Weak<ManualConnectorManager>,
}

impl InstanceConfigPatcher {
    fn parse_tcp_hole_punch_mode_patch(
        mode: Option<&str>,
    ) -> Result<Option<String>, anyhow::Error> {
        let Some(mode) = mode else {
            return Ok(None);
        };
        let parsed = mode
            .parse::<crate::common::config::TcpHolePunchMode>()
            .context("invalid TCP hole-punch mode patch")?;
        Ok(Some(parsed.to_string()))
    }

    fn parse_ipv6_public_addr_prefix_patch(
        prefix: Option<&str>,
    ) -> Result<Option<Option<cidr::Ipv6Cidr>>, anyhow::Error> {
        let Some(prefix) = prefix else {
            return Ok(None);
        };

        let prefix = prefix.trim();
        if prefix.is_empty() {
            return Ok(Some(None));
        }

        let parsed = prefix
            .parse()
            .with_context(|| format!("failed to parse ipv6 public address prefix: {prefix}"))?;
        Ok(Some(Some(parsed)))
    }

    fn effective_ipv6_for_public_ipv6_validation(
        global_ctx: &ArcGlobalCtx,
        patch: &crate::proto::api::config::InstanceConfigPatch,
        _auto_enabled: bool,
    ) -> Option<cidr::Ipv6Inet> {
        if let Some(ipv6) = patch.ipv6 {
            return Some(ipv6.into());
        }

        global_ctx.get_ipv6()
    }

    fn validate_public_ipv6_patch(
        global_ctx: &ArcGlobalCtx,
        patch: &crate::proto::api::config::InstanceConfigPatch,
    ) -> Result<Option<Option<cidr::Ipv6Cidr>>, anyhow::Error> {
        let parsed_prefix =
            Self::parse_ipv6_public_addr_prefix_patch(patch.ipv6_public_addr_prefix.as_deref())?;

        let auto_enabled = patch
            .ipv6_public_addr_auto
            .unwrap_or(global_ctx.config.get_ipv6_public_addr_auto());
        let provider_enabled = patch
            .ipv6_public_addr_provider
            .unwrap_or(global_ctx.config.get_ipv6_public_addr_provider());
        let prefix =
            parsed_prefix.unwrap_or_else(|| global_ctx.config.get_ipv6_public_addr_prefix());
        let ipv6 = Self::effective_ipv6_for_public_ipv6_validation(global_ctx, patch, auto_enabled);

        validate_public_ipv6_config_values(ipv6, provider_enabled, auto_enabled, prefix)?;
        Ok(parsed_prefix)
    }

    pub async fn apply_patch(
        &self,
        patch: crate::proto::api::config::InstanceConfigPatch,
    ) -> Result<(), anyhow::Error> {
        let patch_for_event = patch.clone();
        let global_ctx = weak_upgrade(&self.global_ctx)?;
        let tcp_hole_punch_mode =
            Self::parse_tcp_hole_punch_mode_patch(patch.tcp_hole_punch_mode.as_deref())?;
        let parsed_ipv6_public_addr_prefix = Self::validate_public_ipv6_patch(&global_ctx, &patch)?;

        self.patch_port_forwards(patch.port_forwards).await?;
        self.patch_acl(patch.acl).await?;
        self.patch_proxy_networks(patch.proxy_networks).await?;
        self.patch_routes(patch.routes).await?;
        self.patch_exit_nodes(patch.exit_nodes).await?;
        self.patch_mapped_listeners(patch.mapped_listeners).await?;
        self.patch_connector(patch.connectors).await?;

        let provider_reconcile_was_running = should_run_public_ipv6_provider_reconcile(&global_ctx);
        let mut provider_config_changed = false;
        if let Some(hostname) = patch.hostname {
            global_ctx.set_hostname(hostname.clone());
            global_ctx.config.set_hostname(Some(hostname));
        }
        if let Some(ipv4) = patch.ipv4
            && !global_ctx.config.get_dhcp()
        {
            global_ctx.set_ipv4(Some(ipv4.into()));
            global_ctx.config.set_ipv4(Some(ipv4.into()));
        }
        if let Some(ipv6) = patch.ipv6 {
            global_ctx.set_ipv6(Some(ipv6.into()));
            global_ctx.config.set_ipv6(Some(ipv6.into()));
        }
        if let Some(tcp_hole_punch_mode) = tcp_hole_punch_mode {
            let mut flags = global_ctx.get_flags();
            flags.tcp_hole_punch_mode = tcp_hole_punch_mode;
            global_ctx.set_flags(flags);
        }
        if let Some(disable_relay_data) = patch.disable_relay_data {
            let mut flags = global_ctx.get_flags();
            flags.disable_relay_data = disable_relay_data;
            global_ctx.set_flags(flags);
        }
        if let Some(mp) = patch.mp {
            crate::common::config::validate_mp_config(&mp)
                .context("invalid MP configuration patch")?;
            let mut flags = global_ctx.get_flags();
            flags.mp = Some(mp.clone());
            global_ctx.set_flags(flags);
            #[cfg(feature = "mpquic")]
            weak_upgrade(&self.peer_manager)?
                .get_mp_session_manager()
                .set_config(mp)
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        }
        if let Some(egress_wire_limit_bps) = patch.egress_wire_limit_bps {
            // MP_SQM_PLAN.md S2.0 landed + validated the patched value on
            // `Flags` so it round-trips through GetConfig/GUI readback. S2.1
            // makes it actually re-cap the already-running
            // `EgressQualityManager` live (see `reapply_egress_ceiling`
            // below) -- no instance restart.
            let checked = if egress_wire_limit_bps == 0 {
                None
            } else {
                crate::common::config::validate_egress_wire_limit_bps(egress_wire_limit_bps)
                    .context("invalid egress_wire_limit_bps patch")?;
                Some(egress_wire_limit_bps)
            };
            let mut flags = global_ctx.get_flags();
            flags.egress_wire_limit_bps = checked;
            global_ctx.set_flags(flags);
        }
        if patch.egress_wire_limit_bps.is_some() || patch_for_event.mp.is_some() {
            // MP_SQM_PLAN.md S2.1: re-derive the full effective egress
            // ceiling (global `Flags::egress_wire_limit_bps` plus any
            // per-NIC `MpConfig.egress_limits` override) from whichever of
            // the two branches above just ran, and hot-apply it to every
            // already-resolved `EgressScope` -- covers both branches (or
            // either alone) in one place instead of duplicating the
            // resolve-and-apply logic per field.
            Self::reapply_egress_ceiling(&global_ctx);
        }
        if let Some(enabled) = patch.ipv6_public_addr_provider {
            global_ctx.config.set_ipv6_public_addr_provider(enabled);
            provider_config_changed = true;
        }
        if let Some(enabled) = patch.ipv6_public_addr_auto {
            global_ctx.config.set_ipv6_public_addr_auto(enabled);
        }
        if let Some(prefix) = parsed_ipv6_public_addr_prefix {
            global_ctx.config.set_ipv6_public_addr_prefix(prefix);
            provider_config_changed = true;
        }

        global_ctx.issue_event(GlobalCtxEvent::ConfigPatched(patch_for_event));

        if provider_config_changed {
            reconcile_public_ipv6_provider_runtime(&global_ctx).await;

            let provider_reconcile_should_run =
                should_run_public_ipv6_provider_reconcile(&global_ctx);
            if !provider_reconcile_was_running && provider_reconcile_should_run {
                run_public_ipv6_provider_reconcile_task(&global_ctx);
            }
        }

        Ok(())
    }

    /// MP_SQM_PLAN.md S2.1: re-derive the effective egress ceiling from the
    /// instance's current `Flags` (global `egress_wire_limit_bps` plus
    /// `MpConfig.egress_limits`, resolved from interface *names* to
    /// `EgressStableId`s here so `common::egress_quality` stays decoupled
    /// from `EgressInventory` -- see that module's own doc) and hot-apply it
    /// to the instance's `EgressQualityManager`. Called after every
    /// `apply_patch` branch that could have changed either input; a no-op
    /// reapply of unchanged state is harmless, so this deliberately does
    /// not try to track exactly which field changed.
    ///
    /// Scope note: this covers the hot-patch path only (MP_SQM_PLAN.md
    /// S2.1's "flags 与 MpConfig 热更新路径"). A statically-configured
    /// `MpConfig.egress_limits` present from the very first `run()` (never
    /// patched) is not separately reapplied at startup here -- the global
    /// half already is, via `GlobalCtx::new`'s own construction-time
    /// `EgressQualityConfig::static_wire_ceiling`; the per-NIC half would
    /// additionally need `EgressInventory` to already be started, which
    /// happens lazily on first access, not eagerly during `run()`.
    fn reapply_egress_ceiling(global_ctx: &ArcGlobalCtx) {
        let flags = global_ctx.get_flags();
        let global_ceiling = flags.egress_wire_limit_bps.map(WireBitrate);
        let per_device = match (flags.mp.as_ref(), global_ctx.get_egress_inventory()) {
            (Some(mp), Some(inventory)) if !mp.egress_limits.is_empty() => {
                Self::resolve_per_device_ceilings(&mp.egress_limits, &inventory.snapshot())
            }
            _ => HashMap::new(),
        };
        global_ctx
            .egress_quality_manager()
            .set_static_ceiling(global_ceiling, per_device);
    }

    /// Pure matching step of `reapply_egress_ceiling`, split out so it is
    /// testable with a synthetic `EgressInventorySnapshot` and no real
    /// `EgressInventory`/`GlobalCtx` needed. Matches by the raw OS interface
    /// name (`platform_name`), the same convention
    /// `ResourceGroupId::egress_device`/`MpResourceGroupConfig::egress_devices`
    /// already use -- MP_SQM_PLAN.md §9 does not define fuzzy matching here.
    /// A name that does not currently resolve to any interface is simply
    /// not applied, not an error: the NIC may be temporarily absent.
    fn resolve_per_device_ceilings(
        limits: &[crate::proto::common::MpEgressLimit],
        snapshot: &crate::common::egress_inventory::EgressInventorySnapshot,
    ) -> HashMap<EgressStableId, WireBitrate> {
        let mut per_device = HashMap::new();
        for limit in limits {
            if let Some(interface) = snapshot
                .interfaces
                .values()
                .find(|interface| interface.platform_name == limit.egress_device)
            {
                per_device.insert(interface.id.clone(), WireBitrate(limit.limit_bps));
            }
        }
        per_device
    }

    fn trace_patchables<T: std::fmt::Debug>(
        patches: &Vec<crate::proto::api::config::Patchable<T>>,
    ) {
        for patch in patches {
            match patch.action {
                Some(ConfigPatchAction::Add) | Some(ConfigPatchAction::Remove) => {
                    if let Some(value) = &patch.value {
                        tracing::info!("{:?} {:?}", patch.action, value);
                    } else {
                        tracing::warn!(
                            "Ignored {:?} patch with no value for type '{}'. Please ensure the patch value is provided.",
                            patch.action,
                            std::any::type_name::<T>()
                        );
                    }
                }
                Some(ConfigPatchAction::Clear) => {
                    tracing::info!("Clear all for type '{}'", std::any::type_name::<T>());
                }
                None => {
                    tracing::warn!(
                        "Invalid patch action for type '{}'",
                        std::any::type_name::<T>()
                    );
                }
            }
        }
    }

    async fn patch_port_forwards(
        &self,
        port_forwards: Vec<PortForwardPatch>,
    ) -> Result<(), anyhow::Error> {
        if port_forwards.is_empty() {
            return Ok(());
        }
        #[cfg(feature = "socks5")]
        let Some(socks5_server) = self.socks5_server.upgrade() else {
            return Err(anyhow::anyhow!("socks5 server not available"));
        };
        let global_ctx = weak_upgrade(&self.global_ctx)?;

        let mut current_forwards = global_ctx.config.get_port_forwards();
        let patches = port_forwards.into_iter().map(Into::into).collect();
        InstanceConfigPatcher::trace_patchables(&patches);
        crate::proto::api::config::patch_vec(&mut current_forwards, patches);

        global_ctx
            .config
            .set_port_forwards(current_forwards.clone());
        #[cfg(feature = "socks5")]
        socks5_server
            .reload_port_forwards(&current_forwards)
            .await
            .with_context(|| "Failed to reload port forwards")?;

        Ok(())
    }

    async fn patch_acl(
        &self,
        acl_patch: Option<crate::proto::api::config::AclPatch>,
    ) -> Result<(), anyhow::Error> {
        let Some(acl_patch) = acl_patch else {
            return Ok(());
        };
        let global_ctx = weak_upgrade(&self.global_ctx)?;
        if let Some(acl) = acl_patch.acl {
            global_ctx.config.set_acl(Some(acl));
        }
        if !acl_patch.tcp_whitelist.is_empty() {
            let mut current_whitelist = global_ctx.config.get_tcp_whitelist();
            let patches = acl_patch
                .tcp_whitelist
                .into_iter()
                .map(Into::into)
                .collect();
            InstanceConfigPatcher::trace_patchables(&patches);
            crate::proto::api::config::patch_vec(&mut current_whitelist, patches);
            global_ctx.config.set_tcp_whitelist(current_whitelist);
        }
        if !acl_patch.udp_whitelist.is_empty() {
            let mut current_whitelist = global_ctx.config.get_udp_whitelist();
            let patches = acl_patch
                .udp_whitelist
                .into_iter()
                .map(Into::into)
                .collect();
            InstanceConfigPatcher::trace_patchables(&patches);
            crate::proto::api::config::patch_vec(&mut current_whitelist, patches);
            global_ctx.config.set_udp_whitelist(current_whitelist);
        }
        global_ctx
            .get_acl_filter()
            .reload_rules(AclRuleBuilder::build(&global_ctx)?.as_ref());
        weak_upgrade(&self.peer_manager)?
            .get_route()
            .refresh_acl_groups()
            .await;
        Ok(())
    }

    async fn patch_proxy_networks(
        &self,
        proxy_networks: Vec<crate::proto::api::config::ProxyNetworkPatch>,
    ) -> Result<(), anyhow::Error> {
        if proxy_networks.is_empty() {
            return Ok(());
        }
        let global_ctx = weak_upgrade(&self.global_ctx)?;
        for proxy_network_patch in proxy_networks {
            match ConfigPatchAction::try_from(proxy_network_patch.action) {
                Ok(ConfigPatchAction::Add) => {
                    let Some(cidr) = proxy_network_patch.cidr.map(|c| c.into()) else {
                        tracing::warn!("Proxy network cidr is None, skipping add.");
                        continue;
                    };
                    let mapped_cidr: Option<cidr::Ipv4Cidr> =
                        proxy_network_patch.mapped_cidr.map(|s| s.into());
                    tracing::info!("Proxy network added: {}", cidr);
                    global_ctx.config.add_proxy_cidr(cidr, mapped_cidr)?;
                }
                Ok(ConfigPatchAction::Remove) => {
                    let Some(cidr) = proxy_network_patch.cidr.map(|c| c.into()) else {
                        tracing::warn!("Proxy network cidr is None, skipping remove.");
                        continue;
                    };
                    tracing::info!("Proxy network removed: {}", cidr);
                    global_ctx.config.remove_proxy_cidr(cidr);
                }
                Ok(ConfigPatchAction::Clear) => {
                    tracing::info!("Proxy networks cleared.");
                    global_ctx.config.clear_proxy_cidrs();
                }
                Err(_) => {
                    tracing::warn!(
                        "Invalid proxy network action: {}",
                        proxy_network_patch.action
                    );
                }
            }
        }
        Ok(())
    }

    async fn patch_routes(
        &self,
        routes: Vec<crate::proto::api::config::RoutePatch>,
    ) -> Result<(), anyhow::Error> {
        if routes.is_empty() {
            return Ok(());
        }
        let global_ctx = weak_upgrade(&self.global_ctx)?;
        let mut current_routes = global_ctx.config.get_routes().unwrap_or_default();
        let patches = routes.into_iter().map(Into::into).collect();
        InstanceConfigPatcher::trace_patchables(&patches);
        crate::proto::api::config::patch_vec(&mut current_routes, patches);
        if current_routes.is_empty() {
            global_ctx.config.set_routes(None);
        } else {
            global_ctx.config.set_routes(Some(current_routes));
        }
        Ok(())
    }

    async fn patch_exit_nodes(
        &self,
        exit_nodes: Vec<crate::proto::api::config::ExitNodePatch>,
    ) -> Result<(), anyhow::Error> {
        if exit_nodes.is_empty() {
            return Ok(());
        }
        let global_ctx = weak_upgrade(&self.global_ctx)?;
        let peer_manager = weak_upgrade(&self.peer_manager)?;
        let mut current_exit_nodes = global_ctx.config.get_exit_nodes();
        let patches = exit_nodes.into_iter().map(Into::into).collect();
        InstanceConfigPatcher::trace_patchables(&patches);
        crate::proto::api::config::patch_vec(&mut current_exit_nodes, patches);
        global_ctx.config.set_exit_nodes(current_exit_nodes);
        peer_manager.update_exit_nodes().await;

        Ok(())
    }

    async fn patch_mapped_listeners(
        &self,
        mapped_listeners: Vec<crate::proto::api::config::UrlPatch>,
    ) -> Result<(), anyhow::Error> {
        if mapped_listeners.is_empty() {
            return Ok(());
        }
        let global_ctx = weak_upgrade(&self.global_ctx)?;
        let mut current_mapped_listeners = global_ctx.config.get_mapped_listeners();
        let patches = mapped_listeners.into_iter().map(Into::into).collect();
        InstanceConfigPatcher::trace_patchables(&patches);
        crate::proto::api::config::patch_vec(&mut current_mapped_listeners, patches);
        if current_mapped_listeners.is_empty() {
            global_ctx.config.set_mapped_listeners(None);
        } else {
            global_ctx
                .config
                .set_mapped_listeners(Some(current_mapped_listeners));
        }
        Ok(())
    }

    async fn patch_connector(
        &self,
        connectors: Vec<crate::proto::api::config::UrlPatch>,
    ) -> Result<(), anyhow::Error> {
        if connectors.is_empty() {
            return Ok(());
        }
        let conn_manager = weak_upgrade(&self.conn_manager)?;
        for connector in connectors {
            let Some(url) = connector.url.map(Into::<url::Url>::into) else {
                tracing::warn!("Connector url is None, skipping.");
                return Ok(());
            };
            match ConfigPatchAction::try_from(connector.action) {
                Ok(ConfigPatchAction::Add) => {
                    tracing::info!("Connector added: {}", url);
                    conn_manager.add_connector_by_url(url).await?;
                }
                Ok(ConfigPatchAction::Remove) => {
                    tracing::info!("Connector removed: {}", url);
                    conn_manager.remove_connector(url).await?;
                }
                Ok(ConfigPatchAction::Clear) => {
                    tracing::info!("Connectors cleared.");
                    conn_manager.clear_connectors().await;
                }
                Err(_) => {
                    tracing::warn!("Invalid connector action: {}", connector.action);
                }
            }
        }
        Ok(())
    }
}

pub struct Instance {
    inst_name: String,

    id: uuid::Uuid,

    #[cfg(feature = "tun")]
    nic_ctx: ArcNicCtx,

    peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,
    peer_manager: Arc<PeerManager>,
    listener_manager: Arc<Mutex<ListenerManager<PeerManager>>>,
    conn_manager: Arc<ManualConnectorManager>,
    direct_conn_manager: Arc<DirectConnectorManager>,
    udp_hole_puncher: Arc<Mutex<UdpHolePunchConnector>>,
    tcp_hole_puncher: Arc<Mutex<TcpHolePunchConnector>>,

    ip_proxy: Option<IpProxy>,

    #[cfg(feature = "kcp")]
    kcp_proxy_src: Option<KcpProxySrc>,
    #[cfg(feature = "kcp")]
    kcp_proxy_dst: Option<KcpProxyDst>,

    #[cfg(feature = "quic")]
    quic_proxy: Option<QuicProxy>,

    peer_center: Arc<PeerCenterInstance>,

    vpn_portal: Arc<Mutex<Box<dyn VpnPortal>>>,

    #[cfg(feature = "socks5")]
    socks5_server: Arc<Socks5Server>,

    proxy_cidrs_monitor: Option<AbortOnDropHandle<()>>,

    global_ctx: ArcGlobalCtx,
}

impl Instance {
    pub fn new(config: impl ConfigLoader + 'static) -> Self {
        let global_ctx = Arc::new(GlobalCtx::new(config));

        tracing::info!(
            "[INIT] instance creating. config: {}",
            global_ctx.config.dump()
        );

        let (peer_packet_sender, peer_packet_receiver) = create_packet_recv_chan();

        let id = global_ctx.get_id();

        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx.clone(),
            peer_packet_sender,
        ));

        peer_manager.set_allow_loopback_tunnel(false);

        let listener_manager = Arc::new(Mutex::new(ListenerManager::new(
            global_ctx.clone(),
            peer_manager.clone(),
        )));

        let conn_manager = Arc::new(ManualConnectorManager::new(
            global_ctx.clone(),
            peer_manager.clone(),
        ));

        let mut direct_conn_manager =
            DirectConnectorManager::new(global_ctx.clone(), peer_manager.clone());
        direct_conn_manager.run();
        let direct_conn_manager = Arc::new(direct_conn_manager);

        let udp_hole_puncher =
            Arc::new(Mutex::new(UdpHolePunchConnector::new(peer_manager.clone())));
        let tcp_hole_puncher =
            Arc::new(Mutex::new(TcpHolePunchConnector::new(peer_manager.clone())));

        let peer_center = Arc::new(PeerCenterInstance::new(peer_manager.clone()));

        #[cfg(feature = "wireguard")]
        let vpn_portal_inst = vpn_portal::wireguard::WireGuard::default();
        #[cfg(not(feature = "wireguard"))]
        let vpn_portal_inst = vpn_portal::NullVpnPortal;

        #[cfg(feature = "socks5")]
        let socks5_server = Socks5Server::new(global_ctx.clone(), peer_manager.clone(), None);

        Instance {
            inst_name: global_ctx.inst_name.clone(),
            id,

            peer_packet_receiver: Arc::new(Mutex::new(peer_packet_receiver)),
            #[cfg(feature = "tun")]
            nic_ctx: Arc::new(Mutex::new(None)),

            peer_manager,
            listener_manager,
            conn_manager,
            direct_conn_manager,
            udp_hole_puncher,
            tcp_hole_puncher,

            ip_proxy: None,
            #[cfg(feature = "kcp")]
            kcp_proxy_src: None,
            #[cfg(feature = "kcp")]
            kcp_proxy_dst: None,

            #[cfg(feature = "quic")]
            quic_proxy: None,

            peer_center,

            vpn_portal: Arc::new(Mutex::new(Box::new(vpn_portal_inst))),

            #[cfg(feature = "socks5")]
            socks5_server,

            proxy_cidrs_monitor: None,

            global_ctx,
        }
    }

    pub fn get_conn_manager(&self) -> Arc<ManualConnectorManager> {
        self.conn_manager.clone()
    }

    async fn add_initial_peers(&self) -> Result<(), Error> {
        for peer in self.global_ctx.config.get_peers().iter() {
            self.get_conn_manager()
                .add_connector_by_url(peer.uri.clone())
                .await?;
        }
        Ok(())
    }

    async fn prepare_public_ipv6_config(&self) -> Result<(), Error> {
        validate_public_ipv6_config(&self.global_ctx)?;
        reconcile_public_ipv6_provider_runtime(&self.global_ctx).await;
        Ok(())
    }

    // use a mock nic ctx to consume packets.
    #[cfg(feature = "tun")]
    async fn clear_nic_ctx(
        arc_nic_ctx: ArcNicCtx,
        packet_recv: Arc<Mutex<PacketRecvChanReceiver>>,
    ) {
        Self::shutdown_nic_ctx(arc_nic_ctx.clone()).await;

        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut packet_recv = packet_recv.lock().await;
            while let Ok(packet) = recv_packet_from_chan(&mut packet_recv).await {
                tracing::trace!("packet consumed by mock nic ctx: {:?}", packet);
            }
        });
        arc_nic_ctx
            .lock()
            .await
            .replace(NicCtxContainer::packet_drain(tasks));

        tracing::debug!("nic ctx cleared.");
    }

    // The lock is released before waiting, the old container is already detached.
    #[cfg(feature = "tun")]
    async fn shutdown_nic_ctx(arc_nic_ctx: ArcNicCtx) {
        let old = arc_nic_ctx.lock().await.take();
        if let Some(old) = old {
            old.shutdown().await;
        }
    }

    #[cfg(feature = "magic-dns")]
    fn create_magic_dns_runner(
        peer_mgr: Arc<PeerManager>,
        tun_dev: Option<String>,
        tun_ip: Ipv4Inet,
    ) -> Option<DnsRunner> {
        let ctx = peer_mgr.get_global_ctx();
        if !ctx.config.get_flags().accept_dns {
            return None;
        }

        let runner = DnsRunner::new(
            peer_mgr,
            tun_dev,
            tun_ip,
            MAGIC_DNS_FAKE_IP.parse().unwrap(),
        );
        Some(runner)
    }

    #[cfg(feature = "tun")]
    async fn use_new_nic_ctx(
        arc_nic_ctx: ArcNicCtx,
        nic_ctx: NicCtx,
        #[cfg(feature = "magic-dns")] magic_dns: Option<DnsRunner>,
    ) {
        let mut g = arc_nic_ctx.lock().await;
        *g = Some(NicCtxContainer::new(
            nic_ctx,
            #[cfg(feature = "magic-dns")]
            magic_dns,
        ));
        tracing::debug!("nic ctx updated.");
    }

    // Warning, if there is an IP conflict in the network when using DHCP, the IP will be automatically changed.
    fn check_dhcp_ip_conflict(&self) {
        use rand::Rng;
        let peer_manager_c = Arc::downgrade(&self.peer_manager.clone());
        let global_ctx_c = self.get_global_ctx();
        #[cfg(feature = "tun")]
        let nic_ctx = self.nic_ctx.clone();
        let _peer_packet_receiver = self.peer_packet_receiver.clone();
        tokio::spawn(async move {
            let default_ipv4_addr = Ipv4Inet::new(Ipv4Addr::new(10, 126, 126, 0), 24).unwrap();
            let mut current_dhcp_ip: Option<Ipv4Inet> = None;
            let mut next_sleep_time = 0;
            let nic_closed_notifier = Arc::new(Notify::new());
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(next_sleep_time)).await;

                let Some(peer_manager_c) = peer_manager_c.upgrade() else {
                    tracing::warn!("peer manager is dropped, stop dhcp check.");
                    return;
                };

                if nic_closed_notifier.notified().now_or_never().is_some() {
                    tracing::debug!("nic ctx is closed, try recreate it");
                    current_dhcp_ip = None;
                }

                // do not allocate ip if no peer connected
                let routes = peer_manager_c.list_routes().await;
                if routes.is_empty() {
                    next_sleep_time = 1;
                    continue;
                } else {
                    next_sleep_time = rand::thread_rng().gen_range(5..10);
                }

                let mut used_ipv4 = HashSet::new();
                for route in routes {
                    let Some(peer_ipv4_addr) = route.ipv4_addr else {
                        continue;
                    };

                    used_ipv4.insert(peer_ipv4_addr.into());
                }

                let dhcp_inet = used_ipv4.iter().next().unwrap_or(&default_ipv4_addr);
                // if old ip is already in this subnet and not conflicted, use it
                if let Some(ip) = current_dhcp_ip
                    && ip.network() == dhcp_inet.network()
                    && !used_ipv4.contains(&ip)
                {
                    continue;
                }

                // find an available ip in the subnet
                let candidate_ipv4_addr = dhcp_inet.network().iter().find(|ip| {
                    ip.address() != dhcp_inet.first_address()
                        && ip.address() != dhcp_inet.last_address()
                        && !used_ipv4.contains(ip)
                });

                if current_dhcp_ip == candidate_ipv4_addr {
                    continue;
                }

                let last_ip = current_dhcp_ip;
                tracing::debug!(
                    ?current_dhcp_ip,
                    ?candidate_ipv4_addr,
                    "dhcp start changing ip"
                );

                #[cfg(feature = "tun")]
                Self::clear_nic_ctx(nic_ctx.clone(), _peer_packet_receiver.clone()).await;

                if let Some(ip) = candidate_ipv4_addr {
                    if global_ctx_c.no_tun() {
                        current_dhcp_ip = Some(ip);
                        global_ctx_c.set_ipv4(Some(ip));
                        global_ctx_c
                            .issue_event(GlobalCtxEvent::DhcpIpv4Changed(last_ip, Some(ip)));
                        continue;
                    }

                    #[cfg(all(not(mobile), feature = "tun"))]
                    {
                        let mut new_nic_ctx = NicCtx::new(
                            global_ctx_c.clone(),
                            &peer_manager_c,
                            _peer_packet_receiver.clone(),
                            nic_closed_notifier.clone(),
                        );
                        if let Err(e) = new_nic_ctx.run(Some(ip), global_ctx_c.get_ipv6()).await {
                            tracing::error!(
                                ?current_dhcp_ip,
                                ?candidate_ipv4_addr,
                                ?e,
                                "add ip failed"
                            );
                            global_ctx_c.set_ipv4(None);
                            continue;
                        }
                        #[cfg(feature = "magic-dns")]
                        let ifname = new_nic_ctx.ifname().await;
                        Self::use_new_nic_ctx(
                            nic_ctx.clone(),
                            new_nic_ctx,
                            #[cfg(feature = "magic-dns")]
                            Self::create_magic_dns_runner(peer_manager_c.clone(), ifname, ip),
                        )
                        .await;
                    }

                    current_dhcp_ip = Some(ip);
                    global_ctx_c.set_ipv4(Some(ip));
                    global_ctx_c.issue_event(GlobalCtxEvent::DhcpIpv4Changed(last_ip, Some(ip)));
                } else {
                    current_dhcp_ip = None;
                    global_ctx_c.set_ipv4(None);
                    global_ctx_c.issue_event(GlobalCtxEvent::DhcpIpv4Conflicted(last_ip));
                }
            }
        });
    }

    #[cfg(all(not(mobile), feature = "tun"))]
    fn check_for_static_ip(&self, first_round_output: oneshot::Sender<Result<(), Error>>) {
        let ipv4_addr = self.global_ctx.get_ipv4();
        let ipv6_addr = self.global_ctx.get_ipv6();

        // Only run if we have at least one IP address (IPv4 or IPv6)
        if ipv4_addr.is_none() && ipv6_addr.is_none() {
            let _ = first_round_output.send(Ok(()));
            return;
        }

        let nic_ctx = self.nic_ctx.clone();
        let peer_mgr = Arc::downgrade(&self.peer_manager);
        let peer_packet_receiver = self.peer_packet_receiver.clone();

        tokio::spawn(async move {
            let mut output_tx = Some(first_round_output);
            let first_round_started = std::time::Instant::now();
            loop {
                let close_notifier = Arc::new(Notify::new());
                {
                    let Some(peer_mgr) = peer_mgr.upgrade() else {
                        tracing::warn!("peer manager is dropped, stop static ip check.");
                        if let Some(output_tx) = output_tx.take() {
                            let _ = output_tx.send(Err(Error::Unknown));
                            return;
                        }
                        return;
                    };

                    // The previous NIC must release its device before the same name is reused.
                    Self::shutdown_nic_ctx(nic_ctx.clone()).await;

                    let mut new_nic_ctx = NicCtx::new(
                        peer_mgr.get_global_ctx(),
                        &peer_mgr,
                        peer_packet_receiver.clone(),
                        close_notifier.clone(),
                    );

                    if let Err(e) = new_nic_ctx.run(ipv4_addr, ipv6_addr).await {
                        if let Some(tx) = output_tx.take() {
                            if !retry_first_nic_setup(
                                first_round_started.elapsed(),
                                FIRST_NIC_SETUP_RETRY_WINDOW,
                            ) {
                                let _ = tx.send(Err(e));
                                return;
                            }
                            output_tx = Some(tx);
                            tracing::warn!(
                                "failed to create nic ctx on startup, retrying, err: {:?}",
                                e
                            );
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            continue;
                        }
                        tracing::error!("failed to create new nic ctx, err: {:?}", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }

                    // Create Magic DNS runner only if we have IPv4
                    #[cfg(feature = "magic-dns")]
                    {
                        let ifname = new_nic_ctx.ifname().await;
                        let dns_runner = if let Some(ipv4) = ipv4_addr {
                            Self::create_magic_dns_runner(peer_mgr, ifname, ipv4)
                        } else {
                            None
                        };
                        Self::use_new_nic_ctx(nic_ctx.clone(), new_nic_ctx, dns_runner).await;
                    }
                    #[cfg(not(feature = "magic-dns"))]
                    Self::use_new_nic_ctx(nic_ctx.clone(), new_nic_ctx).await;
                }

                if let Some(output_tx) = output_tx.take() {
                    let _ = output_tx.send(Ok(()));
                }

                // NOTICE: make sure we do not hold the peer manager here,
                while close_notifier.notified().now_or_never().is_none() {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    if peer_mgr.strong_count() == 0 {
                        tracing::warn!("peer manager is dropped, stop static ip check.");
                        return;
                    }
                }
            }
        });
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        self.prepare_public_ipv6_config().await?;
        self.listener_manager
            .lock()
            .await
            .prepare_listeners()
            .await?;
        self.listener_manager.lock().await.run().await?;
        self.peer_manager.run().await?;
        run_public_ipv6_provider_reconcile_task(&self.global_ctx);

        #[cfg(feature = "tun")]
        {
            Self::clear_nic_ctx(self.nic_ctx.clone(), self.peer_packet_receiver.clone()).await;

            #[cfg(not(mobile))]
            if !self.global_ctx.config.get_flags().no_tun {
                let (output_tx, output_rx) = oneshot::channel();
                self.check_for_static_ip(output_tx);
                output_rx.await.unwrap()?;
            }
        }

        if self.global_ctx.config.get_dhcp() {
            self.check_dhcp_ip_conflict();
        }

        #[cfg(feature = "kcp")]
        if self.global_ctx.get_flags().enable_kcp_proxy {
            let src_proxy = KcpProxySrc::new(self.get_peer_manager()).await;
            src_proxy.start().await;
            self.kcp_proxy_src = Some(src_proxy);
        }

        #[cfg(feature = "kcp")]
        if !self.global_ctx.get_flags().disable_kcp_input {
            let mut dst_proxy = KcpProxyDst::new(self.get_peer_manager()).await;
            dst_proxy.start().await;
            self.kcp_proxy_dst = Some(dst_proxy);
        }

        #[cfg(feature = "quic")]
        {
            let quic_src = self.global_ctx.get_flags().enable_quic_proxy;
            let quic_dst = !self.global_ctx.get_flags().disable_quic_input;
            if quic_src || quic_dst {
                let mut quic_proxy = QuicProxy::new(self.get_peer_manager());
                quic_proxy.run(quic_src, quic_dst).await;
                self.quic_proxy = Some(quic_proxy);
            }
        }

        self.global_ctx
            .get_acl_filter()
            .reload_rules(AclRuleBuilder::build(&self.global_ctx)?.as_ref());

        // run after tun device created, so listener can bind to tun device, which may be required by win 10
        self.ip_proxy = Some(IpProxy::new(
            self.get_global_ctx(),
            self.get_peer_manager(),
        )?);
        self.run_ip_proxy().await?;

        self.udp_hole_puncher.lock().await.run().await?;
        self.tcp_hole_puncher.lock().await.run().await?;

        self.peer_center.init().await;
        let route_calc = self.peer_center.get_cost_calculator();
        self.peer_manager
            .get_route()
            .set_route_cost_fn(route_calc)
            .await;

        self.add_initial_peers().await?;

        let monitor = super::proxy_cidrs_monitor::ProxyCidrsMonitor::new(
            self.peer_manager.clone(),
            self.global_ctx.clone(),
        );
        self.proxy_cidrs_monitor = Some(monitor.start());

        if self.global_ctx.get_vpn_portal_cidr().is_some() {
            self.run_vpn_portal().await?;
        }

        #[cfg(feature = "socks5")]
        self.socks5_server
            .run(
                #[cfg(feature = "kcp")]
                self.kcp_proxy_src
                    .as_ref()
                    .map(|x| Arc::downgrade(&x.get_kcp_endpoint())),
            )
            .await?;

        Ok(())
    }

    pub async fn run_ip_proxy(&mut self) -> Result<(), Error> {
        if self.ip_proxy.is_none() {
            return Err(anyhow::anyhow!("ip proxy not enabled.").into());
        }
        self.ip_proxy.as_ref().unwrap().start().await?;
        Ok(())
    }

    pub async fn run_vpn_portal(&mut self) -> Result<(), Error> {
        if self.global_ctx.get_vpn_portal_cidr().is_none() {
            return Err(anyhow::anyhow!("vpn portal cidr not set.").into());
        }
        self.vpn_portal
            .lock()
            .await
            .start(self.get_global_ctx(), self.get_peer_manager())
            .await?;
        Ok(())
    }

    pub fn get_peer_manager(&self) -> Arc<PeerManager> {
        self.peer_manager.clone()
    }

    #[cfg(feature = "ffi-dataplane")]
    pub fn get_socks5_server(&self) -> Arc<Socks5Server> {
        self.socks5_server.clone()
    }

    pub async fn close_peer_conn(
        &mut self,
        peer_id: PeerId,
        conn_id: &PeerConnId,
    ) -> Result<(), Error> {
        self.peer_manager
            .get_peer_map()
            .close_peer_conn(peer_id, conn_id)
            .await?;
        Ok(())
    }

    pub async fn wait(&self) {
        self.peer_manager.wait().await;
    }

    pub fn id(&self) -> uuid::Uuid {
        self.id
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_manager.my_peer_id()
    }

    fn get_vpn_portal_rpc_service(
        &self,
    ) -> impl VpnPortalRpc<Controller = BaseController> + Clone + use<> {
        #[derive(Clone)]
        struct VpnPortalRpcService {
            peer_mgr: Weak<PeerManager>,
            vpn_portal: Weak<Mutex<Box<dyn VpnPortal>>>,
        }

        #[async_trait::async_trait]
        impl VpnPortalRpc for VpnPortalRpcService {
            type Controller = BaseController;

            async fn get_vpn_portal_info(
                &self,
                _: BaseController,
                _request: GetVpnPortalInfoRequest,
            ) -> Result<GetVpnPortalInfoResponse, rpc_types::error::Error> {
                let Some(vpn_portal) = self.vpn_portal.upgrade() else {
                    return Err(anyhow::anyhow!("vpn portal not available").into());
                };

                let Some(peer_mgr) = self.peer_mgr.upgrade() else {
                    return Err(anyhow::anyhow!("peer manager not available").into());
                };

                let vpn_portal = vpn_portal.lock().await;
                let ret = GetVpnPortalInfoResponse {
                    vpn_portal_info: Some(VpnPortalInfo {
                        vpn_type: vpn_portal.name(),
                        client_config: vpn_portal.dump_client_config(peer_mgr).await,
                        connected_clients: vpn_portal.list_clients().await,
                    }),
                };

                Ok(ret)
            }
        }

        VpnPortalRpcService {
            peer_mgr: Arc::downgrade(&self.peer_manager),
            vpn_portal: Arc::downgrade(&self.vpn_portal),
        }
    }

    fn get_mapped_listener_manager_rpc_service(
        &self,
    ) -> impl MappedListenerManageRpc<Controller = BaseController> + Clone + use<> {
        #[derive(Clone)]
        pub struct MappedListenerManagerRpcService(Weak<GlobalCtx>);

        #[async_trait::async_trait]
        impl MappedListenerManageRpc for MappedListenerManagerRpcService {
            type Controller = BaseController;

            async fn list_mapped_listener(
                &self,
                _: BaseController,
                _request: ListMappedListenerRequest,
            ) -> Result<ListMappedListenerResponse, rpc_types::error::Error> {
                let mut ret = ListMappedListenerResponse::default();
                let urls = weak_upgrade(&self.0)?.config.get_mapped_listeners();
                let mapped_listeners: Vec<MappedListener> = urls
                    .into_iter()
                    .map(|u| MappedListener {
                        url: Some(u.into()),
                    })
                    .collect();
                ret.mappedlisteners = mapped_listeners;
                Ok(ret)
            }
        }

        MappedListenerManagerRpcService(Arc::downgrade(&self.global_ctx))
    }

    fn get_port_forward_manager_rpc_service(
        &self,
    ) -> impl PortForwardManageRpc<Controller = BaseController> + Clone + use<> {
        #[derive(Clone)]
        pub struct PortForwardManagerRpcService {
            global_ctx: Weak<GlobalCtx>,
            #[cfg(feature = "socks5")]
            socks5_server: Weak<Socks5Server>,
        }

        #[async_trait::async_trait]
        impl PortForwardManageRpc for PortForwardManagerRpcService {
            type Controller = BaseController;

            async fn list_port_forward(
                &self,
                _: BaseController,
                _request: ListPortForwardRequest,
            ) -> Result<ListPortForwardResponse, rpc_types::error::Error> {
                let forwards = weak_upgrade(&self.global_ctx)?.config.get_port_forwards();
                let cfgs: Vec<PortForwardConfigPb> = forwards.into_iter().map(Into::into).collect();
                Ok(ListPortForwardResponse { cfgs })
            }
        }

        PortForwardManagerRpcService {
            global_ctx: Arc::downgrade(&self.global_ctx),
            #[cfg(feature = "socks5")]
            socks5_server: Arc::downgrade(&self.socks5_server),
        }
    }

    fn get_stats_rpc_service(&self) -> impl StatsRpc<Controller = BaseController> + Clone + use<> {
        #[derive(Clone)]
        pub struct StatsRpcService {
            global_ctx: Weak<GlobalCtx>,
            #[cfg(feature = "mpquic")]
            peer_manager: Weak<PeerManager>,
        }

        #[async_trait::async_trait]
        impl StatsRpc for StatsRpcService {
            type Controller = BaseController;

            async fn get_stats(
                &self,
                _: BaseController,
                _request: GetStatsRequest,
            ) -> Result<GetStatsResponse, rpc_types::error::Error> {
                let snapshots = weak_upgrade(&self.global_ctx)?
                    .stats_manager()
                    .get_all_metrics();

                let metrics = snapshots
                    .into_iter()
                    .map(|snapshot| {
                        let mut labels = std::collections::BTreeMap::new();
                        for label in snapshot.labels.labels() {
                            labels.insert(label.key.clone(), label.value.clone());
                        }

                        MetricSnapshot {
                            name: snapshot.name_str(),
                            value: snapshot.value,
                            labels,
                        }
                    })
                    .collect();

                #[cfg(feature = "mpquic")]
                let (mp_peers, mp_egress_resources) = {
                    let peer_manager = weak_upgrade(&self.peer_manager)?;
                    let manager = peer_manager.get_mp_session_manager();
                    let peers = manager
                        .runtime_snapshots()
                        .await?
                        .into_iter()
                        .map(mp_peer_status_from_snapshot)
                        .collect();
                    let egress = manager
                        .egress_resource_snapshots()
                        .into_iter()
                        .map(mp_egress_status_from_snapshot)
                        .collect();
                    (peers, egress)
                };
                #[cfg(not(feature = "mpquic"))]
                let (mp_peers, mp_egress_resources) = (Vec::new(), Vec::new());

                Ok(GetStatsResponse {
                    metrics,
                    mp_peers,
                    mp_egress_resources,
                })
            }

            async fn get_prometheus_stats(
                &self,
                _: BaseController,
                _request: GetPrometheusStatsRequest,
            ) -> Result<GetPrometheusStatsResponse, rpc_types::error::Error> {
                let prometheus_text = weak_upgrade(&self.global_ctx)?
                    .stats_manager()
                    .export_prometheus();

                Ok(GetPrometheusStatsResponse { prometheus_text })
            }
        }

        StatsRpcService {
            global_ctx: Arc::downgrade(&self.global_ctx),
            #[cfg(feature = "mpquic")]
            peer_manager: Arc::downgrade(&self.peer_manager),
        }
    }

    pub fn get_config_patcher(&self) -> InstanceConfigPatcher {
        InstanceConfigPatcher {
            global_ctx: Arc::downgrade(&self.global_ctx),
            #[cfg(feature = "socks5")]
            socks5_server: Arc::downgrade(&self.socks5_server),
            peer_manager: Arc::downgrade(&self.peer_manager),
            conn_manager: Arc::downgrade(&self.conn_manager),
        }
    }

    fn get_config_service(&self) -> impl ConfigRpc<Controller = BaseController> + Clone + use<> {
        #[derive(Clone)]
        pub struct ConfigRpcService {
            patcher: InstanceConfigPatcher,
            global_ctx: Weak<GlobalCtx>,
        }

        #[async_trait::async_trait]
        impl ConfigRpc for ConfigRpcService {
            type Controller = BaseController;

            async fn patch_config(
                &self,
                _: Self::Controller,
                request: PatchConfigRequest,
            ) -> crate::proto::rpc_types::error::Result<PatchConfigResponse> {
                let Some(patch) = request.patch else {
                    return Ok(PatchConfigResponse::default());
                };

                self.patcher.apply_patch(patch).await?;
                Ok(PatchConfigResponse::default())
            }

            async fn get_config(
                &self,
                _: Self::Controller,
                _request: GetConfigRequest,
            ) -> crate::proto::rpc_types::error::Result<GetConfigResponse> {
                let global_ctx = weak_upgrade(&self.global_ctx)?;
                let config = NetworkConfig::new_from_config(&global_ctx.config)?;
                Ok(GetConfigResponse {
                    config: Some(config),
                    mp_scheduler_plugins: mp_scheduler_plugin_schemas(),
                    mp_providers: [
                        "udp-direct",
                        "udp-punch",
                        "faketcp-punch",
                        "relay-next-hop",
                        "manual",
                    ]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                    tcp_hole_punch_modes: ["auto", "faketcp", "tcp"]
                        .into_iter()
                        .map(str::to_string)
                        .collect(),
                })
            }
        }

        ConfigRpcService {
            patcher: self.get_config_patcher(),
            global_ctx: Arc::downgrade(&self.global_ctx),
        }
    }

    pub fn get_api_rpc_service(&self) -> impl InstanceRpcService + use<> {
        use crate::proto::api::instance::*;

        #[derive(Clone)]
        struct ApiRpcServiceImpl<A, B, C, D, E, F, G, H> {
            peer_mgr_rpc_service: A,
            connector_mgr_rpc_service: B,
            mapped_listener_mgr_rpc_service: C,
            vpn_portal_rpc_service: D,
            tcp_proxy_rpc_services: dashmap::DashMap<
                String,
                Arc<dyn TcpProxyRpc<Controller = BaseController> + Send + Sync>,
            >,
            acl_manage_rpc_service: E,
            port_forward_manage_rpc_service: F,
            stats_rpc_service: G,
            config_rpc_service: H,
            peer_center_rpc_service: Arc<PeerCenterInstanceService>,
            credential_manage_rpc_service: PeerManagerRpcService,
        }

        #[async_trait::async_trait]
        impl<
            A: PeerManageRpc<Controller = BaseController> + Send + Sync,
            B: ConnectorManageRpc<Controller = BaseController> + Send + Sync,
            C: MappedListenerManageRpc<Controller = BaseController> + Send + Sync,
            D: VpnPortalRpc<Controller = BaseController> + Send + Sync,
            E: AclManageRpc<Controller = BaseController> + Send + Sync,
            F: PortForwardManageRpc<Controller = BaseController> + Send + Sync,
            G: StatsRpc<Controller = BaseController> + Send + Sync,
            H: ConfigRpc<Controller = BaseController> + Send + Sync,
        > InstanceRpcService for ApiRpcServiceImpl<A, B, C, D, E, F, G, H>
        {
            fn get_peer_manage_service(&self) -> &dyn PeerManageRpc<Controller = BaseController> {
                &self.peer_mgr_rpc_service
            }

            fn get_connector_manage_service(
                &self,
            ) -> &dyn ConnectorManageRpc<Controller = BaseController> {
                &self.connector_mgr_rpc_service
            }

            fn get_mapped_listener_manage_service(
                &self,
            ) -> &dyn MappedListenerManageRpc<Controller = BaseController> {
                &self.mapped_listener_mgr_rpc_service
            }

            fn get_vpn_portal_service(&self) -> &dyn VpnPortalRpc<Controller = BaseController> {
                &self.vpn_portal_rpc_service
            }

            fn get_proxy_service(
                &self,
                client_type: &str,
            ) -> Option<Arc<dyn TcpProxyRpc<Controller = BaseController> + Send + Sync>>
            {
                self.tcp_proxy_rpc_services
                    .get(client_type)
                    .map(|e| e.clone())
            }

            fn get_acl_manage_service(&self) -> &dyn AclManageRpc<Controller = BaseController> {
                &self.acl_manage_rpc_service
            }

            fn get_port_forward_manage_service(
                &self,
            ) -> &dyn PortForwardManageRpc<Controller = BaseController> {
                &self.port_forward_manage_rpc_service
            }

            fn get_stats_service(&self) -> &dyn StatsRpc<Controller = BaseController> {
                &self.stats_rpc_service
            }

            fn get_config_service(&self) -> &dyn ConfigRpc<Controller = BaseController> {
                &self.config_rpc_service
            }

            fn get_peer_center_service(
                &self,
            ) -> Arc<dyn PeerCenterRpc<Controller = BaseController> + Send + Sync> {
                self.peer_center_rpc_service.clone()
            }

            fn get_credential_manage_service(
                &self,
            ) -> &dyn CredentialManageRpc<Controller = BaseController> {
                &self.credential_manage_rpc_service
            }
        }

        ApiRpcServiceImpl {
            peer_mgr_rpc_service: PeerManagerRpcService::new(self.peer_manager.clone()),
            connector_mgr_rpc_service: ConnectorManagerRpcService(Arc::downgrade(
                &self.conn_manager,
            )),
            mapped_listener_mgr_rpc_service: self.get_mapped_listener_manager_rpc_service(),
            vpn_portal_rpc_service: self.get_vpn_portal_rpc_service(),
            tcp_proxy_rpc_services: {
                let tcp_proxy_rpc_services: dashmap::DashMap<
                    String,
                    Arc<dyn TcpProxyRpc<Controller = BaseController> + Send + Sync>,
                > = dashmap::DashMap::new();

                if let Some(ip_proxy) = self.ip_proxy.as_ref() {
                    tcp_proxy_rpc_services.insert(
                        "tcp".to_string(),
                        Arc::new(TcpProxyRpcService::new(ip_proxy.tcp_proxy.clone())),
                    );
                }
                #[cfg(feature = "kcp")]
                if let Some(kcp_proxy) = self.kcp_proxy_src.as_ref() {
                    tcp_proxy_rpc_services.insert(
                        "kcp_src".to_string(),
                        Arc::new(TcpProxyRpcService::new(kcp_proxy.get_tcp_proxy())),
                    );
                }

                #[cfg(feature = "kcp")]
                if let Some(kcp_proxy) = self.kcp_proxy_dst.as_ref() {
                    tcp_proxy_rpc_services.insert(
                        "kcp_dst".to_string(),
                        Arc::new(KcpProxyDstRpcService::new(kcp_proxy)),
                    );
                }

                #[cfg(feature = "quic")]
                if let Some(quic_proxy) = self.quic_proxy.as_ref() {
                    if let Some(quic_src) = quic_proxy.src() {
                        tcp_proxy_rpc_services.insert(
                            "quic_src".to_string(),
                            Arc::new(TcpProxyRpcService::new(quic_src.get_tcp_proxy())),
                        );
                    }

                    if let Some(quic_dst) = quic_proxy.dst() {
                        tcp_proxy_rpc_services.insert(
                            "quic_dst".to_string(),
                            Arc::new(QuicProxyDstRpcService::new(quic_dst)),
                        );
                    }
                }

                tcp_proxy_rpc_services
            },
            acl_manage_rpc_service: PeerManagerRpcService::new(self.peer_manager.clone()),
            port_forward_manage_rpc_service: self.get_port_forward_manager_rpc_service(),
            stats_rpc_service: self.get_stats_rpc_service(),
            config_rpc_service: self.get_config_service(),
            peer_center_rpc_service: Arc::new(self.peer_center.get_rpc_service()),
            credential_manage_rpc_service: PeerManagerRpcService::new(self.peer_manager.clone()),
        }
    }

    pub fn get_global_ctx(&self) -> ArcGlobalCtx {
        self.global_ctx.clone()
    }

    pub fn get_vpn_portal_inst(&self) -> Arc<Mutex<Box<dyn VpnPortal>>> {
        self.vpn_portal.clone()
    }

    #[cfg(feature = "tun")]
    pub fn get_nic_ctx(&self) -> ArcNicCtx {
        self.nic_ctx.clone()
    }

    pub fn get_peer_packet_receiver(&self) -> Arc<Mutex<PacketRecvChanReceiver>> {
        self.peer_packet_receiver.clone()
    }

    #[cfg(mobile)]
    pub async fn setup_nic_ctx_for_mobile(
        nic_ctx: ArcNicCtx,
        global_ctx: ArcGlobalCtx,
        peer_manager: Arc<PeerManager>,
        peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,
        fd: i32,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("setup_nic_ctx_for_mobile, fd: {}", fd);
        Self::clear_nic_ctx(nic_ctx.clone(), peer_packet_receiver.clone()).await;
        if fd <= 0 {
            return Ok(());
        }
        let close_notifier = Arc::new(Notify::new());
        let mut new_nic_ctx = NicCtx::new(
            global_ctx.clone(),
            &peer_manager,
            peer_packet_receiver.clone(),
            close_notifier.clone(),
        );
        new_nic_ctx
            .run_for_mobile(fd)
            .await
            .with_context(|| "add ip failed")?;

        let magic_dns_runner = if let Some(ipv4) = global_ctx.get_ipv4() {
            Self::create_magic_dns_runner(peer_manager.clone(), None, ipv4)
        } else {
            None
        };
        Self::use_new_nic_ctx(nic_ctx.clone(), new_nic_ctx, magic_dns_runner).await;
        Ok(())
    }

    pub async fn clear_resources(&mut self) {
        self.peer_manager.clear_resources().await;
        #[cfg(feature = "tun")]
        Self::shutdown_nic_ctx(self.nic_ctx.clone()).await;
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        let my_peer_id = self.peer_manager.my_peer_id();
        let pm = Arc::downgrade(&self.peer_manager);
        #[cfg(feature = "tun")]
        let nic_ctx = self.nic_ctx.clone();
        tokio::spawn(async move {
            #[cfg(feature = "tun")]
            Instance::shutdown_nic_ctx(nic_ctx).await;
            if let Some(pm) = pm.upgrade() {
                pm.clear_resources().await;
            };

            let now = std::time::Instant::now();
            while now.elapsed().as_secs() < 10 {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                if pm.strong_count() == 0 {
                    tracing::info!(
                        "Instance for peer {} dropped, all resources cleared.",
                        my_peer_id
                    );
                    return;
                }
            }

            debug_assert!(
                false,
                "Instance for peer {} dropped, but resources not cleared in 1 seconds.",
                my_peer_id
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        common::config::{ConfigFileControl, ConfigLoader, TomlConfigLoader},
        common::global_ctx::tests::get_mock_global_ctx,
        common::transport_quality::rate::WireBitrate,
        instance::instance::{InstanceConfigPatcher, InstanceRpcServerHook},
        instance_manager::NetworkInstanceManager,
        proto::{api::config::InstanceConfigPatch, rpc_impl::standalone::RpcServerHook},
    };

    #[cfg(all(not(mobile), feature = "tun"))]
    #[test]
    fn first_nic_setup_failure_is_retried_only_inside_the_startup_window() {
        use super::{FIRST_NIC_SETUP_RETRY_WINDOW, retry_first_nic_setup};
        use std::time::Duration;

        let window = Duration::from_secs(60);
        assert!(retry_first_nic_setup(Duration::ZERO, window));
        // Wintun gives up on a slow adapter after ~15 s; the next attempt at
        // boot took another 10-14 s, so a second and third try must still fit.
        assert!(retry_first_nic_setup(Duration::from_secs(31), window));
        assert!(!retry_first_nic_setup(window, window));
        assert!(!retry_first_nic_setup(Duration::from_secs(90), window));

        if cfg!(target_os = "windows") {
            assert_eq!(FIRST_NIC_SETUP_RETRY_WINDOW, window);
        } else {
            // A first failure stays fatal at once where TUN creation is immediate.
            assert!(!retry_first_nic_setup(
                Duration::ZERO,
                FIRST_NIC_SETUP_RETRY_WINDOW
            ));
        }
    }

    #[tokio::test]
    async fn test_rpc_portal_whitelist() {
        use cidr::IpCidr;

        struct TestCase {
            remote_url: String,
            whitelist: Option<Vec<IpCidr>>,
            expected_result: bool,
        }

        let test_cases: Vec<TestCase> = vec![
            // Test default whitelist (127.0.0.0/8, ::1/128)
            TestCase {
                remote_url: "tcp://127.0.0.1:15888".to_string(),
                whitelist: None,
                expected_result: true,
            },
            TestCase {
                remote_url: "tcp://127.1.2.3:15888".to_string(),
                whitelist: None,
                expected_result: true,
            },
            TestCase {
                remote_url: "tcp://192.168.1.1:15888".to_string(),
                whitelist: None,
                expected_result: false,
            },
            // Test custom whitelist
            TestCase {
                remote_url: "tcp://192.168.1.10:15888".to_string(),
                whitelist: Some(vec![
                    "192.168.1.0/24".parse().unwrap(),
                    "10.0.0.0/8".parse().unwrap(),
                ]),
                expected_result: true,
            },
            TestCase {
                remote_url: "tcp://10.1.2.3:15888".to_string(),
                whitelist: Some(vec![
                    "192.168.1.0/24".parse().unwrap(),
                    "10.0.0.0/8".parse().unwrap(),
                ]),
                expected_result: true,
            },
            TestCase {
                remote_url: "tcp://172.16.0.1:15888".to_string(),
                whitelist: Some(vec![
                    "192.168.1.0/24".parse().unwrap(),
                    "10.0.0.0/8".parse().unwrap(),
                ]),
                expected_result: false,
            },
            // Test empty whitelist (should reject all connections)
            TestCase {
                remote_url: "tcp://127.0.0.1:15888".to_string(),
                whitelist: Some(vec![]),
                expected_result: false,
            },
            // Test broad whitelist (0.0.0.0/0 and ::/0 accept all IP addresses)
            TestCase {
                remote_url: "tcp://8.8.8.8:15888".to_string(),
                whitelist: Some(vec!["0.0.0.0/0".parse().unwrap()]),
                expected_result: true,
            },
            // Test edge case: specific IP whitelist
            TestCase {
                remote_url: "tcp://192.168.1.5:15888".to_string(),
                whitelist: Some(vec!["192.168.1.5/32".parse().unwrap()]),
                expected_result: true,
            },
            TestCase {
                remote_url: "tcp://192.168.1.6:15888".to_string(),
                whitelist: Some(vec!["192.168.1.5/32".parse().unwrap()]),
                expected_result: false,
            },
            // Test invalid URL (this case will fail during URL parsing)
            TestCase {
                remote_url: "invalid-url".to_string(),
                whitelist: None,
                expected_result: false,
            },
            // Test URL without IP address (this case will fail during IP parsing)
            TestCase {
                remote_url: "tcp://localhost:15888".to_string(),
                whitelist: None,
                expected_result: false,
            },
        ];

        for case in test_cases {
            let hook = InstanceRpcServerHook::new(case.whitelist.clone());
            let tunnel_info = Some(crate::proto::common::TunnelInfo {
                remote_addr: Some(crate::proto::common::Url {
                    url: case.remote_url.clone(),
                }),
                ..Default::default()
            });

            let result = hook.on_new_client(tunnel_info).await;
            if case.expected_result {
                assert!(
                    result.is_ok(),
                    "Expected success for remote_url:{},whitelist:{:?},but got: {:?}",
                    case.remote_url,
                    case.whitelist,
                    result
                );
            } else {
                assert!(
                    result.is_err(),
                    "Expected failure for remote_url:{},whitelist:{:?},but got: {:?}",
                    case.remote_url,
                    case.whitelist,
                    result
                );
            }
        }
    }

    // The provider role exists on Linux only; elsewhere it is refused before
    // the prefix is looked at (see the test below this one).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn validate_public_ipv6_patch_rejects_non_global_prefix() {
        let global_ctx = get_mock_global_ctx();
        let patch = InstanceConfigPatch {
            ipv6_public_addr_provider: Some(true),
            ipv6_public_addr_prefix: Some("fd00::/64".to_string()),
            ..Default::default()
        };

        let err =
            InstanceConfigPatcher::validate_public_ipv6_patch(&global_ctx, &patch).unwrap_err();

        assert!(
            err.to_string()
                .contains("not a valid global unicast IPv6 prefix")
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn validate_public_ipv6_patch_refuses_the_provider_role_off_linux() {
        let global_ctx = get_mock_global_ctx();
        let patch = InstanceConfigPatch {
            ipv6_public_addr_provider: Some(true),
            ipv6_public_addr_prefix: Some("2001:db8:100::/64".to_string()),
            ..Default::default()
        };

        let err =
            InstanceConfigPatcher::validate_public_ipv6_patch(&global_ctx, &patch).unwrap_err();

        assert!(err.to_string().contains("requires Linux"));
    }

    #[test]
    fn tcp_hole_punch_mode_patch_is_normalized_and_rejects_unknown_values() {
        assert_eq!(
            InstanceConfigPatcher::parse_tcp_hole_punch_mode_patch(Some("  FAKETCP  ")).unwrap(),
            Some("faketcp".to_string())
        );
        assert_eq!(
            InstanceConfigPatcher::parse_tcp_hole_punch_mode_patch(None).unwrap(),
            None
        );
        assert!(
            InstanceConfigPatcher::parse_tcp_hole_punch_mode_patch(Some("framed-tcp")).is_err()
        );
    }

    #[tokio::test]
    async fn config_patch_updates_tcp_hole_punch_mode_without_restarting() {
        let global_ctx = get_mock_global_ctx();
        let patcher = InstanceConfigPatcher {
            global_ctx: std::sync::Arc::downgrade(&global_ctx),
            #[cfg(feature = "socks5")]
            socks5_server: std::sync::Weak::new(),
            peer_manager: std::sync::Weak::new(),
            conn_manager: std::sync::Weak::new(),
        };

        patcher
            .apply_patch(InstanceConfigPatch {
                tcp_hole_punch_mode: Some("faketcp".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(global_ctx.get_flags().tcp_hole_punch_mode, "faketcp");
        assert!(
            global_ctx
                .config
                .dump()
                .contains("tcp_hole_punch_mode = \"faketcp\"")
        );
    }

    /// MP_SQM_PLAN.md S2.1: the whole point of `reapply_egress_ceiling` is
    /// that `apply_patch`'s `egress_wire_limit_bps` branch re-caps the
    /// already-running `EgressQualityManager` live, not just the round-trip
    /// `Flags` value S2.0 already covered.
    #[tokio::test]
    async fn config_patch_hot_applies_the_global_egress_ceiling_without_restart() {
        let global_ctx = get_mock_global_ctx();
        let patcher = InstanceConfigPatcher {
            global_ctx: std::sync::Arc::downgrade(&global_ctx),
            #[cfg(feature = "socks5")]
            socks5_server: std::sync::Weak::new(),
            peer_manager: std::sync::Weak::new(),
            conn_manager: std::sync::Weak::new(),
        };
        let probe_id = crate::common::egress_inventory::EgressStableId::Fallback {
            platform: "test".to_string(),
            opaque: "probe".to_string(),
        };
        assert_eq!(
            global_ctx.egress_quality_manager().ceiling_info_for(&probe_id).source,
            crate::common::egress_quality::CeilingSource::None,
            "no ceiling should be configured before the patch"
        );

        patcher
            .apply_patch(InstanceConfigPatch {
                egress_wire_limit_bps: Some(2_000_000),
                ..Default::default()
            })
            .await
            .unwrap();

        let info = global_ctx.egress_quality_manager().ceiling_info_for(&probe_id);
        assert_eq!(info.source, crate::common::egress_quality::CeilingSource::Static);
        assert_eq!(info.ceiling_bps, Some(WireBitrate(2_000_000)));

        // Patching it away (0 cancels the limit, same convention as the
        // flags-level round-trip) must live-uncap it too.
        patcher
            .apply_patch(InstanceConfigPatch {
                egress_wire_limit_bps: Some(0),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            global_ctx.egress_quality_manager().ceiling_info_for(&probe_id),
            crate::common::egress_quality::CeilingInfo {
                ceiling_bps: None,
                source: crate::common::egress_quality::CeilingSource::None,
            }
        );
    }

    /// MP_SQM_PLAN.md S2.2's grey-box RED spec ("`PatchNetworkInstanceConfig`
    /// 改限速/调度器后运行态变化且实例未重启（PID、peer 连接不断）"), pulled forward
    /// into S2.1 verification: the local half of that RPC is exactly
    /// `InstanceConfigPatcher::apply_patch` (`rpc_service::instance_manage::
    /// patch_network_instance_config` just resolves the instance and forwards
    /// to it, see that function's own doc). Two real `PeerManager`s complete a
    /// real handshake over a real (in-process) tunnel first; the patch must
    /// neither restart the process nor tear down and re-establish that
    /// connection, and the connection must still functionally route traffic
    /// afterward -- not just still appear in a stale map.
    #[tokio::test]
    async fn config_patch_survives_with_established_peer_connections_and_no_restart() {
        let client = crate::peers::tests::create_mock_peer_manager().await;
        let server = crate::peers::tests::create_mock_peer_manager().await;
        crate::peers::tests::connect_peer_manager(client.clone(), server.clone()).await;
        crate::peers::tests::wait_route_appear(client.clone(), server.clone())
            .await
            .unwrap();

        let client_peer_id = client.my_peer_id();
        let conn_id_before = server
            .get_peer_map()
            .get_peer_default_conn_id(client_peer_id)
            .await
            .expect("server must already have an established connection to the client");

        let pid_before = std::process::id();
        let patcher = InstanceConfigPatcher {
            global_ctx: std::sync::Arc::downgrade(&server.get_global_ctx()),
            #[cfg(feature = "socks5")]
            socks5_server: std::sync::Weak::new(),
            peer_manager: std::sync::Arc::downgrade(&server),
            conn_manager: std::sync::Weak::new(),
        };

        patcher
            .apply_patch(InstanceConfigPatch {
                egress_wire_limit_bps: Some(2_000_000),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(
            std::process::id(),
            pid_before,
            "a config hot-patch must never restart the process"
        );
        let conn_id_after = server
            .get_peer_map()
            .get_peer_default_conn_id(client_peer_id)
            .await
            .expect("the peer connection must still be present after the patch");
        assert_eq!(
            conn_id_before, conn_id_after,
            "the existing peer connection must not have been torn down and re-established by \
             the patch"
        );

        // Functional proof, not just bookkeeping: routing between the two
        // nodes must still work after the patch, with no re-handshake.
        crate::peers::tests::wait_route_appear(client, server.clone())
            .await
            .unwrap();

        // And the patch actually took effect, through the same
        // PatchNetworkInstanceConfig-shaped path this test exercises (not a
        // direct `EgressQualityManager` call, unlike the manager-level tests
        // above).
        let probe_id = crate::common::egress_inventory::EgressStableId::Fallback {
            platform: "test".to_string(),
            opaque: "probe".to_string(),
        };
        let info = server.get_global_ctx().egress_quality_manager().ceiling_info_for(&probe_id);
        assert_eq!(info.source, crate::common::egress_quality::CeilingSource::Static);
        assert_eq!(info.ceiling_bps, Some(WireBitrate(2_000_000)));
    }

    /// Worklist 103: a patch carrying `mp.selection` takes effect without
    /// restarting the process or touching the peer connection, and the session
    /// manager the next control tick asks selects with the new values.
    #[cfg(feature = "mpquic")]
    #[tokio::test]
    async fn config_patch_hot_applies_mp_selection_without_restart() {
        use crate::proto::common::{MpSelectionConfig, MpSelectionKindRule};

        let client = crate::peers::tests::create_mock_peer_manager().await;
        let server = crate::peers::tests::create_mock_peer_manager().await;
        crate::peers::tests::connect_peer_manager(client.clone(), server.clone()).await;
        crate::peers::tests::wait_route_appear(client.clone(), server.clone())
            .await
            .unwrap();
        let client_peer_id = client.my_peer_id();
        let conn_id_before = server
            .get_peer_map()
            .get_peer_default_conn_id(client_peer_id)
            .await
            .expect("server must already have an established connection to the client");
        let manager = server.get_mp_session_manager();
        assert_eq!(
            manager.selection_params().await,
            crate::connector::mp_optimizer::SelectionParams::default(),
            "before the patch the built-in values apply"
        );

        let patcher = InstanceConfigPatcher {
            global_ctx: std::sync::Arc::downgrade(&server.get_global_ctx()),
            #[cfg(feature = "socks5")]
            socks5_server: std::sync::Weak::new(),
            peer_manager: std::sync::Arc::downgrade(&server),
            conn_manager: std::sync::Weak::new(),
        };
        let selection = MpSelectionConfig {
            kind_rules: vec![MpSelectionKindRule {
                carrier_kind: "udp-direct".into(),
                ip_family: "v6".into(),
                tier: "primary".into(),
                rtt_bias_ms: 0,
            }],
            switch_min_ms: 2,
            switch_percent: 25,
            lossy_percent: 20,
            unmeasured_rtt_ms: 50,
        };
        let pid_before = std::process::id();
        patcher
            .apply_patch(InstanceConfigPatch {
                mp: Some(crate::proto::common::MpConfig {
                    selection: Some(selection.clone()),
                    ..crate::common::config::gen_default_mp_config()
                }),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(std::process::id(), pid_before);
        assert_eq!(
            server
                .get_peer_map()
                .get_peer_default_conn_id(client_peer_id)
                .await,
            Some(conn_id_before),
            "the peer connection must survive the patch"
        );
        let flags = server.get_global_ctx().get_flags();
        assert_eq!(flags.mp.unwrap().selection, Some(selection.clone()));
        let params = manager.selection_params().await;
        assert_eq!(params.switch_min_micros, 2_000);
        assert_eq!(params.switch_percent, 25);
        assert_eq!(params.lossy_loss, 0.20);
        assert_eq!(params.unmeasured_rtt_micros, 50_000);
        assert_eq!(
            crate::connector::mp_optimizer::transport_bias(
                crate::connector::mp_path::CarrierKind::UdpDirect,
                "[2001:db8::1]:9".parse().unwrap(),
                &params
            ),
            (crate::connector::mp_optimizer::PathTier::Primary, 0)
        );

        // An invalid selection is refused and leaves the running one alone.
        let mut invalid = selection.clone();
        invalid.switch_percent = 101;
        patcher
            .apply_patch(InstanceConfigPatch {
                mp: Some(crate::proto::common::MpConfig {
                    selection: Some(invalid),
                    ..crate::common::config::gen_default_mp_config()
                }),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(manager.selection_params().await.switch_percent, 25);
    }

    /// MP_SQM_PLAN.md S2.2: `NetworkInstanceRunningInfo.mp_runtime` used to be
    /// hardcoded `None` in `launcher.rs::get_running_info` (S2.0 landed only
    /// the proto field); this proves the real wiring against a REAL running
    /// instance -- no mocked stats, no netns (avoids the `.88` test
    /// account's missing CAP_NET_ADMIN the way `no_tun = true` already does
    /// for the existing `credential_tests.rs` fixtures) -- rather than only
    /// unit-testing the snapshot-to-proto mapping in isolation (that half is
    /// `mp_runtime_snapshot_maps_to_structured_stats_status`, above).
    #[tokio::test]
    #[serial_test::serial]
    async fn get_running_info_reports_a_populated_mp_runtime_for_a_real_running_instance() {
        let manager = NetworkInstanceManager::new();
        let cfg = TomlConfigLoader::new_from_str("listeners = []").unwrap();
        let mut flags = cfg.get_flags();
        flags.no_tun = true;
        cfg.set_flags(flags);

        let instance_id = manager
            .run_network_instance(cfg, false, ConfigFileControl::STATIC_CONFIG)
            .unwrap();

        // Poll for the launcher thread to actually reach a running state with
        // a live api_service -- `run_network_instance`'s synchronous
        // `instance.start()` only spawns it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let info = loop {
            if let Some(info) = manager.get_network_info(&instance_id).await
                && info.running
            {
                break info;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "instance did not reach a running state (with no_tun, so this cannot be a TUN \
                 permission issue)"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        };

        let runtime = info
            .mp_runtime
            .expect("a real running instance must report Some(mp_runtime), not the old hardcoded None");
        assert!(
            runtime.peers.is_empty() && runtime.egress.is_empty(),
            "no MP peers/egress exist in this test, so the real (non-mocked) MpSessionManager \
             must report empty vectors, not fabricated data"
        );
        // A second sample, after real wall-clock time has passed, must have
        // advanced -- proves this is a live monotonic reading on every call,
        // not a value computed once and cached (`monotonic_now_ms`'s process
        // epoch is set on its own first call anywhere in the process, so the
        // very first reading here can legitimately still be 0ms in -- this
        // deliberately does not assert `> 0` on it alone).
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let info2 = manager.get_network_info(&instance_id).await.unwrap();
        assert!(
            info2.mp_runtime.unwrap().sample_time_ms > runtime.sample_time_ms,
            "sample_time_ms did not advance between two real calls"
        );

        manager.delete_network_instance(vec![instance_id]).unwrap();
    }

    /// Pure matching step of `reapply_egress_ceiling`: `MpConfig.egress_limits`
    /// overrides the global ceiling for the NIC it names (by
    /// `platform_name`, the raw OS interface name), and leaves every other
    /// interface's `EgressStableId` unmapped -- the caller falls back to the
    /// global ceiling for those, not a decision this function makes itself.
    #[test]
    fn resolve_per_device_ceilings_matches_by_platform_name_and_skips_unknown_names() {
        use crate::common::egress_inventory::{
            EgressInterfaceSnapshot, EgressInventorySnapshot, EgressKind, EgressStableId,
            OperState, WatchMode,
        };

        fn interface(ifindex: u32, name: &str) -> EgressInterfaceSnapshot {
            EgressInterfaceSnapshot {
                id: EgressStableId::Linux {
                    netns_inode: 1,
                    ifindex,
                },
                revision: 1,
                generation: 1,
                platform_name: name.to_string(),
                display_name: name.to_string(),
                aliases: vec![name.to_string()],
                hardware_address: None,
                runtime_ifindex: ifindex,
                kind: EgressKind::Physical,
                oper_state: OperState::Up,
                addresses: Vec::new(),
                mtu: Some(1500),
                transmit_speed_bps: None,
                receive_speed_bps: None,
                is_eligible: true,
                exclusion_reasons: Vec::new(),
                watch_mode: WatchMode::Native,
            }
        }

        let eth0 = interface(10, "eth0");
        let eth1 = interface(11, "eth1");
        let snapshot = EgressInventorySnapshot {
            revision: 1,
            observed_at_unix_ms: 1,
            interfaces: [eth0.clone(), eth1.clone()]
                .into_iter()
                .map(|interface| (interface.id.clone(), interface))
                .collect(),
        };

        let limits = vec![
            crate::proto::common::MpEgressLimit {
                egress_device: "eth0".to_string(),
                limit_bps: 4_000_000,
            },
            crate::proto::common::MpEgressLimit {
                egress_device: "does-not-exist".to_string(),
                limit_bps: 1,
            },
        ];

        let resolved = InstanceConfigPatcher::resolve_per_device_ceilings(&limits, &snapshot);
        assert_eq!(resolved.len(), 1, "an unmatched device name must not be applied at all");
        assert_eq!(resolved.get(&eth0.id), Some(&WireBitrate(4_000_000)));
        assert_eq!(resolved.get(&eth1.id), None);
    }

    #[tokio::test]
    async fn validate_public_ipv6_patch_allows_enabling_auto_with_manual_ipv6() {
        let global_ctx = get_mock_global_ctx();
        global_ctx.set_ipv6(Some("fd00::1/64".parse().unwrap()));

        let patch = InstanceConfigPatch {
            ipv6_public_addr_auto: Some(true),
            ..Default::default()
        };

        assert!(InstanceConfigPatcher::validate_public_ipv6_patch(&global_ctx, &patch).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn validate_public_ipv6_patch_ignores_runtime_auto_ipv6_cache() {
        let global_ctx = get_mock_global_ctx();
        global_ctx.config.set_ipv6_public_addr_auto(true);
        global_ctx.set_ipv6(Some("2001:db8::10/64".parse().unwrap()));

        let patch = InstanceConfigPatch {
            ipv6_public_addr_provider: Some(true),
            ipv6_public_addr_prefix: Some("2001:db8:100::/64".to_string()),
            ..Default::default()
        };

        assert!(InstanceConfigPatcher::validate_public_ipv6_patch(&global_ctx, &patch).is_ok());
    }

    #[cfg(feature = "mpquic")]
    #[test]
    fn mp_runtime_snapshot_maps_to_structured_stats_status() {
        use crate::{
            connector::{
                mp_path::{CarrierKind, PathLifecycleState, PathMeasurements, ResourceGroupId},
                mp_session::{
                    MpOptimizationSnapshot, MpPathRuntimeSnapshot, MpPeerRuntimeSnapshot,
                },
            },
            instance::instance::mp_peer_status_from_snapshot,
            tunnel::mpquic::{CarrierId, PathKey},
        };

        let key = PathKey {
            carrier_id: CarrierId(41),
            local_addr: "10.0.0.1:10001".parse().unwrap(),
            remote_addr: "10.0.0.2:10002".parse().unwrap(),
        };
        let status = mp_peer_status_from_snapshot(MpPeerRuntimeSnapshot {
            peer_id: 7,
            paths: vec![MpPathRuntimeSnapshot {
                key,
                carrier_kind: CarrierKind::RelayNextHop,
                relay_metadata: Some(crate::connector::mp_path::RelayPathMetadata {
                    first_hop_peer_id: 11,
                    egress_first_hop_peer_id: 12,
                    route_generation: 37,
                }),
                local_resource: ResourceGroupId::new("wan-a"),
                remote_resource: ResourceGroupId::new("wan-b"),
                state: PathLifecycleState::AVAILABLE,
                measurements: PathMeasurements {
                    btlbw: 80_000_000,
                    delivery_rate: 72_000_000,
                    propagation_rtt_micros: 12_000,
                    loss_rate: 0.01,
                    app_limited: false,
                    sample_age_micros: Some(250_000),
                    congestion_control_state: tquic::CongestionControlState::ProbeBandwidth,
                    observed_local_addr: None,
                },
                telemetry: None,
                target_rate_bps: Some(60_000_000),
                egress_device: "eth0".to_string(),
                user_policy: String::new(),
            selection: Default::default(),
            }],
            optimization: Some(MpOptimizationSnapshot {
                active_paths: vec![key],
                targets: Vec::new(),
                candidate_count: 1,
                eligible_count: 1,
            }),
            effective_congestion_control: "cubic".into(),
            // MP_SQM_PLAN.md S2.6: deliberately different strings, so the
            // assertions below prove `mp_peer_status_from_snapshot` passes
            // these two through verbatim rather than deriving them from
            // `effective_congestion_control` (a stale copy of either would
            // false-negative this test).
            desired_congestion_control: "bbr".into(),
            reconnect_required: true,
            standalone: false,
            brutal_tx_bps: None,
            peer_advertised_rx_bps: None,
            data_plane: Some(crate::tunnel::mp_dataplane::disabled_status("standalone")),
            faketcp_upgrade: None,
            switch_threshold_micros: 5_000,
            active_tier: "primary".into(),
        });

        assert_eq!(status.peer_id, 7);
        assert_eq!(status.switch_threshold_micros, 5_000);
        assert_eq!(status.active_tier, "primary");
        assert_eq!(
            status.data_plane.as_ref().map(|plane| plane.fallback_reason.as_str()),
            Some("standalone")
        );
        assert_eq!(status.desired_congestion_control, "bbr");
        assert!(status.reconnect_required);
        assert_eq!(status.candidate_count, 1);
        assert_eq!(status.paths.len(), 1);
        assert_eq!(status.paths[0].carrier_kind, "relay-next-hop");
        assert_eq!(status.paths[0].first_hop_peer_id, Some(11));
        assert_eq!(status.paths[0].egress_first_hop_peer_id, Some(12));
        assert_eq!(status.paths[0].route_generation, Some(37));
        assert_eq!(status.paths[0].btlbw_bps, 80_000_000);
        assert_eq!(status.paths[0].target_rate_bps, Some(60_000_000));
        assert_eq!(status.active_paths.len(), 1);
        assert_eq!(status.eligible_count, 1);
        assert_eq!(status.effective_engine, "tquic");
        assert_eq!(status.effective_congestion_control, "cubic");
        assert_eq!(status.path_mode, "n=1");
        assert_eq!(status.scheduler_state, "no-choice-single-path");
        assert_eq!(status.unsupported_reason, None);
    }

    #[cfg(feature = "mpquic")]
    #[test]
    fn relay_path_stats_export_validating_mtu_as_validated_once_lifecycle_accepts() {
        use crate::{
            connector::{
                mp_path::{CarrierKind, PathLifecycleState, PathMeasurements, ResourceGroupId},
                mp_session::MpPathRuntimeSnapshot,
            },
            instance::instance::mp_path_status_from_snapshot,
            tunnel::mpquic::{CarrierId, MpPathTelemetry, PathKey},
        };

        let key = PathKey {
            carrier_id: CarrierId(9),
            local_addr: "[fd4d:5000::1]:44443".parse().unwrap(),
            remote_addr: "[fd4d:5000::2]:44443".parse().unwrap(),
        };
        let status = mp_path_status_from_snapshot(MpPathRuntimeSnapshot {
            key,
            carrier_kind: CarrierKind::RelayNextHop,
            relay_metadata: Some(crate::connector::mp_path::RelayPathMetadata {
                first_hop_peer_id: 11,
                egress_first_hop_peer_id: 11,
                route_generation: 2,
            }),
            local_resource: ResourceGroupId::new("relay-a"),
            remote_resource: ResourceGroupId::new("relay-b"),
            state: PathLifecycleState::AVAILABLE,
            measurements: PathMeasurements::default(),
            telemetry: Some(MpPathTelemetry {
                local_addr: key.local_addr,
                remote_addr: key.remote_addr,
                validation_state: tquic::PathState::ValidatingMTU,
                bandwidth_model_valid: true,
                btlbw: 1000,
                delivery_rate: 500,
                app_limited: false,
                sample_age_micros: Some(1000),
                congestion_control_state: tquic::CongestionControlState::Startup,
                observed_local_addr: None,
                scheduler_target_rate_bps: Some(1000),
                min_rtt_micros: 900,
                windowed_min_rtt_micros: 950,
                backed_off: true,
                srtt_micros: 1000,
                sent_bytes: 100,
                recv_bytes: 90,
                lost_bytes: 0,
                acked_bytes: 90,
                max_inflight_bytes: 200,
                cwnd_bytes: 12_000,
                pacing_rate_bps: 8_000_000,
            }),
            target_rate_bps: Some(1000),
            egress_device: "eth0".to_string(),
            user_policy: String::new(),
            selection: crate::connector::mp_session::PathSelectionDiagnostics {
                recent_loss: Some(0.02),
                first_hop_loss: Some(1.0),
                not_selected_reason: "lossy-first-hop".to_string(),
                tier: "backup".to_string(),
                rtt_bias_micros: -3_000,
                ranked_rtt_micros: 333_000,
                selected: true,
            },
        });

        assert_eq!(
            status.validation_state, "validated",
            "active relay paths stuck in ValidatingMTU must export as validated"
        );
        assert_eq!(status.carrier_kind, "relay-next-hop");
        assert_eq!(status.lifecycle_state, "available");
        // MP_SQM_PLAN.md S2.2/S2.3: cwnd/pacing/inflight/user_policy/
        // egress_device must be read from the real snapshot/telemetry, not
        // left as the old hardcoded placeholders.
        assert_eq!(status.cwnd_bytes, 12_000);
        assert_eq!(status.pacing_rate_bps, 8_000_000);
        assert_eq!(status.bytes_in_flight, 200);
        assert_eq!(status.egress_device, "eth0");
        assert_eq!(status.user_policy, "");
        // The selection's view of the path (MP weak-network plan W4).
        assert_eq!(status.windowed_min_rtt_micros, 950);
        assert_eq!(status.recent_loss, Some(0.02));
        assert_eq!(status.first_hop_loss, Some(1.0));
        assert!(status.backed_off);
        assert_eq!(status.not_selected_reason, "lossy-first-hop");
        // Where the path stands in the selection (worklist 103).
        assert_eq!(status.tier, "backup");
        assert_eq!(status.rtt_bias_micros, -3_000);
        assert_eq!(status.ranked_rtt_micros, 333_000);
        assert!(status.selected);
    }

    #[test]
    fn mp_scheduler_plugin_schema_is_data_driven_for_gui() {
        // MP_SQM_PLAN.md S2.7: schedulers then congestion controls, one registry.
        let schemas = super::mp_scheduler_plugin_schemas();
        assert_eq!(
            schemas
                .iter()
                .map(|schema| (schema.kind.as_str(), schema.name.as_str()))
                .collect::<Vec<_>>(),
            [
                ("scheduler", "min-rtt"),
                ("scheduler", "round-robin"),
                ("scheduler", "redundant"),
                ("scheduler", "sqm-weighted"),
                ("congestion_control", "engine-default"),
                ("congestion_control", "bbr"),
                ("congestion_control", "bbr3"),
                ("congestion_control", "cubic"),
                ("congestion_control", "copa"),
                ("congestion_control", "brutal"),
            ]
        );
        let brutal = schemas.iter().find(|schema| schema.name == "brutal").unwrap();
        assert_eq!(brutal.tunables[0].key, "up_mbps");
        assert_eq!(brutal.tunables[0].default_json, "50.0");
        let sqm = schemas
            .iter()
            .find(|schema| schema.name == "sqm-weighted")
            .unwrap();
        assert_eq!(sqm.tunables.len(), 1);
        assert_eq!(sqm.tunables[0].key, "latency_bandwidth");
        assert_eq!(sqm.tunables[0].kind, "slider");
        assert_eq!(sqm.tunables[0].min, Some(0.0));
        assert_eq!(sqm.tunables[0].max, Some(1.0));
        assert_eq!(sqm.tunables[0].step, Some(0.01));
        assert_eq!(sqm.tunables[0].default_json, "0.5");
    }
}

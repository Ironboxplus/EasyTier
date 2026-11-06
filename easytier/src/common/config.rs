use std::{
    hash::Hasher,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::Context;
use ariadne::{CharSet, Config as AriadneConfig, IndexType, Label, Report, ReportKind, Source};
use base64::{Engine as _, prelude::BASE64_STANDARD};
use clap::ValueEnum;
use clap::builder::PossibleValue;
use prost_reflect::{DynamicMessage, ReflectMessage, SerializeOptions};
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString, VariantArray};
use tokio::io::AsyncReadExt as _;

use crate::{
    common::stun::StunInfoCollector,
    instance::dns_server::DEFAULT_ET_DNS_ZONE,
    proto::{
        acl::Acl,
        api::manage::ConfigSource as RpcConfigSource,
        common::{CompressionAlgoPb, MpConfig, PortForwardConfigPb, SecureModeConfig, SocketType},
    },
    tunnel::{IpScheme, TunnelScheme, generate_digest_from_str},
};

use super::env_parser;

pub type Flags = crate::proto::common::FlagsInConfig;

pub const DEFAULT_TCP_HOLE_PUNCH_MODE: &str = "auto";

/// Shared floor for `Flags.egress_wire_limit_bps` (MP_SQM_PLAN.md §4.4 (b)
/// follow-up review). Defined exactly once: `core.rs`'s CLI merge and
/// `instance_manager.rs`'s `run_network_instance` -- the one function every
/// instance-start path (CLI, GUI, web console/RPC, FFI/library callers) is
/// confirmed to funnel through -- both call [`validate_egress_wire_limit_bps`]
/// against this same value rather than each hard-coding their own copy.
pub const MIN_EGRESS_WIRE_LIMIT_BPS: u64 = 8_000;

/// Reject a configured `egress_wire_limit_bps` below [`MIN_EGRESS_WIRE_LIMIT_BPS`],
/// including 0. A CLI/GUI "limit" field commonly uses 0 to mean "unlimited",
/// but this codebase's other bps-limit flags (`instance_recv_bps_limit`,
/// `foreign_relay_bps_limit`) use `u64::MAX` for that instead -- a literal 0
/// here would stay a literal zero-rate ceiling, permanently rejecting every
/// data reservation (`ExplicitPause`/`AwaitingExternalUpdate`) from the
/// moment a physical egress scope is created. Reject loudly at the point
/// where the config is about to take effect rather than silently
/// reinterpreting 0 as "no ceiling" (surprising an operator who deliberately
/// typed 0) or letting the instance start and quietly never send data.
pub fn validate_egress_wire_limit_bps(limit: u64) -> Result<(), anyhow::Error> {
    if limit < MIN_EGRESS_WIRE_LIMIT_BPS {
        anyhow::bail!(
            "egress_wire_limit_bps must be at least {MIN_EGRESS_WIRE_LIMIT_BPS} bits/s \
             ({} wire bytes/s) -- a lower value, including 0, would leave every physical \
             egress scope unable to send data indefinitely. Omit the flag entirely (or \
             leave it unset in the config file) for no ceiling.",
            MIN_EGRESS_WIRE_LIMIT_BPS / 8
        );
    }
    Ok(())
}

/// `[flags.mp]` fields that no longer exist. The flags are parsed strictly
/// (an unknown key is an error), so a config written by an older build would
/// stop loading without this: `mp.sqm.autorate_enforce` (shaping to the
/// Autorate estimate is always on) and `mp.data_plane.datagram_bypass_cwnd`
/// (datagram classes always bypass the congestion window), and the Top-K
/// optimizer's `optimizer`, `lambda`, `churn_penalty`, `path_penalty`,
/// `switch_margin` and `confirm_rounds` (paths are now chosen by round-trip
/// time, MP_FIX_PHASES.md phase 4), and `max_sample_age_ms` (nothing ages a
/// measurement out any more).
fn remove_retired_mp_fields(mp: &mut serde_json::Map<String, serde_json::Value>) {
    for field in [
        "optimizer",
        "lambda",
        "churn_penalty",
        "path_penalty",
        "switch_margin",
        "confirm_rounds",
        "max_sample_age_ms",
    ] {
        mp.remove(field);
    }
    for (section, field) in [("sqm", "autorate_enforce"), ("data_plane", "datagram_bypass_cwnd")] {
        if let Some(serde_json::Value::Object(section)) = mp.get_mut(section) {
            section.remove(field);
        }
    }
}

pub fn gen_default_mp_config() -> MpConfig {
    MpConfig {
        enabled: false,
        packet_scheduler: "sqm-weighted".to_string(),
        scheduler_params_json: "{}".to_string(),
        // One path carries data; the other usable paths stand by for
        // failover. A host with several NICs/WANs raises it to use them.
        kmax: 1,
        control_interval_ms: 500,
        establishment_timeout_ms: 10_000,
        congestion_control: "engine-default".to_string(),
        providers: vec![
            "udp-direct".to_string(),
            "udp-punch".to_string(),
            "faketcp-punch".to_string(),
            "relay-next-hop".to_string(),
        ],
        egress_devices: Vec::new(),
        resource_groups: Vec::new(),
        manual_paths: Vec::new(),
        disable_overlay_weighted_routing: true,
        path_policies: Vec::new(),
        congestion_control_params_json: "{}".to_string(),
        egress_limits: Vec::new(),
        sqm: Some(crate::proto::common::MpSqmConfig {
            enabled: false,
            target_ms: 5,
            interval_ms: 100,
            autorate_min_bps: 0,
            autorate_max_bps: 0,
            reflectors: Vec::new(),
            reflectors_disabled: false,
        }),
        session_generation: 0,
        punch_attempts: DEFAULT_MP_PUNCH_ATTEMPTS,
        data_plane: None,
        punch_pps: 0,
        punch_rate_limits: Vec::new(),
    }
}

/// MP_SQM_PLAN.md S2.14: native punches per peer; 1 keeps the old behavior.
pub const DEFAULT_MP_PUNCH_ATTEMPTS: u32 = 1;
pub const MAX_MP_PUNCH_ATTEMPTS: u32 = 8;

/// `MpConfig.punch_attempts` with the proto default (0) mapped to 1.
pub fn effective_mp_punch_attempts(config: &MpConfig) -> u32 {
    config.punch_attempts.clamp(1, MAX_MP_PUNCH_ATTEMPTS)
}

pub fn is_tunnel_or_loopback_device(device: &str) -> bool {
    let normalized = device.trim().to_ascii_lowercase();
    normalized == "lo"
        || normalized.contains("loopback")
        || ["tun", "tap", "utun", "wintun", "easytier"]
            .iter()
            .any(|prefix| normalized.starts_with(prefix))
}

pub fn validate_mp_config(config: &MpConfig) -> Result<(), anyhow::Error> {
    let congestion_control = crate::common::transport_quality::CongestionControlProfile::parse(
        &config.congestion_control,
    )
    .map_err(anyhow::Error::from)?;
    if congestion_control
        == crate::common::transport_quality::CongestionControlProfile::DummyExperimental
    {
        anyhow::bail!(
            "mp.congestion_control=dummy is test/experimental only and is not a supported runtime profile"
        );
    }
    let congestion_control_params: serde_json::Value =
        serde_json::from_str(&config.congestion_control_params_json)
            .context("mp.congestion_control_params_json must be valid JSON")?;
    // MP_SQM_PLAN.md S2.4: "tx 未配置时拒绝选择 brutal（配置校验报错，不静默回落）".
    // Every non-dummy profile is registered in `MpCcRegistry`, so any future
    // addition gets the same treatment automatically -- only `brutal` today
    // is non-total (its `resolve` can fail without a configured tx).
    if let Some(Err(message)) = crate::tunnel::mp_plugin::MpCcRegistry::with_builtins()
        .resolve(congestion_control.as_str(), &congestion_control_params)
    {
        anyhow::bail!(message);
    }
    let scheduler_params: serde_json::Value =
        serde_json::from_str(&config.scheduler_params_json)
            .context("mp.scheduler_params_json must be valid JSON")?;
    let registry = crate::tunnel::mp_plugin::MpSchedulerRegistry::with_builtins();
    if registry
        .resolve(&config.packet_scheduler, &scheduler_params)
        .is_none()
    {
        anyhow::bail!("unknown mp.packet_scheduler {:?}", config.packet_scheduler);
    }
    if config.kmax == 0 {
        anyhow::bail!("mp.kmax must be at least 1");
    }
    if config.control_interval_ms == 0 {
        anyhow::bail!("mp.control_interval_ms must be at least 1");
    }
    if !(1_000..=120_000).contains(&config.establishment_timeout_ms) {
        anyhow::bail!(
            "mp.establishment_timeout_ms must be within [1000, 120000] so a stalled MP session cannot wait forever"
        );
    }
    let allowed_providers = [
        "udp-direct",
        "udp-punch",
        "faketcp-punch",
        "relay-next-hop",
        "manual",
    ];
    for provider in &config.providers {
        if !allowed_providers.contains(&provider.as_str()) {
            anyhow::bail!("unknown mp provider {provider:?}");
        }
    }
    for device in &config.egress_devices {
        if is_tunnel_or_loopback_device(device) {
            anyhow::bail!(
                "refusing to use tunnel/loopback interface {device:?} as an MP SQM egress device"
            );
        }
    }
    for group in &config.resource_groups {
        if group.name.trim().is_empty() {
            anyhow::bail!("mp.resource_groups contains an empty name");
        }
        for device in &group.egress_devices {
            if is_tunnel_or_loopback_device(device) {
                anyhow::bail!(
                    "resource group {:?} contains tunnel/loopback device {device:?}",
                    group.name
                );
            }
        }
        for endpoint in &group.remote_endpoints {
            let endpoint = endpoint.trim();
            if endpoint.is_empty()
                || (endpoint.parse::<std::net::IpAddr>().is_err()
                    && endpoint.parse::<std::net::SocketAddr>().is_err())
            {
                anyhow::bail!(
                    "resource group {:?} contains invalid remote endpoint {endpoint:?}; expected an IP or socket address",
                    group.name
                );
            }
        }
    }
    let allowed_policy_actions = ["pin", "exclude", "pause", "prefer"];
    for policy in &config.path_policies {
        if !allowed_policy_actions.contains(&policy.action.as_str()) {
            anyhow::bail!(
                "mp.path_policies entry has invalid action {:?}; expected pin, exclude, pause, or prefer",
                policy.action
            );
        }
        if policy.action == "prefer" && !(policy.prefer_weight.is_finite() && policy.prefer_weight > 0.0) {
            anyhow::bail!(
                "mp.path_policies prefer action requires a finite prefer_weight > 0, got {}",
                policy.prefer_weight
            );
        }
        let remote_endpoint = policy.match_remote_endpoint.trim();
        if !remote_endpoint.is_empty() && remote_endpoint.parse::<SocketAddr>().is_err() {
            anyhow::bail!(
                "mp.path_policies match_remote_endpoint {:?} must be empty (wildcard) or a valid socket address",
                policy.match_remote_endpoint
            );
        }
    }
    if !config.manual_paths.is_empty()
        && !config.providers.iter().any(|provider| provider == "manual")
    {
        anyhow::bail!("mp.manual_paths requires the manual provider");
    }
    #[cfg(feature = "mpquic")]
    for path in &config.manual_paths {
        crate::connector::mp_manual::ManualUdpPathConfig::parse(path)
            .with_context(|| format!("invalid mp.manual_paths entry {path:?}"))?;
    }
    #[cfg(not(feature = "mpquic"))]
    if !config.manual_paths.is_empty() {
        anyhow::bail!("mp.manual_paths requires a binary built with mpquic support");
    }
    if let Some(sqm) = &config.sqm {
        if sqm.target_ms == 0 {
            anyhow::bail!("mp.sqm.target_ms must be at least 1");
        }
        if sqm.interval_ms == 0 {
            anyhow::bail!("mp.sqm.interval_ms must be at least 1");
        }
        if sqm.target_ms as u64 >= sqm.interval_ms as u64 {
            anyhow::bail!(
                "mp.sqm.target_ms ({}) must be smaller than mp.sqm.interval_ms ({}); CAKE's \
                 target is the acceptable queue delay *within* each interval window",
                sqm.target_ms,
                sqm.interval_ms
            );
        }
        for reflector in &sqm.reflectors {
            reflector.parse::<std::net::Ipv4Addr>().with_context(|| {
                format!("mp.sqm.reflectors entry {reflector:?} is not an IPv4 address")
            })?;
        }
        if sqm.autorate_min_bps > 0
            && sqm.autorate_max_bps > 0
            && sqm.autorate_min_bps > sqm.autorate_max_bps
        {
            anyhow::bail!(
                "mp.sqm.autorate_min_bps ({}) must not exceed mp.sqm.autorate_max_bps ({})",
                sqm.autorate_min_bps,
                sqm.autorate_max_bps
            );
        }
    }
    if config.punch_attempts > MAX_MP_PUNCH_ATTEMPTS {
        anyhow::bail!(
            "mp.punch_attempts ({}) must not exceed {MAX_MP_PUNCH_ATTEMPTS}",
            config.punch_attempts
        );
    }
    for limit in &config.punch_rate_limits {
        if limit.egress_device.trim().is_empty() {
            anyhow::bail!("mp.punch_rate_limits contains an entry without a NIC name");
        }
    }
    if let Some(data_plane) = &config.data_plane {
        crate::tunnel::mp_dataplane::DataPlanePolicy::from_config(data_plane)
            .context("invalid mp.data_plane")?;
        #[cfg(not(feature = "mpquic"))]
        if data_plane.enabled {
            anyhow::bail!("mp.data_plane requires a binary built with mpquic support");
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TcpHolePunchMode {
    #[default]
    Auto,
    FakeTcp,
    Tcp,
}

impl TcpHolePunchMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::FakeTcp => "faketcp",
            Self::Tcp => "tcp",
        }
    }
}

impl std::fmt::Display for TcpHolePunchMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for TcpHolePunchMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "faketcp" => Ok(Self::FakeTcp),
            "tcp" => Ok(Self::Tcp),
            other => Err(anyhow::anyhow!(
                "invalid tcp_hole_punch_mode {other:?}; expected auto, faketcp, or tcp"
            )),
        }
    }
}

pub fn gen_default_flags() -> Flags {
    #[allow(deprecated)]
    Flags {
        default_protocol: "tcp".to_string(),
        dev_name: "".to_string(),
        enable_encryption: true,
        enable_ipv6: true,
        mtu: 1380,
        latency_first: false,
        enable_exit_node: false,
        proxy_forward_by_system: false,
        no_tun: false,
        use_smoltcp: false,
        relay_network_whitelist: "*".to_string(),
        disable_p2p: false,
        p2p_only: false,
        lazy_p2p: false,
        relay_all_peer_rpc: false,
        disable_tcp_hole_punching: false,
        disable_udp_hole_punching: false,
        multi_thread: true,
        data_compress_algo: CompressionAlgoPb::None.into(),
        bind_device: true,
        enable_kcp_proxy: false,
        disable_kcp_input: false,
        disable_relay_kcp: false,
        enable_relay_foreign_network_kcp: false,
        accept_dns: false,
        private_mode: false,
        enable_quic_proxy: false,
        disable_quic_input: false,
        disable_relay_quic: false,
        enable_relay_foreign_network_quic: false,
        foreign_relay_bps_limit: u64::MAX,
        multi_thread_count: 2,
        encryption_algorithm: EncryptionAlgorithm::default().to_string(),
        disable_sym_hole_punching: false,
        tld_dns_zone: DEFAULT_ET_DNS_ZONE.to_string(),

        quic_listen_port: u32::MAX,
        need_p2p: false,
        instance_recv_bps_limit: u64::MAX,
        disable_upnp: false,
        disable_relay_data: false,
        enable_udp_broadcast_relay: false,
        socket_mark: None,
        tcp_hole_punch_mode: DEFAULT_TCP_HOLE_PUNCH_MODE.to_string(),
        mp: Some(gen_default_mp_config()),
        // None: no static pre-send wire-rate ceiling (MP_SQM_PLAN.md §4.4
        // (b)); a scope stays NativeOnly until something else publishes a
        // dynamic budget.
        egress_wire_limit_bps: None,
    }
}

// ---------------------------------------------------------------------------
// MP_SQM_PLAN.md S2.6: how each GUI-editable field takes effect
// ---------------------------------------------------------------------------

/// How an edit reaches a running instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldEffect {
    /// Applied by the next control tick or immediately.
    Hot,
    /// Applies to paths (and punches) created afterwards.
    NewPath,
    /// Needs the MP sessions rebuilt (`MpConfig.session_generation` bump);
    /// runtime status reports `reconnect_required` until then.
    Reconnect,
    /// Needs the instance restarted.
    Restart,
}

impl FieldEffect {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hot => "hot",
            Self::NewPath => "new_path",
            Self::Reconnect => "reconnect",
            Self::Restart => "restart",
        }
    }
}

/// The one field-effect table. Its `mp.*` rows cover every `MpConfig` field
/// (`field_effects_cover_every_mp_config_field`), and the GUI reads its
/// snapshot `frontend-lib/src/generated/mp_field_effects.json`
/// (`field_effects_snapshot_matches_the_gui_copy`).
pub const FIELD_EFFECTS: &[(&str, FieldEffect)] = &[
    ("egress_wire_limit_bps", FieldEffect::Hot),
    ("tcp_hole_punch_mode", FieldEffect::NewPath),
    ("mp.enabled", FieldEffect::Hot),
    ("mp.packet_scheduler", FieldEffect::Hot),
    ("mp.scheduler_params_json", FieldEffect::Hot),
    ("mp.kmax", FieldEffect::Hot),
    ("mp.control_interval_ms", FieldEffect::Hot),
    ("mp.providers", FieldEffect::NewPath),
    ("mp.egress_devices", FieldEffect::NewPath),
    ("mp.resource_groups", FieldEffect::Hot),
    ("mp.manual_paths", FieldEffect::NewPath),
    ("mp.disable_overlay_weighted_routing", FieldEffect::Hot),
    ("mp.establishment_timeout_ms", FieldEffect::NewPath),
    ("mp.congestion_control", FieldEffect::Reconnect),
    ("mp.path_policies", FieldEffect::Hot),
    ("mp.congestion_control_params_json", FieldEffect::Reconnect),
    ("mp.egress_limits", FieldEffect::Hot),
    ("mp.sqm.enabled", FieldEffect::Reconnect),
    // CAKE's `target` and `rtt`: the egress queues and the reliable-stream
    // queues read them again on their next packet.
    ("mp.sqm.target_ms", FieldEffect::Hot),
    ("mp.sqm.interval_ms", FieldEffect::Hot),
    ("mp.sqm.autorate_min_bps", FieldEffect::Hot),
    ("mp.sqm.autorate_max_bps", FieldEffect::Hot),
    // The prober's registry key holds the list, so the next tick uses another
    // prober; the old one ends with its last user.
    ("mp.sqm.reflectors", FieldEffect::Hot),
    ("mp.sqm.reflectors_disabled", FieldEffect::Hot),
    ("mp.session_generation", FieldEffect::Hot),
    ("mp.punch_attempts", FieldEffect::NewPath),
    ("mp.data_plane.enabled", FieldEffect::Reconnect),
    ("mp.data_plane.oversize", FieldEffect::Hot),
    ("mp.data_plane.class_policies", FieldEffect::Hot),
    ("mp.data_plane.class_rules", FieldEffect::Hot),
    ("mp.data_plane.reliable_stream_max", FieldEffect::Hot),
    ("mp.data_plane.reliable_stream_idle_ms", FieldEffect::Hot),
    ("mp.punch_pps", FieldEffect::Hot),
    ("mp.punch_rate_limits", FieldEffect::Hot),
    ("enable_quic_proxy", FieldEffect::Restart),
    ("enable_kcp_proxy", FieldEffect::Restart),
    ("disable_quic_input", FieldEffect::Restart),
    ("disable_kcp_input", FieldEffect::Restart),
    ("mtu", FieldEffect::Restart),
];

pub fn field_effect(path: &str) -> Option<FieldEffect> {
    FIELD_EFFECTS
        .iter()
        .find(|(field, _)| *field == path)
        .map(|(_, effect)| *effect)
}

/// An unset proto3 sub-message means its defaults; materialize it so an unset
/// `sqm`/`data_plane` and one set to defaults serialize alike.
fn fill_unset_messages(message: &mut DynamicMessage) {
    for field in message.descriptor().fields() {
        let prost_reflect::Kind::Message(sub) = field.kind() else {
            continue;
        };
        if field.is_list() || field.is_map() {
            continue;
        }
        if !message.has_field(&field) {
            message.set_field(&field, prost_reflect::Value::Message(DynamicMessage::new(sub)));
        }
        if let Some(inner) = message.get_field_mut(&field).as_message_mut() {
            fill_unset_messages(inner);
        }
    }
}

fn mp_config_json(config: &MpConfig) -> serde_json::Value {
    let mut message = DynamicMessage::new(config.descriptor());
    message
        .transcode_from(config)
        .expect("MpConfig should transcode to DynamicMessage");
    fill_unset_messages(&mut message);
    let options = SerializeOptions::new()
        .use_proto_field_name(true)
        .skip_default_fields(false);
    message
        .serialize_with_options(serde_json::value::Serializer, &options)
        .expect("MpConfig should serialize to JSON")
}

/// The values of every `reconnect` field of `config`. A live session built
/// from a different fingerprint needs a rebuild (`reconnect_required`).
pub fn mp_reconnect_fingerprint(config: &MpConfig) -> String {
    let value = mp_config_json(config);
    FIELD_EFFECTS
        .iter()
        .filter(|(_, effect)| *effect == FieldEffect::Reconnect)
        .filter_map(|(path, _)| path.strip_prefix("mp."))
        .map(|path| {
            let field = path
                .split('.')
                .try_fold(&value, |value, key| value.get(key))
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            format!("{path}={field}")
        })
        .collect::<Vec<_>>()
        .join(";")
}

fn flags_to_dynamic_message(flags: &Flags) -> DynamicMessage {
    let mut message = DynamicMessage::new(flags.descriptor());
    message
        .transcode_from(flags)
        .expect("FlagsInConfig should transcode to DynamicMessage");
    message
}

fn flags_to_full_json_map(flags: &DynamicMessage) -> serde_json::Map<String, serde_json::Value> {
    let options = SerializeOptions::new()
        .use_proto_field_name(true)
        .skip_default_fields(false);

    match flags
        .serialize_with_options(serde_json::value::Serializer, &options)
        .expect("FlagsInConfig should serialize to JSON")
    {
        serde_json::Value::Object(map) => map,
        _ => unreachable!("FlagsInConfig should serialize to a JSON object"),
    }
}

fn flags_diff_from_default(flags: &Flags) -> serde_json::Map<String, serde_json::Value> {
    let default_flags = gen_default_flags();
    let default_message = flags_to_dynamic_message(&default_flags);
    let current_message = flags_to_dynamic_message(flags);
    let default_map = flags_to_full_json_map(&default_message);
    let current_map = flags_to_full_json_map(&current_message);

    current_message
        .descriptor()
        .fields()
        .filter_map(|field| {
            let key = field.name();
            let value_changed = default_map.get(key) != current_map.get(key);
            let presence_changed =
                default_message.has_field(&field) != current_message.has_field(&field);
            if value_changed || presence_changed {
                current_map
                    .get(key)
                    .map(|value| (key.to_string(), value.clone()))
            } else {
                None
            }
        })
        .collect()
}

fn mapped_listener_allows_implicit_port(url: &url::Url) -> bool {
    TunnelScheme::try_from(url)
        .ok()
        .and_then(|scheme| IpScheme::try_from(scheme).ok())
        .is_some()
}

pub fn validate_mapped_listener_url(url: &url::Url) -> Result<(), anyhow::Error> {
    if url.port().is_none() && !mapped_listener_allows_implicit_port(url) {
        anyhow::bail!("mapped listener port is missing: {}", url);
    }

    Ok(())
}

pub fn parse_mapped_listener_urls(
    mapped_listeners: &[String],
) -> Result<Vec<url::Url>, anyhow::Error> {
    mapped_listeners
        .iter()
        .map(|s| {
            let url: url::Url = s
                .parse()
                .with_context(|| format!("mapped listener is not a valid url: {}", s))?;
            validate_mapped_listener_url(&url)?;
            Ok(url)
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Display, EnumString, VariantArray)]
#[strum(ascii_case_insensitive)]
pub enum EncryptionAlgorithm {
    #[strum(serialize = "xor")]
    Xor,

    #[cfg(any(feature = "aes-gcm", feature = "wireguard", feature = "openssl-crypto"))]
    #[strum(serialize = "aes-gcm")]
    AesGcm,
    #[cfg(any(feature = "aes-gcm", feature = "wireguard", feature = "openssl-crypto"))]
    #[strum(serialize = "aes-256-gcm")]
    Aes256Gcm,
    #[cfg(any(feature = "wireguard", feature = "openssl-crypto"))]
    #[strum(serialize = "chacha20")]
    ChaCha20,
}

impl ValueEnum for EncryptionAlgorithm {
    fn value_variants<'a>() -> &'a [Self] {
        Self::VARIANTS
    }

    fn from_str(input: &str, _ignore_case: bool) -> Result<Self, String> {
        input
            .parse()
            .map_err(|_| format!("'{}' is not a valid encryption algorithm", input))
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(PossibleValue::new(self.to_string()))
    }
}

#[allow(clippy::derivable_impls)]
impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        cfg_select! {
            any(feature = "aes-gcm", feature = "wireguard", feature = "openssl-crypto") => EncryptionAlgorithm::AesGcm,
            _ => {
                crate::common::log::warn!("no AEAD encryption algorithm is available, using INSECURE XOR");
                EncryptionAlgorithm::Xor
            }
        }
    }
}

#[auto_impl::auto_impl(Box, &)]
pub trait ConfigLoader: Send + Sync {
    fn get_id(&self) -> uuid::Uuid;
    fn set_id(&self, id: uuid::Uuid);

    fn get_hostname(&self) -> String;
    fn set_hostname(&self, name: Option<String>);

    fn get_inst_name(&self) -> String;
    fn set_inst_name(&self, name: String);

    fn get_netns(&self) -> Option<String>;
    fn set_netns(&self, ns: Option<String>);

    fn get_ipv4(&self) -> Option<cidr::Ipv4Inet>;
    fn set_ipv4(&self, addr: Option<cidr::Ipv4Inet>);

    fn get_ipv6(&self) -> Option<cidr::Ipv6Inet>;
    fn set_ipv6(&self, addr: Option<cidr::Ipv6Inet>);

    fn get_ipv6_public_addr_provider(&self) -> bool;
    fn set_ipv6_public_addr_provider(&self, enabled: bool);

    fn get_ipv6_public_addr_auto(&self) -> bool;
    fn set_ipv6_public_addr_auto(&self, enabled: bool);

    fn get_ipv6_public_addr_prefix(&self) -> Option<cidr::Ipv6Cidr>;
    fn set_ipv6_public_addr_prefix(&self, prefix: Option<cidr::Ipv6Cidr>);

    fn get_dhcp(&self) -> bool;
    fn set_dhcp(&self, dhcp: bool);

    fn add_proxy_cidr(
        &self,
        cidr: cidr::Ipv4Cidr,
        mapped_cidr: Option<cidr::Ipv4Cidr>,
    ) -> Result<(), anyhow::Error>;
    fn remove_proxy_cidr(&self, cidr: cidr::Ipv4Cidr);
    fn clear_proxy_cidrs(&self);
    fn get_proxy_cidrs(&self) -> Vec<ProxyNetworkConfig>;

    fn get_network_identity(&self) -> NetworkIdentity;
    fn set_network_identity(&self, identity: NetworkIdentity);

    fn get_listener_uris(&self) -> Vec<url::Url>;

    fn get_peers(&self) -> Vec<PeerConfig>;
    fn set_peers(&self, peers: Vec<PeerConfig>);

    fn get_listeners(&self) -> Option<Vec<url::Url>>;
    fn set_listeners(&self, listeners: Vec<url::Url>);

    fn get_mapped_listeners(&self) -> Vec<url::Url>;
    fn set_mapped_listeners(&self, listeners: Option<Vec<url::Url>>);

    fn get_vpn_portal_config(&self) -> Option<VpnPortalConfig>;
    fn set_vpn_portal_config(&self, config: VpnPortalConfig);

    fn get_flags(&self) -> Flags;
    fn set_flags(&self, flags: Flags);

    fn get_exit_nodes(&self) -> Vec<IpAddr>;
    fn set_exit_nodes(&self, nodes: Vec<IpAddr>);

    fn get_routes(&self) -> Option<Vec<cidr::Ipv4Cidr>>;
    fn set_routes(&self, routes: Option<Vec<cidr::Ipv4Cidr>>);

    fn get_socks5_portal(&self) -> Option<url::Url>;
    fn set_socks5_portal(&self, addr: Option<url::Url>);

    fn get_port_forwards(&self) -> Vec<PortForwardConfig>;
    fn set_port_forwards(&self, forwards: Vec<PortForwardConfig>);

    fn get_acl(&self) -> Option<Acl>;
    fn set_acl(&self, acl: Option<Acl>);

    fn get_tcp_whitelist(&self) -> Vec<String>;
    fn set_tcp_whitelist(&self, whitelist: Vec<String>);

    fn get_udp_whitelist(&self) -> Vec<String>;
    fn set_udp_whitelist(&self, whitelist: Vec<String>);

    fn get_stun_servers(&self) -> Option<Vec<String>>;
    fn set_stun_servers(&self, servers: Option<Vec<String>>);

    fn get_tcp_stun_servers(&self) -> Option<Vec<String>>;
    fn set_tcp_stun_servers(&self, servers: Option<Vec<String>>);

    fn get_stun_servers_v6(&self) -> Option<Vec<String>>;
    fn set_stun_servers_v6(&self, servers: Option<Vec<String>>);

    fn get_secure_mode(&self) -> Option<SecureModeConfig>;
    fn set_secure_mode(&self, secure_mode: Option<SecureModeConfig>);

    fn get_credential_file(&self) -> Option<std::path::PathBuf> {
        None
    }
    fn set_credential_file(&self, _path: Option<std::path::PathBuf>) {}

    fn get_network_config_source(&self) -> ConfigSource {
        ConfigSource::User
    }
    fn set_network_config_source(&self, _source: Option<ConfigSource>) {}

    fn dump(&self) -> String;
}

pub trait LoggingConfigLoader {
    fn get_file_logger_config(&self) -> FileLoggerConfig;

    fn get_console_logger_config(&self) -> ConsoleLoggerConfig;
}

pub type NetworkSecretDigest = [u8; 32];

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkIdentity {
    pub network_name: String,
    pub network_secret: Option<String>,
    #[serde(skip)]
    pub network_secret_digest: Option<NetworkSecretDigest>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    #[default]
    User,
    Web,
}

impl ConfigSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Web => "web",
        }
    }

    pub fn from_rpc(source: i32) -> Option<Self> {
        match RpcConfigSource::try_from(source).ok() {
            Some(RpcConfigSource::Web) => Some(Self::Web),
            Some(RpcConfigSource::User) => Some(Self::User),
            _ => None,
        }
    }

    pub fn to_rpc(self) -> i32 {
        match self {
            Self::User => RpcConfigSource::User as i32,
            Self::Web => RpcConfigSource::Web as i32,
        }
    }
}

impl std::str::FromStr for ConfigSource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(Self::User),
            "web" => Ok(Self::Web),
            other => Err(format!("unknown network config source: {other}")),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct ConfigSourceConfig {
    source: ConfigSource,
}

#[derive(Eq, PartialEq, Hash)]
struct NetworkIdentityWithOnlyDigest {
    network_name: String,
    network_secret_digest: Option<NetworkSecretDigest>,
}

impl From<NetworkIdentity> for NetworkIdentityWithOnlyDigest {
    fn from(identity: NetworkIdentity) -> Self {
        if identity.network_secret_digest.is_some() {
            Self {
                network_name: identity.network_name,
                network_secret_digest: identity.network_secret_digest,
            }
        } else if identity.network_secret.is_some() {
            let mut network_secret_digest = [0u8; 32];
            generate_digest_from_str(
                &identity.network_name,
                identity.network_secret.as_ref().unwrap(),
                &mut network_secret_digest,
            );
            Self {
                network_name: identity.network_name,
                network_secret_digest: Some(network_secret_digest),
            }
        } else {
            Self {
                network_name: identity.network_name,
                network_secret_digest: None,
            }
        }
    }
}

impl PartialEq for NetworkIdentity {
    fn eq(&self, other: &Self) -> bool {
        let self_with_digest = NetworkIdentityWithOnlyDigest::from(self.clone());
        let other_with_digest = NetworkIdentityWithOnlyDigest::from(other.clone());
        self_with_digest == other_with_digest
    }
}

impl Eq for NetworkIdentity {}

impl std::hash::Hash for NetworkIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let self_with_digest = NetworkIdentityWithOnlyDigest::from(self.clone());
        self_with_digest.hash(state);
    }
}

impl NetworkIdentity {
    pub fn new(network_name: String, network_secret: String) -> Self {
        let mut network_secret_digest = [0u8; 32];
        generate_digest_from_str(&network_name, &network_secret, &mut network_secret_digest);

        NetworkIdentity {
            network_name,
            network_secret: Some(network_secret),
            network_secret_digest: Some(network_secret_digest),
        }
    }

    /// Create a NetworkIdentity for a credential node (no network_secret).
    /// The node identifies by network_name only and authenticates via credential keypair.
    pub fn new_credential(network_name: String) -> Self {
        NetworkIdentity {
            network_name,
            network_secret: None,
            network_secret_digest: None,
        }
    }
}

impl Default for NetworkIdentity {
    fn default() -> Self {
        Self::new("default".to_string(), "".to_string())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct PeerConfig {
    pub uri: url::Url,
    pub peer_public_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ProxyNetworkConfig {
    pub cidr: cidr::Ipv4Cidr,                // the CIDR of the proxy network
    pub mapped_cidr: Option<cidr::Ipv4Cidr>, // allow remap the proxy CIDR to another CIDR
    pub allow: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct FileLoggerConfig {
    pub level: Option<String>,
    pub file: Option<String>,
    pub dir: Option<String>,
    pub size_mb: Option<u64>,
    pub count: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct ConsoleLoggerConfig {
    pub level: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, derive_builder::Builder)]
pub struct LoggingConfig {
    #[builder(setter(into, strip_option), default = None)]
    pub file_logger: Option<FileLoggerConfig>,
    #[builder(setter(into, strip_option), default = None)]
    pub console_logger: Option<ConsoleLoggerConfig>,
}

impl LoggingConfigLoader for &LoggingConfig {
    fn get_file_logger_config(&self) -> FileLoggerConfig {
        self.file_logger.clone().unwrap_or_default()
    }

    fn get_console_logger_config(&self) -> ConsoleLoggerConfig {
        self.console_logger.clone().unwrap_or_default()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct VpnPortalConfig {
    pub client_cidr: cidr::Ipv4Cidr,
    pub wireguard_listen: SocketAddr,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct PortForwardConfig {
    pub bind_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    pub proto: String,
}

impl From<PortForwardConfigPb> for PortForwardConfig {
    fn from(config: PortForwardConfigPb) -> Self {
        PortForwardConfig {
            bind_addr: config.bind_addr.unwrap_or_default().into(),
            dst_addr: config.dst_addr.unwrap_or_default().into(),
            proto: match SocketType::try_from(config.socket_type) {
                Ok(SocketType::Tcp) => "tcp".to_string(),
                Ok(SocketType::Udp) => "udp".to_string(),
                _ => "tcp".to_string(),
            },
        }
    }
}

impl From<PortForwardConfig> for PortForwardConfigPb {
    fn from(val: PortForwardConfig) -> Self {
        PortForwardConfigPb {
            bind_addr: Some(val.bind_addr.into()),
            dst_addr: Some(val.dst_addr.into()),
            socket_type: match val.proto.to_lowercase().as_str() {
                "tcp" => SocketType::Tcp as i32,
                "udp" => SocketType::Udp as i32,
                _ => SocketType::Tcp as i32,
            },
        }
    }
}

pub fn process_secure_mode_cfg(mut user_cfg: SecureModeConfig) -> anyhow::Result<SecureModeConfig> {
    if !user_cfg.enabled {
        return Ok(user_cfg);
    }

    let private_key = if user_cfg.local_private_key.is_none() {
        // if no private key, generate random one
        let private = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        user_cfg.local_private_key = Some(BASE64_STANDARD.encode(private.clone().as_bytes()));
        private
    } else {
        // check if private key is valid
        user_cfg.private_key()?
    };

    let public = x25519_dalek::PublicKey::from(&private_key);

    match user_cfg.local_public_key {
        None => {
            user_cfg.local_public_key = Some(BASE64_STANDARD.encode(public.as_bytes()));
        }
        Some(ref user_pub) => {
            let public = user_cfg.public_key()?;
            if *user_pub != BASE64_STANDARD.encode(public.as_bytes()) {
                return Err(anyhow::anyhow!(
                    "local public key {} does not match generated public key {}",
                    user_pub,
                    BASE64_STANDARD.encode(public.as_bytes())
                ));
            }
        }
    }

    Ok(user_cfg)
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
struct Config {
    netns: Option<String>,
    hostname: Option<String>,
    instance_name: Option<String>,
    instance_id: Option<uuid::Uuid>,
    ipv4: Option<String>,
    ipv6: Option<String>,
    ipv6_public_addr_provider: Option<bool>,
    ipv6_public_addr_auto: Option<bool>,
    ipv6_public_addr_prefix: Option<String>,
    dhcp: Option<bool>,
    network_identity: Option<NetworkIdentity>,
    listeners: Option<Vec<url::Url>>,
    mapped_listeners: Option<Vec<url::Url>>,
    exit_nodes: Option<Vec<IpAddr>>,

    peer: Option<Vec<PeerConfig>>,
    proxy_network: Option<Vec<ProxyNetworkConfig>>,

    vpn_portal_config: Option<VpnPortalConfig>,

    routes: Option<Vec<cidr::Ipv4Cidr>>,

    socks5_proxy: Option<url::Url>,

    port_forward: Option<Vec<PortForwardConfig>>,

    secure_mode: Option<SecureModeConfig>,

    flags: Option<serde_json::Map<String, serde_json::Value>>,

    #[serde(skip)]
    flags_struct: Option<Flags>,

    acl: Option<Acl>,

    tcp_whitelist: Option<Vec<String>>,
    udp_whitelist: Option<Vec<String>>,
    stun_servers: Option<Vec<String>>,
    tcp_stun_servers: Option<Vec<String>>,
    stun_servers_v6: Option<Vec<String>>,

    credential_file: Option<PathBuf>,
    source: Option<ConfigSourceConfig>,
}

fn format_toml_parse_error(source_name: &str, config_str: &str, error: &toml::de::Error) -> String {
    let message = format!("failed to parse config TOML from {source_name}");

    let Some(span) = error.span() else {
        return format!("{message}\ndetail: {error}");
    };

    let mut output = Vec::new();
    let report = Report::build(ReportKind::Error, (source_name, span.clone()))
        .with_config(
            AriadneConfig::default()
                .with_color(false)
                .with_char_set(CharSet::Ascii)
                .with_index_type(IndexType::Byte),
        )
        .with_message(&message)
        .with_label(Label::new((source_name, span)).with_message(error.message()))
        .finish();

    if report
        .write((source_name, Source::from(config_str)), &mut output)
        .is_ok()
    {
        String::from_utf8_lossy(&output).into_owned()
    } else {
        format!("{message}\ndetail: {error}")
    }
}

#[derive(Debug, Clone)]
pub struct TomlConfigLoader {
    config: Arc<Mutex<Config>>,
}

impl Default for TomlConfigLoader {
    fn default() -> Self {
        TomlConfigLoader::new_from_str("").unwrap()
    }
}

impl TomlConfigLoader {
    fn normalize_config_source(config: &mut Config) {
        if matches!(
            config.source.as_ref().map(|source| source.source),
            Some(ConfigSource::User)
        ) {
            config.source = None;
        }
    }

    pub fn new_from_str(config_str: &str) -> Result<Self, anyhow::Error> {
        Self::new_from_str_with_source("inline config", config_str)
    }

    pub fn new(config_path: &PathBuf) -> Result<Self, anyhow::Error> {
        let config_str = std::fs::read_to_string(config_path)
            .with_context(|| format!("failed to read config file: {}", config_path.display()))?;

        let source_name = config_path.display().to_string();
        Self::new_from_str_with_source(&source_name, &config_str)
    }

    pub(crate) fn new_from_str_with_source(
        source_name: &str,
        config_str: &str,
    ) -> Result<Self, anyhow::Error> {
        let mut config = toml::de::from_str::<Config>(config_str).map_err(|err| {
            let message = format_toml_parse_error(source_name, config_str, &err);
            anyhow::Error::new(err).context(message)
        })?;

        Self::normalize_config_source(&mut config);

        Self::new_from_config(config).map_err(|err| {
            let message = format!("failed to load config from {source_name}: {err}");
            err.context(message)
        })
    }

    fn new_from_config(mut config: Config) -> Result<Self, anyhow::Error> {
        let flags = Self::gen_flags(config.flags.clone().unwrap_or_default())
            .context("failed to parse flags")?;
        flags
            .tcp_hole_punch_mode
            .parse::<TcpHolePunchMode>()
            .context("failed to parse tcp_hole_punch_mode")?;
        let mp = flags
            .mp
            .as_ref()
            .context("mp config is missing after default merge")?;
        validate_mp_config(mp)
            .map_err(|error| anyhow::anyhow!("failed to validate mp config: {error}"))?;
        config.flags_struct = Some(flags);
        let has_network_identity = config.network_identity.is_some();

        let config = TomlConfigLoader {
            config: Arc::new(Mutex::new(config)),
        };

        let old_ns = config.get_network_identity();

        // Detect credential mode: secure_mode enabled + no network_secret in TOML
        let is_credential = has_network_identity
            && config
                .get_secure_mode()
                .map(|sm| sm.enabled)
                .unwrap_or(false)
            && old_ns
                .network_secret
                .as_deref()
                .is_none_or(|s| s.is_empty());

        if is_credential {
            config.set_network_identity(NetworkIdentity::new_credential(old_ns.network_name));
        } else {
            config.set_network_identity(NetworkIdentity::new(
                old_ns.network_name,
                old_ns.network_secret.unwrap_or_default(),
            ));
        }

        Ok(config)
    }

    fn gen_flags(
        flags_hashmap: serde_json::Map<String, serde_json::Value>,
    ) -> serde_json::Result<Flags> {
        let mut merged_hashmap = match serde_json::to_value(gen_default_flags()) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        };
        let mut flags_hashmap = flags_hashmap;
        if let Some(serde_json::Value::Object(mut mp_override)) = flags_hashmap.remove("mp") {
            remove_retired_mp_fields(&mut mp_override);
            let mut mp = merged_hashmap
                .remove("mp")
                .and_then(|value| value.as_object().cloned())
                .unwrap_or_default();
            mp.extend(mp_override);
            merged_hashmap.insert("mp".to_string(), serde_json::Value::Object(mp));
        }
        merged_hashmap.extend(flags_hashmap);
        serde_json::from_value(serde_json::Value::Object(merged_hashmap))
    }
}

impl ConfigLoader for TomlConfigLoader {
    fn get_inst_name(&self) -> String {
        self.config
            .lock()
            .unwrap()
            .instance_name
            .clone()
            .unwrap_or("default".to_string())
    }

    fn set_inst_name(&self, name: String) {
        self.config.lock().unwrap().instance_name = Some(name);
    }

    fn get_hostname(&self) -> String {
        let hostname = self.config.lock().unwrap().hostname.clone();

        match hostname {
            Some(hostname) => {
                let hostname = hostname
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(32)
                    .collect::<String>();

                if !hostname.is_empty() {
                    self.set_hostname(Some(hostname.clone()));
                    hostname
                } else {
                    self.set_hostname(None);
                    gethostname::gethostname().to_string_lossy().to_string()
                }
            }
            None => gethostname::gethostname().to_string_lossy().to_string(),
        }
    }

    fn set_hostname(&self, name: Option<String>) {
        self.config.lock().unwrap().hostname = name;
    }

    fn get_netns(&self) -> Option<String> {
        self.config.lock().unwrap().netns.clone()
    }

    fn set_netns(&self, ns: Option<String>) {
        self.config.lock().unwrap().netns = ns;
    }

    fn get_ipv4(&self) -> Option<cidr::Ipv4Inet> {
        let locked_config = self.config.lock().unwrap();
        locked_config
            .ipv4
            .as_ref()
            .and_then(|s| s.parse().ok())
            .map(|c: cidr::Ipv4Inet| {
                if c.network_length() == 32 {
                    cidr::Ipv4Inet::new(c.address(), 24).unwrap()
                } else {
                    c
                }
            })
    }

    fn set_ipv4(&self, addr: Option<cidr::Ipv4Inet>) {
        self.config.lock().unwrap().ipv4 = addr.map(|addr| addr.to_string());
    }

    fn get_ipv6(&self) -> Option<cidr::Ipv6Inet> {
        let locked_config = self.config.lock().unwrap();
        locked_config.ipv6.as_ref().and_then(|s| s.parse().ok())
    }

    fn set_ipv6(&self, addr: Option<cidr::Ipv6Inet>) {
        self.config.lock().unwrap().ipv6 = addr.map(|addr| addr.to_string());
    }

    fn get_ipv6_public_addr_provider(&self) -> bool {
        self.config
            .lock()
            .unwrap()
            .ipv6_public_addr_provider
            .unwrap_or_default()
    }

    fn set_ipv6_public_addr_provider(&self, enabled: bool) {
        self.config.lock().unwrap().ipv6_public_addr_provider = Some(enabled);
    }

    fn get_ipv6_public_addr_auto(&self) -> bool {
        self.config
            .lock()
            .unwrap()
            .ipv6_public_addr_auto
            .unwrap_or_default()
    }

    fn set_ipv6_public_addr_auto(&self, enabled: bool) {
        self.config.lock().unwrap().ipv6_public_addr_auto = Some(enabled);
    }

    fn get_ipv6_public_addr_prefix(&self) -> Option<cidr::Ipv6Cidr> {
        let locked_config = self.config.lock().unwrap();
        locked_config
            .ipv6_public_addr_prefix
            .as_ref()
            .and_then(|s| s.parse().ok())
    }

    fn set_ipv6_public_addr_prefix(&self, prefix: Option<cidr::Ipv6Cidr>) {
        self.config.lock().unwrap().ipv6_public_addr_prefix =
            prefix.map(|prefix| prefix.to_string());
    }

    fn get_dhcp(&self) -> bool {
        self.config.lock().unwrap().dhcp.unwrap_or_default()
    }

    fn set_dhcp(&self, dhcp: bool) {
        self.config.lock().unwrap().dhcp = Some(dhcp);
    }

    fn add_proxy_cidr(
        &self,
        cidr: cidr::Ipv4Cidr,
        mapped_cidr: Option<cidr::Ipv4Cidr>,
    ) -> Result<(), anyhow::Error> {
        let mut locked_config = self.config.lock().unwrap();
        if locked_config.proxy_network.is_none() {
            locked_config.proxy_network = Some(vec![]);
        }
        if let Some(mapped_cidr) = mapped_cidr.as_ref()
            && cidr.network_length() != mapped_cidr.network_length()
        {
            return Err(anyhow::anyhow!(
                "Mapped CIDR must have the same network length as the original CIDR: {} != {}",
                cidr.network_length(),
                mapped_cidr.network_length()
            ));
        }
        // insert if no duplicate
        if !locked_config
            .proxy_network
            .as_ref()
            .unwrap()
            .iter()
            .any(|c| c.cidr == cidr && c.mapped_cidr == mapped_cidr)
        {
            locked_config
                .proxy_network
                .as_mut()
                .unwrap()
                .push(ProxyNetworkConfig {
                    cidr,
                    mapped_cidr,
                    allow: None,
                });
        }
        Ok(())
    }

    fn remove_proxy_cidr(&self, cidr: cidr::Ipv4Cidr) {
        let mut locked_config = self.config.lock().unwrap();
        if let Some(proxy_cidrs) = &mut locked_config.proxy_network {
            proxy_cidrs.retain(|c| c.cidr != cidr);
        }
    }

    fn clear_proxy_cidrs(&self) {
        let mut locked_config = self.config.lock().unwrap();
        locked_config.proxy_network = None;
    }

    fn get_proxy_cidrs(&self) -> Vec<ProxyNetworkConfig> {
        self.config
            .lock()
            .unwrap()
            .proxy_network
            .as_ref()
            .cloned()
            .unwrap_or_default()
    }

    fn get_id(&self) -> uuid::Uuid {
        let mut locked_config = self.config.lock().unwrap();
        match locked_config.instance_id {
            Some(id) => id,
            None => {
                let id = uuid::Uuid::new_v4();
                locked_config.instance_id = Some(id);
                id
            }
        }
    }

    fn set_id(&self, id: uuid::Uuid) {
        self.config.lock().unwrap().instance_id = Some(id);
    }

    fn get_network_identity(&self) -> NetworkIdentity {
        self.config
            .lock()
            .unwrap()
            .network_identity
            .clone()
            .unwrap_or_default()
    }

    fn set_network_identity(&self, identity: NetworkIdentity) {
        self.config.lock().unwrap().network_identity = Some(identity);
    }

    fn get_listener_uris(&self) -> Vec<url::Url> {
        self.config
            .lock()
            .unwrap()
            .listeners
            .clone()
            .unwrap_or_default()
    }

    fn get_peers(&self) -> Vec<PeerConfig> {
        self.config.lock().unwrap().peer.clone().unwrap_or_default()
    }

    fn set_peers(&self, peers: Vec<PeerConfig>) {
        self.config.lock().unwrap().peer = Some(peers);
    }

    fn get_listeners(&self) -> Option<Vec<url::Url>> {
        self.config.lock().unwrap().listeners.clone()
    }

    fn set_listeners(&self, listeners: Vec<url::Url>) {
        self.config.lock().unwrap().listeners = Some(listeners);
    }

    fn get_mapped_listeners(&self) -> Vec<url::Url> {
        self.config
            .lock()
            .unwrap()
            .mapped_listeners
            .clone()
            .unwrap_or_default()
    }

    fn set_mapped_listeners(&self, listeners: Option<Vec<url::Url>>) {
        self.config.lock().unwrap().mapped_listeners = listeners;
    }

    fn get_vpn_portal_config(&self) -> Option<VpnPortalConfig> {
        self.config.lock().unwrap().vpn_portal_config.clone()
    }
    fn set_vpn_portal_config(&self, config: VpnPortalConfig) {
        self.config.lock().unwrap().vpn_portal_config = Some(config);
    }

    fn get_flags(&self) -> Flags {
        self.config
            .lock()
            .unwrap()
            .flags_struct
            .clone()
            .unwrap_or_default()
    }

    fn set_flags(&self, flags: Flags) {
        self.config.lock().unwrap().flags_struct = Some(flags);
    }

    fn get_exit_nodes(&self) -> Vec<IpAddr> {
        self.config
            .lock()
            .unwrap()
            .exit_nodes
            .clone()
            .unwrap_or_default()
    }

    fn set_exit_nodes(&self, nodes: Vec<IpAddr>) {
        self.config.lock().unwrap().exit_nodes = Some(nodes);
    }

    fn get_routes(&self) -> Option<Vec<cidr::Ipv4Cidr>> {
        self.config.lock().unwrap().routes.clone()
    }

    fn set_routes(&self, routes: Option<Vec<cidr::Ipv4Cidr>>) {
        self.config.lock().unwrap().routes = routes;
    }

    fn get_socks5_portal(&self) -> Option<url::Url> {
        self.config.lock().unwrap().socks5_proxy.clone()
    }

    fn set_socks5_portal(&self, addr: Option<url::Url>) {
        self.config.lock().unwrap().socks5_proxy = addr;
    }

    fn get_port_forwards(&self) -> Vec<PortForwardConfig> {
        self.config
            .lock()
            .unwrap()
            .port_forward
            .clone()
            .unwrap_or_default()
    }

    fn set_port_forwards(&self, forwards: Vec<PortForwardConfig>) {
        self.config.lock().unwrap().port_forward = Some(forwards);
    }

    fn get_acl(&self) -> Option<Acl> {
        self.config.lock().unwrap().acl.clone()
    }

    fn set_acl(&self, acl: Option<Acl>) {
        self.config.lock().unwrap().acl = acl;
    }

    fn get_tcp_whitelist(&self) -> Vec<String> {
        self.config
            .lock()
            .unwrap()
            .tcp_whitelist
            .clone()
            .unwrap_or_default()
    }

    fn set_tcp_whitelist(&self, whitelist: Vec<String>) {
        self.config.lock().unwrap().tcp_whitelist = Some(whitelist);
    }

    fn get_udp_whitelist(&self) -> Vec<String> {
        self.config
            .lock()
            .unwrap()
            .udp_whitelist
            .clone()
            .unwrap_or_default()
    }

    fn set_udp_whitelist(&self, whitelist: Vec<String>) {
        self.config.lock().unwrap().udp_whitelist = Some(whitelist);
    }

    fn get_stun_servers(&self) -> Option<Vec<String>> {
        self.config.lock().unwrap().stun_servers.clone()
    }

    fn set_stun_servers(&self, servers: Option<Vec<String>>) {
        self.config.lock().unwrap().stun_servers = servers;
    }

    fn get_tcp_stun_servers(&self) -> Option<Vec<String>> {
        self.config.lock().unwrap().tcp_stun_servers.clone()
    }

    fn set_tcp_stun_servers(&self, servers: Option<Vec<String>>) {
        self.config.lock().unwrap().tcp_stun_servers = servers;
    }

    fn get_stun_servers_v6(&self) -> Option<Vec<String>> {
        self.config.lock().unwrap().stun_servers_v6.clone()
    }

    fn set_stun_servers_v6(&self, servers: Option<Vec<String>>) {
        self.config.lock().unwrap().stun_servers_v6 = servers;
    }

    fn get_secure_mode(&self) -> Option<SecureModeConfig> {
        self.config.lock().unwrap().secure_mode.clone()
    }

    fn set_secure_mode(&self, secure_mode: Option<SecureModeConfig>) {
        self.config.lock().unwrap().secure_mode = secure_mode;
    }

    fn get_credential_file(&self) -> Option<PathBuf> {
        self.config.lock().unwrap().credential_file.clone()
    }

    fn set_credential_file(&self, path: Option<PathBuf>) {
        self.config.lock().unwrap().credential_file = path;
    }

    fn get_network_config_source(&self) -> ConfigSource {
        self.config
            .lock()
            .unwrap()
            .source
            .as_ref()
            .map(|source| source.source)
            .unwrap_or(ConfigSource::User)
    }

    fn set_network_config_source(&self, source: Option<ConfigSource>) {
        self.config.lock().unwrap().source = source.and_then(|source| match source {
            ConfigSource::User => None,
            other => Some(ConfigSourceConfig { source: other }),
        });
    }

    fn dump(&self) -> String {
        let mut config = self.config.lock().unwrap().clone();
        Self::normalize_config_source(&mut config);
        config.flags = Some(flags_diff_from_default(&self.get_flags()));
        if config.stun_servers == Some(StunInfoCollector::get_default_servers()) {
            config.stun_servers = None;
        }
        if config.tcp_stun_servers == Some(StunInfoCollector::get_default_tcp_servers()) {
            config.tcp_stun_servers = None;
        }
        if config.stun_servers_v6 == Some(StunInfoCollector::get_default_servers_v6()) {
            config.stun_servers_v6 = None;
        }
        toml::to_string_pretty(&config).unwrap()
    }
}

#[derive(Clone, Copy, Default)]
pub struct ConfigFilePermission(u8);
impl ConfigFilePermission {
    pub const READ_ONLY: u8 = 1 << 0;
    pub const NO_DELETE: u8 = 1 << 1;

    pub fn with_flag(self, flag: u8) -> Self {
        Self(self.0 | flag)
    }
    pub fn remove_flag(self, flag: u8) -> Self {
        Self(self.0 & !flag)
    }
    pub fn has_flag(&self, flag: u8) -> bool {
        (self.0 & flag) != 0
    }
}
impl From<u8> for ConfigFilePermission {
    fn from(value: u8) -> Self {
        ConfigFilePermission(value)
    }
}
impl From<u32> for ConfigFilePermission {
    fn from(value: u32) -> Self {
        ConfigFilePermission(value as u8)
    }
}
impl From<ConfigFilePermission> for u8 {
    fn from(value: ConfigFilePermission) -> Self {
        value.0
    }
}
impl From<ConfigFilePermission> for u32 {
    fn from(value: ConfigFilePermission) -> Self {
        value.0 as u32
    }
}
impl std::fmt::Debug for ConfigFilePermission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut flags = vec![];
        if self.has_flag(ConfigFilePermission::READ_ONLY) {
            flags.push("READ_ONLY");
        } else {
            flags.push("EDITABLE");
        }
        if self.has_flag(ConfigFilePermission::NO_DELETE) {
            flags.push("NO_DELETE");
        } else {
            flags.push("DELETABLE");
        }
        write!(f, "{}", flags.join("|"))
    }
}

#[derive(Debug, Clone)]
pub struct ConfigFileControl {
    pub path: Option<PathBuf>,
    pub permission: ConfigFilePermission,
}

impl ConfigFileControl {
    pub const STATIC_CONFIG: ConfigFileControl = Self {
        path: None,
        permission: ConfigFilePermission(
            ConfigFilePermission::READ_ONLY | ConfigFilePermission::NO_DELETE,
        ),
    };

    pub fn new(path: Option<PathBuf>, permission: ConfigFilePermission) -> Self {
        ConfigFileControl { path, permission }
    }

    pub async fn from_path(path: PathBuf) -> Self {
        let read_only = if let Ok(metadata) = tokio::fs::metadata(&path).await {
            metadata.permissions().readonly()
        } else {
            true
        };
        Self::new(
            Some(path),
            if read_only {
                ConfigFilePermission(ConfigFilePermission::READ_ONLY)
            } else {
                ConfigFilePermission(0)
            },
        )
    }

    pub fn is_read_only(&self) -> bool {
        self.permission.has_flag(ConfigFilePermission::READ_ONLY)
    }
    pub fn set_read_only(&mut self, read_only: bool) {
        if read_only {
            self.permission = self.permission.with_flag(ConfigFilePermission::READ_ONLY);
        } else {
            self.permission = self.permission.remove_flag(ConfigFilePermission::READ_ONLY);
        }
    }

    pub fn is_no_delete(&self) -> bool {
        self.permission.has_flag(ConfigFilePermission::NO_DELETE)
    }
    pub fn set_no_delete(&mut self, no_delete: bool) {
        if no_delete {
            self.permission = self.permission.with_flag(ConfigFilePermission::NO_DELETE);
        } else {
            self.permission = self.permission.remove_flag(ConfigFilePermission::NO_DELETE);
        }
    }

    pub fn is_deletable(&self) -> bool {
        !self.is_no_delete()
    }
}

pub async fn load_config_from_file(
    config_file: &PathBuf,
    config_dir: Option<&PathBuf>,
    disable_env_parsing: bool,
) -> Result<(TomlConfigLoader, ConfigFileControl), anyhow::Error> {
    if config_file.as_os_str() == "-" {
        let mut stdin = String::new();
        _ = tokio::io::stdin()
            .read_to_string(&mut stdin)
            .await
            .context("failed to read config from stdin")?;
        let config = TomlConfigLoader::new_from_str_with_source("stdin", &stdin)?;
        return Ok((config, ConfigFileControl::STATIC_CONFIG));
    }

    let config_str = tokio::fs::read_to_string(config_file)
        .await
        .with_context(|| format!("failed to read config file: {}", config_file.display()))?;

    let (expanded_config_str, uses_env_vars) = if disable_env_parsing {
        (config_str.clone(), false)
    } else {
        env_parser::expand_env_vars(&config_str)
    };

    if disable_env_parsing {
        tracing::info!(
            "Environment variable parsing is disabled for config file: {:?}",
            config_file
        );
    }

    if uses_env_vars {
        tracing::info!(
            "Environment variables detected and expanded in config file: {:?}",
            config_file
        );
    }

    let source_name = config_file.display().to_string();
    let config = TomlConfigLoader::new_from_str_with_source(&source_name, &expanded_config_str)?;

    let mut control = ConfigFileControl::from_path(config_file.clone()).await;

    if uses_env_vars {
        control.set_read_only(true);
        control.set_no_delete(true);
        tracing::info!(
            "Config file {:?} uses environment variables, marked as READ_ONLY and NO_DELETE",
            config_file
        );
    } else if control.is_read_only() {
        control.set_no_delete(true);
    } else if let Some(config_dir) = config_dir {
        if let Some(config_file_dir) = config_file.parent() {
            // if the config file is in the config dir and named as the instance id, it can be saved remotely
            if config_file_dir == config_dir
                && config_file.file_stem() == Some(config.get_id().to_string().as_ref())
                && config_file.extension() == Some(std::ffi::OsStr::new("toml"))
            {
                control.set_no_delete(false);
            } else {
                control.set_no_delete(true);
            }
        }
    } else {
        control.set_no_delete(true);
    }

    Ok((config, control))
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Every leaf of `MpConfig` (singular sub-messages expanded, repeated
    /// fields as leaves), from the proto descriptor itself.
    fn mp_config_leaf_paths() -> Vec<String> {
        fn walk(desc: &prost_reflect::MessageDescriptor, prefix: &str, out: &mut Vec<String>) {
            for field in desc.fields() {
                let path = format!("{prefix}.{}", field.name());
                match field.kind() {
                    prost_reflect::Kind::Message(sub) if !field.is_list() && !field.is_map() => {
                        walk(&sub, &path, out)
                    }
                    _ => out.push(path),
                }
            }
        }
        let mut out = Vec::new();
        walk(&MpConfig::default().descriptor(), "mp", &mut out);
        out
    }

    #[test]
    fn field_effects_cover_every_mp_config_field() {
        let leaves = mp_config_leaf_paths();
        let table = FIELD_EFFECTS
            .iter()
            .map(|(path, _)| path.to_string())
            .filter(|path| path.starts_with("mp."))
            .collect::<std::collections::BTreeSet<_>>();
        let leaves_set = leaves.iter().cloned().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(table, leaves_set, "FIELD_EFFECTS must list exactly the MpConfig fields");
        assert_eq!(FIELD_EFFECTS.len(), FIELD_EFFECTS.iter().map(|(p, _)| p).collect::<std::collections::HashSet<_>>().len());
        assert_eq!(field_effect("mp.congestion_control"), Some(FieldEffect::Reconnect));
        assert_eq!(field_effect("mp.nope"), None);
    }

    /// Set `ET_UPDATE_SNAPSHOTS=1` to rewrite the GUI copy from the table.
    #[test]
    fn field_effects_snapshot_matches_the_gui_copy() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../easytier-web/frontend-lib/src/generated/mp_field_effects.json");
        let mut map = serde_json::Map::new();
        for (field, effect) in FIELD_EFFECTS {
            map.insert(field.to_string(), serde_json::Value::from(effect.as_str()));
        }
        let expected = serde_json::Value::Object(map);
        if std::env::var_os("ET_UPDATE_SNAPSHOTS").is_some() {
            std::fs::write(&path, serde_json::to_string_pretty(&expected).unwrap() + "\n").unwrap();
        }
        let actual: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(actual, expected, "{} is stale; rerun with ET_UPDATE_SNAPSHOTS=1", path.display());
    }

    #[test]
    fn reconnect_fingerprint_changes_only_with_reconnect_fields() {
        let base = gen_default_mp_config();
        let fingerprint = mp_reconnect_fingerprint(&base);
        let mut hot = base.clone();
        hot.kmax += 1;
        hot.data_plane.get_or_insert_with(Default::default).oversize = "fragment".into();
        assert_eq!(mp_reconnect_fingerprint(&hot), fingerprint);
        let mut cc = base.clone();
        cc.congestion_control = "cubic".into();
        assert_ne!(mp_reconnect_fingerprint(&cc), fingerprint);
        // CAKE's target/interval are hot, SQM on/off is not.
        let mut timing = base.clone();
        timing.sqm.get_or_insert_with(Default::default).target_ms += 1;
        assert_eq!(mp_reconnect_fingerprint(&timing), fingerprint);
        let mut sqm = base.clone();
        let enabled = sqm.sqm.get_or_insert_with(Default::default).enabled;
        sqm.sqm.get_or_insert_with(Default::default).enabled = !enabled;
        assert_ne!(mp_reconnect_fingerprint(&sqm), fingerprint);
        let mut dp = base.clone();
        dp.data_plane.get_or_insert_with(Default::default).enabled = true;
        assert_ne!(mp_reconnect_fingerprint(&dp), fingerprint);
    }
    use crate::tests::{remove_env_var, set_env_var};
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    #[test]
    fn invalid_toml_error_includes_location_and_source_line() {
        let error = TomlConfigLoader::new_from_str("dhcp = \"yes\"").unwrap_err();
        let display = error.to_string();

        assert!(display.contains("failed to parse config TOML"));
        assert!(display.contains("inline config"));
        assert!(display.contains("dhcp = \"yes\""));
        assert!(display.contains("^"));
        assert!(display.contains("invalid type: string"));
        assert!(!display.contains("<unknown>"));
        assert!(
            error
                .chain()
                .any(|err| err.downcast_ref::<toml::de::Error>().is_some())
        );
    }

    #[test]
    fn invalid_file_toml_error_includes_config_source() {
        let mut config_file = NamedTempFile::new().unwrap();
        writeln!(config_file, "dhcp = \"yes\"").unwrap();

        let error = TomlConfigLoader::new(&config_file.path().to_path_buf()).unwrap_err();
        let error = error.to_string();

        assert!(error.contains(config_file.path().to_string_lossy().as_ref()));
        assert!(error.contains("failed to parse config TOML"));
        assert!(error.contains("dhcp = \"yes\""));
        assert!(error.contains("^"));
        assert!(error.contains("invalid type: string"));
        assert!(!error.contains("<unknown>"));
    }

    #[test]
    fn invalid_stdin_toml_error_includes_config_source_in_display() {
        let error = TomlConfigLoader::new_from_str_with_source("stdin", "dhcp = \"yes\"")
            .unwrap_err()
            .to_string();

        assert!(error.contains("stdin"));
        assert!(error.contains("failed to parse config TOML"));
        assert!(error.contains("dhcp = \"yes\""));
        assert!(error.contains("^"));
        assert!(error.contains("invalid type: string"));
        assert!(!error.contains("<unknown>"));
    }

    #[test]
    fn invalid_toml_error_handles_non_ascii_before_error() {
        let error = TomlConfigLoader::new_from_str("hostname = \"节点\"\ndhcp = \"yes\"")
            .unwrap_err()
            .to_string();

        assert!(error.contains("dhcp = \"yes\""));
        assert!(error.contains("^"));
        assert!(error.contains("invalid type: string"));
    }

    #[test]
    fn invalid_toml_error_handles_non_ascii_before_error_on_same_line() {
        let error = TomlConfigLoader::new_from_str("hostname = \"节点\" dhcp = \"yes\"")
            .unwrap_err()
            .to_string();

        assert!(error.contains("failed to parse config TOML"));
        assert!(error.contains("inline config:1:"));
        assert!(error.contains("hostname = \"节点\" dhcp = \"yes\""));
        assert!(error.contains("expected newline"));
        assert!(!error.contains("<unknown>"));
    }

    /// A config written before `mp.sqm.autorate_enforce` and
    /// `mp.data_plane.datagram_bypass_cwnd` were retired still loads.
    #[test]
    fn config_with_retired_mp_fields_still_loads() {
        let cfg = TomlConfigLoader::new_from_str(
            r#"
[network_identity]
network_name = "n"
network_secret = "s"

[flags.mp]
enabled = true
sqm = { enabled = true, autorate_enforce = false, target_ms = 7, interval_ms = 100 }
data_plane = { enabled = true, datagram_bypass_cwnd = true, oversize = "stream" }
"#,
        )
        .unwrap();
        let mp = cfg.get_flags().mp.unwrap();
        assert!(mp.enabled);
        assert_eq!(mp.sqm.unwrap().target_ms, 7);
        assert!(mp.data_plane.unwrap().enabled);
    }

    /// P4-A: a config written while the Top-K optimizer existed still loads;
    /// its six fields are dropped on read and do not come back on dump.
    /// Red before the change: `[flags]` is parsed strictly, so the unknown
    /// `lambda` key failed the whole load (and, with the fields still in the
    /// struct, was written back).
    #[test]
    fn config_with_retired_optimizer_fields_still_loads() {
        let cfg = TomlConfigLoader::new_from_str(
            r#"
[network_identity]
network_name = "n"
network_secret = "s"

[flags.mp]
enabled = true
kmax = 3
optimizer = "min-latency"
lambda = 0.8
churn_penalty = 0.05
path_penalty = 0.01
switch_margin = 0.1
confirm_rounds = 3
max_sample_age_ms = 5000
"#,
        )
        .unwrap();
        let mp = cfg.get_flags().mp.unwrap();
        assert!(mp.enabled);
        assert_eq!(mp.kmax, 3);
        let dumped = cfg.dump();
        for field in [
            "optimizer",
            "lambda",
            "churn_penalty",
            "path_penalty",
            "switch_margin",
            "confirm_rounds",
            "max_sample_age_ms",
        ] {
            assert!(!dumped.contains(field), "{field} must not be written back");
        }
    }

    #[test]
    fn invalid_file_flags_error_includes_config_source_in_display() {
        let mut config_file = NamedTempFile::new().unwrap();
        writeln!(config_file, "[flags]").unwrap();
        writeln!(config_file, "socket_mark = \"bad\"").unwrap();

        let error = TomlConfigLoader::new(&config_file.path().to_path_buf()).unwrap_err();

        let display = error.to_string();
        assert!(display.contains(config_file.path().to_string_lossy().as_ref()));
        assert!(display.contains("failed to load config"));
        assert!(display.contains("failed to parse flags"));

        // with_context preserves the cause chain so callers can inspect the root reason.
        let chain: Vec<String> = error.chain().map(|e| e.to_string()).collect();
        assert!(chain.iter().any(|m| m.contains("failed to parse flags")));
    }

    #[test]
    fn socket_mark_config_file_roundtrip_none_some_and_zero() {
        // Omitting the flag leaves socket_mark unset (None) -> SO_MARK untouched.
        let cfg = TomlConfigLoader::new_from_str(
            r#"
[network_identity]
network_name = "n"
network_secret = "s"
"#,
        )
        .unwrap();
        assert_eq!(cfg.get_flags().socket_mark, None);

        // socket_mark = 0 is a legitimate value distinct from "unset".
        let cfg = TomlConfigLoader::new_from_str(
            r#"
[network_identity]
network_name = "n"
network_secret = "s"

[flags]
socket_mark = 0
"#,
        )
        .unwrap();
        assert_eq!(cfg.get_flags().socket_mark, Some(0));

        // A non-zero mark round-trips as Some(v).
        let cfg = TomlConfigLoader::new_from_str(
            r#"
[network_identity]
network_name = "n"
network_secret = "s"

[flags]
socket_mark = 66
"#,
        )
        .unwrap();
        assert_eq!(cfg.get_flags().socket_mark, Some(66));

        // set_flags(None) must serialize back through gen_config without
        // resurrecting a value (guards the gen_flags merge against dropping
        // the key when the serialized default is null).
        cfg.set_flags(Flags {
            socket_mark: None,
            ..cfg.get_flags()
        });
        assert_eq!(cfg.get_flags().socket_mark, None);
    }

    #[test]
    fn dump_preserves_flags_that_differ_from_easytier_defaults() {
        let cfg = TomlConfigLoader::default();
        let mut flags = gen_default_flags();
        flags.dev_name = "et_test".to_string();
        flags.enable_quic_proxy = true;
        flags.disable_tcp_hole_punching = true;
        flags.disable_sym_hole_punching = true;
        flags.multi_thread = false;
        flags.bind_device = false;
        flags.enable_ipv6 = false;
        flags.relay_network_whitelist = "".to_string();
        flags.mtu = 0;
        flags.socket_mark = Some(0);
        flags.tcp_hole_punch_mode = "faketcp".to_string();
        let mp = flags.mp.as_mut().unwrap();
        mp.enabled = true;
        mp.kmax = 4;
        mp.egress_devices = vec!["Ethernet 2".to_string(), "Wi-Fi".to_string()];
        cfg.set_flags(flags);

        let dumped = cfg.dump();

        assert!(dumped.contains("dev_name = \"et_test\""));
        assert!(dumped.contains("enable_quic_proxy = true"));
        assert!(dumped.contains("disable_tcp_hole_punching = true"));
        assert!(dumped.contains("disable_sym_hole_punching = true"));
        assert!(dumped.contains("multi_thread = false"));
        assert!(dumped.contains("bind_device = false"));
        assert!(dumped.contains("enable_ipv6 = false"));
        assert!(dumped.contains("relay_network_whitelist = \"\""));
        assert!(dumped.contains("mtu = 0"));
        assert!(dumped.contains("socket_mark = 0"));
        assert!(dumped.contains("tcp_hole_punch_mode = \"faketcp\""));
        assert!(dumped.contains("enabled = true"));
        assert!(dumped.contains("kmax = 4"));
        assert!(!dumped.contains("lambda"));
        assert!(dumped.contains("Ethernet 2"));

        let reloaded = TomlConfigLoader::new_from_str(&dumped).unwrap();
        let reloaded_flags = reloaded.get_flags();
        assert_eq!(reloaded_flags.dev_name, "et_test");
        assert!(reloaded_flags.enable_quic_proxy);
        assert!(reloaded_flags.disable_tcp_hole_punching);
        assert!(reloaded_flags.disable_sym_hole_punching);
        assert!(!reloaded_flags.multi_thread);
        assert!(!reloaded_flags.bind_device);
        assert!(!reloaded_flags.enable_ipv6);
        assert_eq!(reloaded_flags.relay_network_whitelist, "");
        assert_eq!(reloaded_flags.mtu, 0);
        assert_eq!(reloaded_flags.socket_mark, Some(0));
        assert_eq!(reloaded_flags.tcp_hole_punch_mode, "faketcp");
        let reloaded_mp = reloaded_flags.mp.unwrap();
        assert!(reloaded_mp.enabled);
        assert_eq!(reloaded_mp.kmax, 4);
        assert_eq!(reloaded_mp.egress_devices, ["Ethernet 2", "Wi-Fi"]);
    }

    #[test]
    fn tcp_hole_punch_mode_defaults_to_auto() {
        assert_eq!(gen_default_flags().tcp_hole_punch_mode, "auto");
    }

    #[test]
    fn tcp_hole_punch_mode_rejects_unknown_values() {
        let err = TomlConfigLoader::new_from_str(
            r#"
[flags]
tcp_hole_punch_mode = "maybe"
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("tcp_hole_punch_mode"));
    }

    #[test]
    fn mp_config_defaults_and_partial_toml_preserve_nested_defaults() {
        let defaults = gen_default_flags().mp.unwrap();
        assert!(!defaults.enabled);
        assert_eq!(defaults.packet_scheduler, "sqm-weighted");
        assert_eq!(defaults.congestion_control, "engine-default");
        assert_eq!(defaults.kmax, 1);
        assert_eq!(defaults.establishment_timeout_ms, 10_000);

        let config = TomlConfigLoader::new_from_str(
            r#"
[flags.mp]
enabled = true
kmax = 2
"#,
        )
        .unwrap();
        let mp = config.get_flags().mp.unwrap();
        assert!(mp.enabled);
        assert_eq!(mp.kmax, 2);
        assert_eq!(mp.control_interval_ms, 500, "nested default must survive a partial table");
        assert_eq!(mp.establishment_timeout_ms, 10_000);
        assert_eq!(mp.congestion_control, "engine-default");
        assert_eq!(
            mp.providers,
            ["udp-direct", "udp-punch", "faketcp-punch", "relay-next-hop"]
        );
    }

    #[test]
    fn mp_config_rejects_tun_as_egress_and_invalid_timeouts() {
        let tun_error = TomlConfigLoader::new_from_str(
            r#"
[flags.mp]
egress_devices = ["tun0"]
"#,
        )
        .unwrap_err();
        assert!(tun_error.to_string().contains("tunnel/loopback"));

        let deadline_error = TomlConfigLoader::new_from_str(
            r#"
[flags.mp]
establishment_timeout_ms = 999
"#,
        )
        .unwrap_err();
        assert!(
            deadline_error
                .to_string()
                .contains("mp.establishment_timeout_ms")
        );
    }

    /// `[flags.mp.sqm]` is a full replacement of the default `sqm` table,
    /// not a per-field merge like `[flags.mp]`'s own top-level scalars get
    /// (`gen_flags`'s merge is one level deep: `mp.extend(mp_override)`
    /// overwrites the whole `sqm` key wholesale, since `sqm` itself is a
    /// nested JSON object, not a scalar). Every case below therefore spells
    /// out every field it needs a specific value for, exactly like every
    /// other nested-message MP config field (`path_policies`,
    /// `resource_groups`) already has to.
    #[test]
    fn mp_sqm_reflectors_must_be_ipv4_addresses() {
        let bad = TomlConfigLoader::new_from_str(
            r#"
[flags.mp.sqm]
target_ms = 5
interval_ms = 100
reflectors = ["223.5.5.5", "dns.example"]
"#,
        )
        .unwrap_err();
        assert!(bad.to_string().contains("mp.sqm.reflectors"), "{bad}");

        let good = TomlConfigLoader::new_from_str(
            r#"
[flags.mp.sqm]
target_ms = 5
interval_ms = 100
reflectors = ["223.5.5.5", "1.2.4.8"]
reflectors_disabled = false
"#,
        )
        .unwrap();
        let sqm = good.get_flags().mp.unwrap().sqm.unwrap();
        assert_eq!(sqm.reflectors, vec!["223.5.5.5", "1.2.4.8"]);
    }

    #[test]
    fn mp_sqm_config_rejects_zero_target_or_interval_and_target_not_below_interval() {
        let zero_target = TomlConfigLoader::new_from_str(
            r#"
[flags.mp.sqm]
target_ms = 0
interval_ms = 100
"#,
        )
        .unwrap_err();
        assert!(zero_target.to_string().contains("mp.sqm.target_ms"));

        let zero_interval = TomlConfigLoader::new_from_str(
            r#"
[flags.mp.sqm]
target_ms = 5
interval_ms = 0
"#,
        )
        .unwrap_err();
        assert!(zero_interval.to_string().contains("mp.sqm.interval_ms"));

        // CAKE's target must be smaller than its interval (RFC 8289 §4.2's
        // "5ms target / 100ms interval" relationship, not just both nonzero).
        let target_not_below_interval = TomlConfigLoader::new_from_str(
            r#"
[flags.mp.sqm]
target_ms = 100
interval_ms = 100
"#,
        )
        .unwrap_err();
        assert!(
            target_not_below_interval
                .to_string()
                .contains("mp.sqm.target_ms")
        );
    }

    #[test]
    fn mp_sqm_config_rejects_autorate_min_above_max() {
        let error = TomlConfigLoader::new_from_str(
            r#"
[flags.mp.sqm]
target_ms = 5
interval_ms = 100
autorate_min_bps = 10000000
autorate_max_bps = 1000000
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("autorate_min_bps"));
    }

    #[test]
    fn mp_sqm_config_default_is_disabled_and_valid() {
        // The generated default (target_ms=5 < interval_ms=100, autorate
        // off) must itself pass validation -- a sanity check that the bounds
        // added above do not reject the shipped default.
        validate_mp_config(&gen_default_mp_config()).unwrap();
    }

    #[test]
    fn mp_punch_attempts_defaults_to_one_and_is_capped() {
        let mut config = gen_default_mp_config();
        assert_eq!(effective_mp_punch_attempts(&config), 1);
        config.punch_attempts = 0;
        assert_eq!(
            effective_mp_punch_attempts(&config),
            1,
            "an old config without the field keeps the single punch"
        );
        config.punch_attempts = MAX_MP_PUNCH_ATTEMPTS;
        validate_mp_config(&config).unwrap();
        assert_eq!(effective_mp_punch_attempts(&config), 8);
        config.punch_attempts = MAX_MP_PUNCH_ATTEMPTS + 1;
        assert!(
            validate_mp_config(&config)
                .unwrap_err()
                .to_string()
                .contains("punch_attempts")
        );
    }

    #[test]
    fn mp_resource_group_accepts_ip_and_socket_remote_endpoints() {
        let config = TomlConfigLoader::new_from_str(
            r#"
[[flags.mp.resource_groups]]
name = "remote-wan"
capacity_bps = 100000000
remote_endpoints = ["203.0.113.10", "[2001:db8::10]:443"]
"#,
        )
        .unwrap();
        let group = &config.get_flags().mp.unwrap().resource_groups[0];
        assert_eq!(group.name, "remote-wan");
        assert_eq!(
            group.remote_endpoints,
            ["203.0.113.10", "[2001:db8::10]:443"]
        );
        assert_eq!(group.capacity_bps, 100_000_000);
    }

    #[test]
    fn mp_resource_group_rejects_invalid_remote_endpoint() {
        let error = TomlConfigLoader::new_from_str(
            r#"
[[flags.mp.resource_groups]]
name = "remote-wan"
remote_endpoints = ["not-an-endpoint"]
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("invalid remote endpoint"));
    }

    #[test]
    fn mp_path_policy_accepts_valid_action_and_wildcard_matches() {
        let config = TomlConfigLoader::new_from_str(
            r#"
[[flags.mp.path_policies]]
action = "pin"
match_egress_device = "eth0"

[[flags.mp.path_policies]]
action = "prefer"
prefer_weight = 2.0
match_remote_endpoint = "203.0.113.10:4000"
"#,
        )
        .unwrap();
        let policies = &config.get_flags().mp.unwrap().path_policies;
        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].action, "pin");
        assert_eq!(policies[0].match_egress_device, "eth0");
        assert_eq!(policies[1].action, "prefer");
        assert_eq!(policies[1].prefer_weight, 2.0);
    }

    #[test]
    fn mp_path_policy_rejects_unknown_action() {
        let error = TomlConfigLoader::new_from_str(
            r#"
[[flags.mp.path_policies]]
action = "throttle"
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("invalid action"));
    }

    #[test]
    fn mp_path_policy_prefer_action_requires_positive_finite_weight() {
        let zero_error = TomlConfigLoader::new_from_str(
            r#"
[[flags.mp.path_policies]]
action = "prefer"
prefer_weight = 0.0
"#,
        )
        .unwrap_err();
        assert!(zero_error.to_string().contains("prefer_weight"));

        let negative_error = TomlConfigLoader::new_from_str(
            r#"
[[flags.mp.path_policies]]
action = "prefer"
prefer_weight = -1.0
"#,
        )
        .unwrap_err();
        assert!(negative_error.to_string().contains("prefer_weight"));
    }

    #[test]
    fn mp_path_policy_rejects_invalid_remote_endpoint() {
        let error = TomlConfigLoader::new_from_str(
            r#"
[[flags.mp.path_policies]]
action = "exclude"
match_remote_endpoint = "not-an-endpoint"
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("match_remote_endpoint"));
    }

    #[test]
    fn mp_brutal_without_up_mbps_uses_the_default_rate() {
        TomlConfigLoader::new_from_str(
            r#"
[flags.mp]
congestion_control = "brutal"
"#,
        )
        .expect("an omitted up_mbps falls back to the 50 Mbit/s default");
        let error = TomlConfigLoader::new_from_str(
            r#"
[flags.mp]
congestion_control = "brutal"
congestion_control_params_json = '{"up_mbps": 0}'
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("up_mbps"), "{error}");
    }

    #[test]
    fn mp_brutal_with_up_mbps_in_params_json_is_accepted() {
        let config = TomlConfigLoader::new_from_str(
            r#"
[flags.mp]
congestion_control = "brutal"
congestion_control_params_json = '{"up_mbps": 20}'
"#,
        )
        .unwrap();
        assert_eq!(config.get_flags().mp.unwrap().congestion_control, "brutal");
    }

    #[test]
    fn mp_congestion_control_params_json_must_be_valid_json() {
        let error = TomlConfigLoader::new_from_str(
            r#"
[flags.mp]
congestion_control_params_json = "not json"
"#,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("congestion_control_params_json"),
            "{error}"
        );
    }

    #[test]
    fn mp_non_brutal_profiles_ignore_congestion_control_params_json() {
        for profile in ["engine-default", "bbr", "cubic", "bbr3", "copa"] {
            let toml = format!(
                r#"
[flags.mp]
congestion_control = "{profile}"
"#
            );
            TomlConfigLoader::new_from_str(&toml)
                .unwrap_or_else(|error| panic!("{profile} should validate: {error}"));
        }
    }

    #[test]
    fn test_stun_servers_config() {
        let config = TomlConfigLoader::default();
        let stun_servers = config.get_stun_servers();
        assert!(stun_servers.is_none());

        // Test setting custom stun servers
        let custom_servers = vec!["txt:stun.easytier.cn".to_string()];
        config.set_stun_servers(Some(custom_servers.clone()));

        let retrieved_servers = config.get_stun_servers();
        assert_eq!(retrieved_servers.unwrap(), custom_servers);
    }

    #[test]
    fn configured_tcp_stun_servers_roundtrip_independently_of_udp() {
        let default = TomlConfigLoader::default();
        assert_eq!(default.get_tcp_stun_servers(), None);
        assert!(!default.dump().contains("tcp_stun_servers"));

        let config = TomlConfigLoader::new_from_str(
            r#"stun_servers = ["192.0.2.1:3478"]
tcp_stun_servers = ["192.0.2.2:3478", "192.0.2.3:3479"]"#,
        )
        .unwrap();
        let expected = vec!["192.0.2.2:3478".to_owned(), "192.0.2.3:3479".to_owned()];
        assert_eq!(config.get_tcp_stun_servers(), Some(expected.clone()));
        let restored = TomlConfigLoader::new_from_str(&config.dump()).unwrap();
        assert_eq!(restored.get_tcp_stun_servers(), Some(expected));
        assert_eq!(restored.get_stun_servers(), Some(vec!["192.0.2.1:3478".to_owned()]));
        restored.set_tcp_stun_servers(None);
        assert_eq!(restored.get_tcp_stun_servers(), None);
        assert_eq!(restored.get_stun_servers(), config.get_stun_servers());
    }

    #[test]
    fn test_stun_servers_toml_parsing() {
        let config_str = r#"
instance_name = "test"
stun_servers = [
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "txt:stun.easytier.cn"
]"#;

        let config = TomlConfigLoader::new_from_str(config_str).unwrap();
        let stun_servers = config.get_stun_servers().unwrap();

        assert_eq!(stun_servers.len(), 3);
        assert_eq!(stun_servers[0], "stun.l.google.com:19302");
        assert_eq!(stun_servers[1], "stun1.l.google.com:19302");
        assert_eq!(stun_servers[2], "txt:stun.easytier.cn");
    }

    #[test]
    fn test_network_config_source_toml_roundtrip() {
        let config = TomlConfigLoader::default();
        assert_eq!(config.get_network_config_source(), ConfigSource::User);

        config.set_network_config_source(Some(ConfigSource::Web));
        let dumped = config.dump();

        assert!(dumped.contains("[source]"));
        assert!(dumped.contains("source = \"web\""));

        let loaded = TomlConfigLoader::new_from_str(&dumped).unwrap();
        assert_eq!(loaded.get_network_config_source(), ConfigSource::Web);
    }

    #[test]
    fn test_toml_credential_mode_omits_network_secret() {
        for network_secret in ["", r#"network_secret = """#] {
            let config = TomlConfigLoader::new_from_str(&format!(
                r#"
[network_identity]
network_name = "credential-network"
{network_secret}

[secure_mode]
enabled = true
"#
            ))
            .unwrap();

            let identity = config.get_network_identity();
            assert_eq!(identity.network_name, "credential-network");
            assert_eq!(identity.network_secret, None);
            assert_eq!(identity.network_secret_digest, None);
            assert!(!config.dump().contains("network_secret"));
        }
    }

    #[test]
    fn test_toml_secure_mode_without_network_identity_uses_default_secret() {
        let config = TomlConfigLoader::new_from_str(
            r#"
[secure_mode]
enabled = true
"#,
        )
        .unwrap();

        let identity = config.get_network_identity();
        assert_eq!(identity.network_name, "default");
        assert_eq!(identity.network_secret.as_deref(), Some(""));
        assert!(identity.network_secret_digest.is_some());
    }

    #[test]
    fn test_parse_mapped_listener_urls_allows_ws_without_port() {
        let parsed = parse_mapped_listener_urls(&[
            "ws://example.com".to_string(),
            "wss://example.com/path".to_string(),
        ])
        .unwrap();

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].scheme(), "ws");
        assert_eq!(parsed[0].port(), None);
        assert_eq!(parsed[1].scheme(), "wss");
        assert_eq!(parsed[1].port(), None);
    }

    #[test]
    fn test_parse_mapped_listener_urls_allows_tcp_without_port() {
        let parsed = parse_mapped_listener_urls(&["tcp://127.0.0.1".to_string()]).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].scheme(), "tcp");
        assert_eq!(parsed[0].port(), None);
    }

    #[test]
    fn test_parse_mapped_listener_urls_requires_port_for_non_ip_scheme() {
        let err = parse_mapped_listener_urls(&["ring://peer-id".to_string()]).unwrap_err();

        assert!(err.to_string().contains("mapped listener port is missing"));
    }

    #[test]
    fn test_acl_toml_rule_uses_defaults_for_omitted_fields() {
        use crate::proto::acl::{Action, ChainType, Protocol};

        let config_str = r#"
[[acl.acl_v1.chains]]
name = "subnet_proxy_protect"
chain_type = 3
enabled = true
default_action = 2

[[acl.acl_v1.chains.rules]]
name = "allow_my_devices"
priority = 1000
action = 1
source_ips = ["10.172.192.2/32"]
protocol = 5
enabled = true
"#;

        let config = TomlConfigLoader::new_from_str(config_str).unwrap();
        let acl = config.get_acl().unwrap();
        let acl_v1 = acl.acl_v1.unwrap();
        let chain = &acl_v1.chains[0];
        let rule = &chain.rules[0];

        assert_eq!(chain.chain_type, ChainType::Forward as i32);
        assert_eq!(chain.default_action, Action::Drop as i32);
        assert_eq!(rule.action, Action::Allow as i32);
        assert_eq!(rule.protocol, Protocol::Any as i32);
        assert_eq!(rule.source_ips, vec!["10.172.192.2/32"]);
        assert!(rule.ports.is_empty());
        assert!(rule.source_ports.is_empty());
        assert!(rule.destination_ips.is_empty());
        assert!(rule.source_groups.is_empty());
        assert!(rule.destination_groups.is_empty());
        assert_eq!(rule.rate_limit, 0);
        assert_eq!(rule.burst_limit, 0);
        assert!(!rule.stateful);
    }

    #[test]
    fn test_acl_toml_group_can_omit_declares_or_members() {
        let declares_only = r#"
[acl.acl_v1.group]

[[acl.acl_v1.group.declares]]
group_name = "admin"
group_secret = "admin-pw"
"#;
        let config = TomlConfigLoader::new_from_str(declares_only).unwrap();
        let group = config.get_acl().unwrap().acl_v1.unwrap().group.unwrap();
        assert_eq!(group.declares.len(), 1);
        assert!(group.members.is_empty());

        let members_only = r#"
[acl.acl_v1.group]
members = ["admin"]
"#;
        let config = TomlConfigLoader::new_from_str(members_only).unwrap();
        let group = config.get_acl().unwrap().acl_v1.unwrap().group.unwrap();
        assert!(group.declares.is_empty());
        assert_eq!(group.members, vec!["admin"]);
    }

    #[test]
    fn test_network_config_source_user_is_implicit() {
        let config = TomlConfigLoader::default();
        config.set_network_config_source(Some(ConfigSource::User));
        let dumped = config.dump();

        assert!(!dumped.contains("[source]"));

        let loaded = TomlConfigLoader::new_from_str(&dumped).unwrap();
        assert_eq!(loaded.get_network_config_source(), ConfigSource::User);

        let explicit_user = TomlConfigLoader::new_from_str(
            r#"
[source]
source = "user"
"#,
        )
        .unwrap();
        assert_eq!(
            explicit_user.get_network_config_source(),
            ConfigSource::User
        );
        assert!(!explicit_user.dump().contains("[source]"));
    }

    #[test]
    fn test_ipv6_public_addr_config_roundtrip() {
        let config = TomlConfigLoader::default();
        let prefix: cidr::Ipv6Cidr = "2001:db8:100::/64".parse().unwrap();

        config.set_ipv6_public_addr_provider(true);
        config.set_ipv6_public_addr_auto(true);
        config.set_ipv6_public_addr_prefix(Some(prefix));

        assert!(config.get_ipv6_public_addr_provider());
        assert!(config.get_ipv6_public_addr_auto());
        assert_eq!(config.get_ipv6_public_addr_prefix(), Some(prefix));

        let dumped = config.dump();
        let loaded = TomlConfigLoader::new_from_str(&dumped).unwrap();
        assert!(loaded.get_ipv6_public_addr_provider());
        assert!(loaded.get_ipv6_public_addr_auto());
        assert_eq!(loaded.get_ipv6_public_addr_prefix(), Some(prefix));
    }

    #[tokio::test]
    async fn full_example_test() {
        let config_str = r#"
instance_name = "default"
instance_id = "87ede5a2-9c3d-492d-9bbe-989b9d07e742"
ipv4 = "10.144.144.10"
listeners = [ "tcp://0.0.0.0:11010", "udp://0.0.0.0:11010" ]
routes = [ "192.168.0.0/16" ]

[network_identity]
network_name = "default"
network_secret = ""

[[peer]]
uri = "tcp://public.kkrainbow.top:11010"

[[peer]]
uri = "udp://192.168.94.33:11010"

[[proxy_network]]
cidr = "10.147.223.0/24"
allow = ["tcp", "udp", "icmp"]

[[proxy_network]]
cidr = "10.1.1.0/24"
allow = ["tcp", "icmp"]

[file_logger]
level = "info"
file = "easytier"
dir = "/tmp/easytier"

[console_logger]
level = "warn"

[[port_forward]]
bind_addr = "0.0.0.0:11011"
dst_addr = "192.168.94.33:11011"
proto = "tcp"
"#;
        let ret = TomlConfigLoader::new_from_str(config_str);
        if let Err(e) = &ret {
            println!("{}", e);
        } else {
            println!("{:?}", ret.as_ref().unwrap());
        }
        assert!(ret.is_ok());

        let ret = ret.unwrap();
        assert_eq!("10.144.144.10/24", ret.get_ipv4().unwrap().to_string());

        assert_eq!(
            vec!["tcp://0.0.0.0:11010", "udp://0.0.0.0:11010"],
            ret.get_listener_uris()
                .iter()
                .map(|u| u.to_string())
                .collect::<Vec<String>>()
        );

        assert_eq!(
            vec![PortForwardConfig {
                bind_addr: "0.0.0.0:11011".parse().unwrap(),
                dst_addr: "192.168.94.33:11011".parse().unwrap(),
                proto: "tcp".to_string(),
            }],
            ret.get_port_forwards()
        );
        println!("{}", ret.dump());
    }

    /// 配置文件环境变量解析功能的集成测试
    ///
    /// 测试范围：
    /// 1. 配置加载功能测试（环境变量替换、权限标记）
    /// 2. RPC API 安全测试（只读配置保护）
    /// 3. CLI 参数测试（--disable-env-parsing 开关）
    /// 4. 多实例隔离测试
    /// 5. 实际配置字段测试（network_secret、peer.uri 等）
    /// 配置加载功能测试（环境变量替换、权限标记）
    ///
    /// 验证：
    /// - 环境变量能正确替换到配置中
    /// - 包含环境变量的配置文件自动标记为只读和禁止删除
    #[tokio::test]
    async fn test_env_var_expansion_and_readonly_flag() {
        // 设置测试环境变量
        set_env_var("TEST_SECRET", "my-test-secret-123");
        set_env_var("TEST_NETWORK", "test-network");

        // 创建临时配置文件，包含环境变量占位符
        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "test-instance"

[network_identity]
network_name = "${TEST_NETWORK}"
network_secret = "${TEST_SECRET}"
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());

        // 加载配置（启用环境变量解析）
        let (config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证环境变量已被替换
        let network_identity = config.get_network_identity();
        assert_eq!(network_identity.network_name, "test-network");
        assert_eq!(
            network_identity.network_secret.as_ref().unwrap(),
            "my-test-secret-123"
        );

        // 验证权限标记：包含环境变量的配置应被标记为只读和禁止删除
        assert!(
            control.is_read_only(),
            "Config with env vars should be marked as READ_ONLY"
        );
        assert!(
            control.is_no_delete(),
            "Config with env vars should be marked as NO_DELETE"
        );

        // 清理环境变量
        remove_env_var("TEST_SECRET");
        remove_env_var("TEST_NETWORK");
    }

    /// RPC API 安全测试（只读配置保护）
    ///
    /// 验证：
    /// - 只读配置不会通过 RPC API 暴露给远程调用
    /// - 这需要测试 get_network_instance_config 拒绝返回只读配置
    ///
    /// 注：这个测试验证权限标记的正确设置，实际的 RPC API 保护已在
    /// `easytier/src/rpc_service/instance_manage.rs` 中实现
    #[tokio::test]
    async fn test_readonly_config_api_protection() {
        set_env_var("API_TEST_SECRET", "secret-value");

        // 创建包含环境变量的配置
        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "api-test"

[network_identity]
network_name = "api-network"
network_secret = "${API_TEST_SECRET}"
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());

        // 加载配置
        let (_config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证只读标记已设置（这是 RPC API 保护的前提）
        assert!(
            control.is_read_only(),
            "Config should be marked as READ_ONLY for RPC protection"
        );
        assert!(
            control.permission.has_flag(ConfigFilePermission::READ_ONLY),
            "Permission flag should be set correctly"
        );

        remove_env_var("API_TEST_SECRET");
    }

    /// CLI 参数测试（--disable-env-parsing 开关）
    ///
    /// 验证：
    /// - disable_env_parsing = true 时，环境变量不会被替换
    /// - 配置不会被标记为只读
    #[tokio::test]
    async fn test_disable_env_parsing_flag() {
        set_env_var("DISABLED_TEST_VAR", "should-not-expand");

        // 创建包含环境变量占位符的配置
        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "disable-test"

[network_identity]
network_name = "test"
network_secret = "${DISABLED_TEST_VAR}"
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());

        // 以 disable_env_parsing = true 加载配置
        let (config, control) = load_config_from_file(&config_path, None, true)
            .await
            .unwrap();

        // 验证环境变量未被替换（保持原样）
        let network_identity = config.get_network_identity();
        assert_eq!(
            network_identity.network_secret.as_ref().unwrap(),
            "${DISABLED_TEST_VAR}",
            "Env var should not be expanded when parsing is disabled"
        );

        // 验证配置不因环境变量而被标记为只读
        // 注：文件系统权限可能使其只读，但不应因环境变量而只读
        // 这里我们主要验证 NO_DELETE 标记的逻辑
        // 由于没有 config_dir，文件会被标记为 NO_DELETE，但不是因为环境变量
        assert!(
            control.is_no_delete(),
            "Config should be NO_DELETE due to no config_dir, not env vars"
        );

        remove_env_var("DISABLED_TEST_VAR");
    }

    /// 多实例隔离测试
    ///
    /// 验证：
    /// - 不同实例可以使用不同的环境变量值
    /// - 环境变量在运行时被解析，支持动态切换
    #[tokio::test]
    async fn test_multiple_instances_with_different_env_vars() {
        // 实例1：使用第一组环境变量
        set_env_var("INSTANCE_SECRET", "instance1-secret");
        set_env_var("INSTANCE_NAME", "instance-one");

        let mut temp_file1 = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "${INSTANCE_NAME}"

[network_identity]
network_name = "multi-test"
network_secret = "${INSTANCE_SECRET}"
"#;
        temp_file1.write_all(config_content.as_bytes()).unwrap();
        temp_file1.flush().unwrap();

        let config_path1 = PathBuf::from(temp_file1.path());
        let (config1, _) = load_config_from_file(&config_path1, None, false)
            .await
            .unwrap();

        // 验证实例1的配置
        assert_eq!(config1.get_inst_name(), "instance-one");
        assert_eq!(
            config1
                .get_network_identity()
                .network_secret
                .as_ref()
                .unwrap(),
            "instance1-secret"
        );

        // 实例2：修改环境变量后加载同一模板
        set_env_var("INSTANCE_SECRET", "instance2-secret");
        set_env_var("INSTANCE_NAME", "instance-two");

        let mut temp_file2 = NamedTempFile::new().unwrap();
        temp_file2.write_all(config_content.as_bytes()).unwrap();
        temp_file2.flush().unwrap();

        let config_path2 = PathBuf::from(temp_file2.path());
        let (config2, _) = load_config_from_file(&config_path2, None, false)
            .await
            .unwrap();

        // 验证实例2使用了不同的环境变量值
        assert_eq!(config2.get_inst_name(), "instance-two");
        assert_eq!(
            config2
                .get_network_identity()
                .network_secret
                .as_ref()
                .unwrap(),
            "instance2-secret"
        );

        // 验证两个实例的配置确实不同
        assert_ne!(config1.get_inst_name(), config2.get_inst_name());
        assert_ne!(
            config1.get_network_identity().network_secret,
            config2.get_network_identity().network_secret
        );

        // 清理
        remove_env_var("INSTANCE_SECRET");
        remove_env_var("INSTANCE_NAME");
    }

    /// 实际配置字段测试（network_secret、peer.uri 等）
    ///
    /// 验证：
    /// - network_secret 字段支持环境变量
    /// - peer.uri 字段支持环境变量
    /// - listeners 字段支持环境变量
    /// - 其他实际使用的配置字段
    #[tokio::test]
    async fn test_real_config_fields_expansion() {
        // 设置各种实际场景的环境变量
        set_env_var("ET_SECRET", "production-secret-key");
        set_env_var("PEER_HOST", "peer.example.com");
        set_env_var("PEER_PORT", "11011");
        set_env_var("LISTEN_PORT", "11010");
        set_env_var("NETWORK_NAME", "prod-network");

        // 创建包含多个实际字段的完整配置
        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "production"
ipv4 = "10.144.144.1"
listeners = ["tcp://0.0.0.0:${LISTEN_PORT}"]

[network_identity]
network_name = "${NETWORK_NAME}"
network_secret = "${ET_SECRET}"

[[peer]]
uri = "tcp://${PEER_HOST}:${PEER_PORT}"
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());

        let (config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证 network_identity 字段
        let identity = config.get_network_identity();
        assert_eq!(identity.network_name, "prod-network");
        assert_eq!(
            identity.network_secret.as_ref().unwrap(),
            "production-secret-key"
        );

        // 验证 listeners 字段
        let listeners = config.get_listener_uris();
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].to_string(), "tcp://0.0.0.0:11010");

        // 验证 peer 字段
        let peers = config.get_peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].uri.to_string(), "tcp://peer.example.com:11011");

        // 验证配置被正确标记
        assert!(control.is_read_only());
        assert!(control.is_no_delete());

        // 清理环境变量
        remove_env_var("ET_SECRET");
        remove_env_var("PEER_HOST");
        remove_env_var("PEER_PORT");
        remove_env_var("LISTEN_PORT");
        remove_env_var("NETWORK_NAME");
    }

    /// 带默认值的环境变量
    ///
    /// 验证：
    /// - ${VAR:-default} 语法在变量未定义时使用默认值
    #[tokio::test]
    async fn test_env_var_with_default_value() {
        // 确保变量未定义
        remove_env_var("UNDEFINED_PORT");
        remove_env_var("UNDEFINED_SECRET");

        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "default-test"
listeners = ["tcp://0.0.0.0:${UNDEFINED_PORT:-11010}"]

[network_identity]
network_name = "test"
network_secret = "${UNDEFINED_SECRET:-default-secret}"
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());

        let (config, _) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证使用了默认值
        assert_eq!(
            config
                .get_network_identity()
                .network_secret
                .as_ref()
                .unwrap(),
            "default-secret"
        );
        assert_eq!(
            config.get_listener_uris()[0].to_string(),
            "tcp://0.0.0.0:11010"
        );
    }

    /// 环境变量未定义且无默认值的情况
    ///
    /// 验证：
    /// - 未定义的环境变量保持原样（shellexpand 的默认行为）
    #[tokio::test]
    async fn test_undefined_env_var_without_default() {
        remove_env_var("COMPLETELY_UNDEFINED");

        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "undefined-test"

[network_identity]
network_name = "test"
network_secret = "${COMPLETELY_UNDEFINED}"
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());
        let (config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证变量保持原样
        assert_eq!(
            config
                .get_network_identity()
                .network_secret
                .as_ref()
                .unwrap(),
            "${COMPLETELY_UNDEFINED}"
        );

        // 注意：由于没有实际替换发生，控制标记不应因环境变量而设置
        // 但会因为其他原因（如没有 config_dir）被标记为 NO_DELETE
        // 这里我们主要验证 NO_DELETE 标记的逻辑
        // 由于没有 config_dir，文件会被标记为 NO_DELETE，但不是因为环境变量
        assert!(control.is_no_delete());
    }

    /// 布尔类型环境变量
    ///
    /// 验证：
    /// - 布尔类型的环境变量能正确解析和反序列化
    /// - TOML 解析器能将字符串 "true"/"false" 转换为布尔值
    #[tokio::test]
    async fn test_boolean_type_env_vars() {
        // 设置布尔类型的环境变量
        set_env_var("ENABLE_DHCP", "true");
        set_env_var("ENABLE_ENCRYPTION", "false");
        set_env_var("ENABLE_IPV6", "true");

        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "bool-test"
dhcp = ${ENABLE_DHCP}

[network_identity]
network_name = "test"
network_secret = "secret"

[flags]
enable_encryption = ${ENABLE_ENCRYPTION}
enable_ipv6 = ${ENABLE_IPV6}
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());
        let (config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证布尔值被正确解析
        assert!(config.get_dhcp(), "dhcp should be true");

        let flags = config.get_flags();
        assert!(
            !flags.enable_encryption,
            "enable_encryption should be false"
        );
        assert!(flags.enable_ipv6, "enable_ipv6 should be true");

        // 验证使用环境变量的配置被标记为只读
        assert!(control.is_read_only());
        assert!(control.is_no_delete());

        // 清理
        remove_env_var("ENABLE_DHCP");
        remove_env_var("ENABLE_ENCRYPTION");
        remove_env_var("ENABLE_IPV6");
    }

    /// 数字类型环境变量
    ///
    /// 验证：
    /// - 数字类型（整数、端口号）的环境变量能正确解析和反序列化
    /// - TOML 解析器能将字符串 "1380" 转换为整数
    #[tokio::test]
    async fn test_numeric_type_env_vars() {
        // 设置数字类型的环境变量
        set_env_var("MTU_VALUE", "1400");
        set_env_var("THREAD_COUNT", "4");

        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "numeric-test"

[network_identity]
network_name = "test"
network_secret = "secret"

[flags]
mtu = ${MTU_VALUE}
multi_thread_count = ${THREAD_COUNT}
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());
        let (config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证数字值被正确解析
        let flags = config.get_flags();
        assert_eq!(flags.mtu, 1400, "mtu should be 1400");
        assert_eq!(
            flags.multi_thread_count, 4,
            "multi_thread_count should be 4"
        );

        // 验证使用环境变量的配置被标记为只读
        assert!(control.is_read_only());
        assert!(control.is_no_delete());

        // 清理
        remove_env_var("MTU_VALUE");
        remove_env_var("THREAD_COUNT");
    }

    /// 混合类型环境变量
    ///
    /// 验证：
    /// - 字符串、布尔、数字类型的环境变量可以同时使用
    /// - 所有类型都能正确解析和反序列化
    /// - 模拟真实的复杂配置场景
    #[tokio::test]
    async fn test_mixed_type_env_vars() {
        // 设置不同类型的环境变量
        set_env_var("MIXED_SECRET", "mixed-secret-key");
        set_env_var("MIXED_NETWORK", "production");
        set_env_var("MIXED_DHCP", "true");
        set_env_var("MIXED_MTU", "1500");
        set_env_var("MIXED_ENCRYPTION", "false");
        set_env_var("MIXED_LISTEN_PORT", "12345");

        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "mixed-test"
ipv4 = "10.0.0.1"
dhcp = ${MIXED_DHCP}
listeners = ["tcp://0.0.0.0:${MIXED_LISTEN_PORT}"]

[network_identity]
network_name = "${MIXED_NETWORK}"
network_secret = "${MIXED_SECRET}"

[flags]
mtu = ${MIXED_MTU}
enable_encryption = ${MIXED_ENCRYPTION}
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());
        let (config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证字符串类型
        let identity = config.get_network_identity();
        assert_eq!(identity.network_name, "production");
        assert_eq!(
            identity.network_secret.as_ref().unwrap(),
            "mixed-secret-key"
        );

        // 验证布尔类型
        assert!(config.get_dhcp());

        let flags = config.get_flags();
        assert!(!flags.enable_encryption);

        // 验证数字类型
        assert_eq!(flags.mtu, 1500);

        // 验证 URL 中的端口号（数字）
        let listeners = config.get_listener_uris();
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].to_string(), "tcp://0.0.0.0:12345");

        // 验证配置被标记为只读
        assert!(control.is_read_only());
        assert!(control.is_no_delete());

        // 清理
        remove_env_var("MIXED_SECRET");
        remove_env_var("MIXED_NETWORK");
        remove_env_var("MIXED_DHCP");
        remove_env_var("MIXED_MTU");
        remove_env_var("MIXED_ENCRYPTION");
        remove_env_var("MIXED_LISTEN_PORT");
    }
}

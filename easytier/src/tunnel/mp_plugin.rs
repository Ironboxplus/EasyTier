//! Pluggable multipath-scheduler registry (MP_SQM_PLAN.md §5).
//!
//! Scheduling algorithms (min-rtt / redundant / round-robin / sqm-weighted / …)
//! are registered as named, self-describing plugins. Each plugin exposes a
//! `tunables()` schema so a GUI can auto-render its parameter panel (the
//! latency↔bandwidth slider is just one such `Tunable` on the sqm-weighted
//! plugin — never hard-coded), and `resolve()` maps user params to a concrete
//! [`MpAlgorithm`] + slider value that the mpquic tunnel consumes.
//!
//! Scope (MP_SQM_PLAN.md §5.4): this is the compile-time, trait-object plugin
//! registry — algorithms chosen at runtime by name/params. True dynamic
//! (`.so`/`.dll`) plugins with a stable ABI are a deferred follow-up. The
//! registry deliberately has no TQUIC dependency so config/GUI code can list
//! algorithms and render their tunables even in builds without the `mpquic`
//! feature; the mpquic tunnel maps [`MpAlgorithm`] onto TQUIC's own enum.

use serde_json::{Value, json};

/// A single self-describing tunable parameter of a scheduler plugin, so a GUI
/// can render the right control with validation and inline help.
#[derive(Clone, Debug, PartialEq)]
pub struct Tunable {
    pub key: String,
    pub label: String,
    pub kind: TunableKind,
    pub default: Value,
    pub help: String,
}

/// The control type + bounds for a [`Tunable`], driving GUI rendering.
#[derive(Clone, Debug, PartialEq)]
pub enum TunableKind {
    Slider { min: f64, max: f64, step: f64 },
    Toggle,
    Number { min: Option<f64>, max: Option<f64> },
    Enum { options: Vec<String> },
}

impl TunableKind {
    /// The GUI shape of a control (`MpTunableSchema`, `mp_plugins.json`):
    /// kind name, min, max, step and options.
    pub fn gui_parts(&self) -> (&'static str, Option<f64>, Option<f64>, Option<f64>, Vec<String>) {
        match self {
            TunableKind::Slider { min, max, step } => {
                ("slider", Some(*min), Some(*max), Some(*step), Vec::new())
            }
            TunableKind::Toggle => ("toggle", None, None, None, Vec::new()),
            TunableKind::Number { min, max } => ("number", *min, *max, None, Vec::new()),
            TunableKind::Enum { options } => ("enum", None, None, None, options.clone()),
        }
    }
}

/// The concrete multipath algorithm a plugin resolves to. Mirrors the TQUIC
/// fork's `MultipathAlgorithm`; the mpquic tunnel maps this onto it (kept here
/// TQUIC-free so config/GUI can use the registry without the mpquic feature).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MpAlgorithm {
    MinRtt,
    RoundRobin,
    Redundant,
    SqmWeighted,
}

/// Scheduler settings resolved from a plugin + its JSON params.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ResolvedMpConfig {
    pub algorithm: MpAlgorithm,
    /// Slider λ ∈ [0,1] (0 = lowest latency, 1 = max bandwidth). Meaningful for
    /// `sqm-weighted`; ignored by the fixed algorithms.
    pub lambda: f64,
}

/// A scheduler algorithm plugin: metadata + a param schema + resolution.
pub trait MpSchedulerPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    /// Parameter schema for GUI auto-rendering (empty for fixed algorithms).
    fn tunables(&self) -> Vec<Tunable>;
    /// Validate/normalize `params` and resolve to a concrete scheduler config.
    /// Must be total: out-of-range/missing params fall back to defaults.
    fn resolve(&self, params: &Value) -> ResolvedMpConfig;
}

/// Read a JSON number field, clamped to `[min, max]`, defaulting to `default`.
fn clamped_f64(params: &Value, key: &str, default: f64, min: f64, max: f64) -> f64 {
    params
        .get(key)
        .and_then(Value::as_f64)
        .unwrap_or(default)
        .clamp(min, max)
}

macro_rules! fixed_plugin {
    ($ty:ident, $name:literal, $desc:literal, $algo:expr) => {
        pub struct $ty;
        impl MpSchedulerPlugin for $ty {
            fn name(&self) -> &str {
                $name
            }
            fn description(&self) -> &str {
                $desc
            }
            fn tunables(&self) -> Vec<Tunable> {
                Vec::new()
            }
            fn resolve(&self, _params: &Value) -> ResolvedMpConfig {
                ResolvedMpConfig {
                    algorithm: $algo,
                    lambda: 0.5,
                }
            }
        }
    };
}

fixed_plugin!(
    MinRttPlugin,
    "min-rtt",
    "Send on the lowest-RTT path (stock, proven).",
    MpAlgorithm::MinRtt
);
fixed_plugin!(
    RoundRobinPlugin,
    "round-robin",
    "Rotate packets evenly across all paths.",
    MpAlgorithm::RoundRobin
);
fixed_plugin!(
    RedundantPlugin,
    "redundant",
    "Duplicate packets on every path (lowest loss/latency, no aggregation).",
    MpAlgorithm::Redundant
);

/// SQM-driven weighted scheduler with the latency↔bandwidth slider
/// (MP_SQM_PLAN.md §9): `latency_bandwidth` λ maps to weight exponent
/// `k = (1-λ)·K_MAX`.
pub struct SqmWeightedPlugin;

/// The tunable key for the latency↔bandwidth slider — shared with the routing
/// layer's `ET_MP_LAMBDA`.
pub const LATENCY_BANDWIDTH_KEY: &str = "latency_bandwidth";

impl MpSchedulerPlugin for SqmWeightedPlugin {
    fn name(&self) -> &str {
        "sqm-weighted"
    }
    fn description(&self) -> &str {
        "Per-link SQM residual-bandwidth weighted split with a latency↔bandwidth slider."
    }
    fn tunables(&self) -> Vec<Tunable> {
        vec![Tunable {
            key: LATENCY_BANDWIDTH_KEY.to_string(),
            label: "Latency ↔ Bandwidth".to_string(),
            kind: TunableKind::Slider {
                min: 0.0,
                max: 1.0,
                step: 0.01,
            },
            default: json!(0.5),
            help: "0 = concentrate on the lowest-latency path; 1 = spread for maximum aggregate bandwidth.".to_string(),
        }]
    }
    fn resolve(&self, params: &Value) -> ResolvedMpConfig {
        ResolvedMpConfig {
            algorithm: MpAlgorithm::SqmWeighted,
            lambda: clamped_f64(params, LATENCY_BANDWIDTH_KEY, 0.5, 0.0, 1.0),
        }
    }
}

/// Registry of scheduler plugins, chosen at runtime by name.
pub struct MpSchedulerRegistry {
    plugins: Vec<Box<dyn MpSchedulerPlugin>>,
}

impl Default for MpSchedulerRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}

impl MpSchedulerRegistry {
    /// Empty registry (for tests / fully custom setups).
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Registry pre-populated with the built-in algorithms.
    pub fn with_builtins() -> Self {
        let mut r = Self::new();
        r.register(Box::new(MinRttPlugin));
        r.register(Box::new(RoundRobinPlugin));
        r.register(Box::new(RedundantPlugin));
        r.register(Box::new(SqmWeightedPlugin));
        r
    }

    /// Register a plugin. A later registration with the same name replaces the
    /// earlier one, so callers can override a built-in.
    pub fn register(&mut self, plugin: Box<dyn MpSchedulerPlugin>) {
        let name = plugin.name().to_string();
        self.plugins.retain(|p| p.name() != name);
        self.plugins.push(plugin);
    }

    /// All registered plugins (for a GUI dropdown).
    pub fn list(&self) -> &[Box<dyn MpSchedulerPlugin>] {
        &self.plugins
    }

    pub fn get(&self, name: &str) -> Option<&dyn MpSchedulerPlugin> {
        self.plugins
            .iter()
            .find(|p| p.name() == name)
            .map(|p| p.as_ref())
    }

    /// Resolve a scheduler `name` + `params` to a concrete config, or `None` if
    /// the name is not registered.
    pub fn resolve(&self, name: &str, params: &Value) -> Option<ResolvedMpConfig> {
        self.get(name).map(|p| p.resolve(params))
    }
}

/// Congestion-control settings resolved from a plugin + its JSON params
/// (MP_SQM_PLAN.md S2.4). Unlike [`ResolvedMpConfig`] this is not `Copy`:
/// `Brutal` carries the params `set_brutal_bps`/`set_brutal_disable_loss_
/// compensation` need at TQUIC `Config` build time.
#[derive(Clone, Debug, PartialEq)]
pub enum ResolvedCcConfig {
    /// tquic-native default parameters for the algorithm; no extra `Tunable`s.
    Native,
    Brutal(BrutalTunables),
}

/// Brutal's three `Tunable`s. Keys/units/defaults are fixed by MP_SQM_PLAN.md
/// §9 and already shipped in the committed `frontend-lib/src/generated/
/// mp_plugins.json` -- the GUI sends exactly `up_mbps`/`down_mbps`/
/// `disable_loss_compensation`, so the backend must accept exactly those,
/// not a bits/sec-named pair invented independently of the shipped contract.
///
/// Both rates are Mbit/s (fractional allowed, e.g. `8.5`), matching the GUI's
/// "number" `Tunable` kind and its "Upload (Mbps)"/"Download (Mbps)" labels
/// -- NOT bits/sec and NOT TQUIC's internal bytes/sec (`RecoveryConfig::
/// brutal_bps`). Callers that need bits/sec (e.g. `RoutePeerInfo.mp_max_rx_bps`,
/// `MpPeerStatus.brutal_tx_bps`) or TQUIC's bytes/sec use the conversion
/// helpers below rather than assuming a unit.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BrutalTunables {
    /// Required local send rate, Mbit/s. `up_mbps` per §9's shipped schema.
    pub up_mbps: f64,
    /// Announced receive-rate ceiling, Mbit/s; `0.0` (the schema default)
    /// means "don't announce a cap", not "announce a zero rate". `down_mbps`
    /// per §9's shipped schema.
    pub down_mbps: f64,
    pub disable_loss_compensation: bool,
}

pub const BRUTAL_UP_MBPS_KEY: &str = "up_mbps";
pub const BRUTAL_DOWN_MBPS_KEY: &str = "down_mbps";
pub const BRUTAL_DISABLE_LOSS_COMPENSATION_KEY: &str = "disable_loss_compensation";
/// Send rate when `up_mbps` is not configured, Mbit/s.
pub const BRUTAL_DEFAULT_UP_MBPS: f64 = 50.0;

/// Mbit/s -> bits/sec, for `RoutePeerInfo.mp_max_rx_bps` and `MpPeerStatus.
/// brutal_tx_bps`/`peer_advertised_rx_bps` (all named/documented as bits/sec,
/// same convention as `WireBitrate`/`capacity_bps` elsewhere in this crate).
pub fn brutal_mbps_to_bits_per_sec(mbps: f64) -> u64 {
    (mbps * 1_000_000.0).round() as u64
}

/// Mbit/s -> bytes/sec, for TQUIC's `RecoveryConfig::brutal_bps`/`BrutalConfig
/// ::bps` (documented in `vendor/tquic/src/congestion_control/brutal.rs` as
/// bytes/sec despite the ET-wide `_bps` convention elsewhere being bits/sec --
/// this is the one deliberate, TQUIC-internal exception; get it wrong and a
/// configured "20 Mbit/s" silently paces at 160 Mbit/s instead).
pub fn brutal_mbps_to_bytes_per_sec(mbps: f64) -> u64 {
    (mbps * 1_000_000.0 / 8.0).round() as u64
}

/// A congestion-control algorithm plugin: metadata + a param schema +
/// resolution, mirroring [`MpSchedulerPlugin`] so both share one registry
/// (MP_SQM_PLAN.md S2.4/S2.7). Unlike scheduler plugins this is not required
/// to be total: brutal without a configured tx is a hard configuration error
/// ("tx 未配置时拒绝选择 brutal（配置校验报错，不静默回落）"), surfaced as
/// `Err` rather than silently defaulting to some made-up rate.
pub trait MpCcPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn tunables(&self) -> Vec<Tunable>;
    fn resolve(&self, params: &Value) -> Result<ResolvedCcConfig, String>;
}

macro_rules! native_cc_plugin {
    ($ty:ident, $name:literal, $desc:literal) => {
        pub struct $ty;
        impl MpCcPlugin for $ty {
            fn name(&self) -> &str {
                $name
            }
            fn description(&self) -> &str {
                $desc
            }
            fn tunables(&self) -> Vec<Tunable> {
                Vec::new()
            }
            fn resolve(&self, _params: &Value) -> Result<ResolvedCcConfig, String> {
                Ok(ResolvedCcConfig::Native)
            }
        }
    };
}

// Descriptions match the already-committed `frontend-lib/src/generated/
// mp_plugins.json` (MP_SQM_PLAN.md §9) verbatim.
native_cc_plugin!(
    EngineDefaultCcPlugin,
    "engine-default",
    "TQUIC default congestion control (BBR)."
);
native_cc_plugin!(
    BbrCcPlugin,
    "bbr",
    "BBR v1: model-based, keeps queues short on stable links."
);
native_cc_plugin!(
    CubicCcPlugin,
    "cubic",
    "CUBIC: loss-based, the conventional TCP default."
);
native_cc_plugin!(
    Bbr3CcPlugin,
    "bbr3",
    "BBR v3: BBR with loss/ECN-aware bandwidth probing."
);
native_cc_plugin!(
    CopaCcPlugin,
    "copa",
    "COPA: delay-based, targets low queueing delay."
);

/// Fixed-rate, externally driven congestion control (MP_SQM_PLAN.md S2.4,
/// ported from Hysteria). Deliberately the only CC plugin with `Tunable`s
/// that can fail to resolve.
pub struct BrutalCcPlugin;

impl MpCcPlugin for BrutalCcPlugin {
    fn name(&self) -> &str {
        "brutal"
    }
    fn description(&self) -> &str {
        "Brutal (Hysteria): sends at the rate Autorate allocates from the egress estimate, starting from the upload rate, under the peer's download, and compensates for loss."
    }
    fn tunables(&self) -> Vec<Tunable> {
        vec![
            Tunable {
                key: BRUTAL_UP_MBPS_KEY.to_string(),
                label: "Upload (Mbps)".to_string(),
                kind: TunableKind::Number {
                    min: Some(0.1),
                    max: None,
                },
                default: json!(BRUTAL_DEFAULT_UP_MBPS),
                help: "Where the send rate starts until Autorate measures the link. Default 50."
                    .to_string(),
            },
            Tunable {
                key: BRUTAL_DOWN_MBPS_KEY.to_string(),
                label: "Download (Mbps)".to_string(),
                kind: TunableKind::Number {
                    min: Some(0.0),
                    max: None,
                },
                default: json!(0),
                help: "Receive rate advertised to peers (0 = no limit advertised).".to_string(),
            },
            Tunable {
                key: BRUTAL_DISABLE_LOSS_COMPENSATION_KEY.to_string(),
                label: "Disable loss compensation".to_string(),
                kind: TunableKind::Toggle,
                default: json!(false),
                help: "When on, the send rate is not raised to make up for lost packets."
                    .to_string(),
            },
        ]
    }
    fn resolve(&self, params: &Value) -> Result<ResolvedCcConfig, String> {
        // Omitted -> the default rate; an explicit bad value is still an error.
        let up_mbps = match params.get(BRUTAL_UP_MBPS_KEY) {
            None | Some(Value::Null) => BRUTAL_DEFAULT_UP_MBPS,
            Some(value) => value
                .as_f64()
                .filter(|value| value.is_finite() && *value > 0.0)
                .ok_or_else(|| {
                    format!(
                        "mp.congestion_control=brutal: {BRUTAL_UP_MBPS_KEY:?} must be a positive number (Mbit/s)"
                    )
                })?,
        };
        let down_mbps = params
            .get(BRUTAL_DOWN_MBPS_KEY)
            .and_then(Value::as_f64)
            .filter(|value| value.is_finite() && *value >= 0.0)
            .unwrap_or(0.0);
        let disable_loss_compensation = params
            .get(BRUTAL_DISABLE_LOSS_COMPENSATION_KEY)
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Ok(ResolvedCcConfig::Brutal(BrutalTunables {
            up_mbps,
            down_mbps,
            disable_loss_compensation,
        }))
    }
}

/// Registry of congestion-control plugins, chosen at runtime by name.
/// Deliberately excludes `dummy`: like `CongestionControlProfile::
/// DummyExperimental`, it is test/experimental-only and never offered through
/// normal configuration or GUI.
pub struct MpCcRegistry {
    plugins: Vec<Box<dyn MpCcPlugin>>,
}

impl Default for MpCcRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}

impl MpCcRegistry {
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    pub fn with_builtins() -> Self {
        let mut r = Self::new();
        r.register(Box::new(EngineDefaultCcPlugin));
        r.register(Box::new(BbrCcPlugin));
        r.register(Box::new(Bbr3CcPlugin));
        r.register(Box::new(CubicCcPlugin));
        r.register(Box::new(CopaCcPlugin));
        r.register(Box::new(BrutalCcPlugin));
        r
    }

    pub fn register(&mut self, plugin: Box<dyn MpCcPlugin>) {
        let name = plugin.name().to_string();
        self.plugins.retain(|p| p.name() != name);
        self.plugins.push(plugin);
    }

    pub fn list(&self) -> &[Box<dyn MpCcPlugin>] {
        &self.plugins
    }

    pub fn get(&self, name: &str) -> Option<&dyn MpCcPlugin> {
        self.plugins
            .iter()
            .find(|p| p.name() == name)
            .map(|p| p.as_ref())
    }

    pub fn resolve(&self, name: &str, params: &Value) -> Option<Result<ResolvedCcConfig, String>> {
        self.get(name).map(|p| p.resolve(params))
    }
}

/// Discriminates a unified schema entry as coming from the scheduler or the
/// congestion-control side of the shared registry (MP_SQM_PLAN.md S2.4/S2.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MpPluginKind {
    Scheduler,
    CongestionControl,
}

impl MpPluginKind {
    pub fn as_str(self) -> &'static str {
        match self {
            MpPluginKind::Scheduler => "scheduler",
            MpPluginKind::CongestionControl => "congestion_control",
        }
    }
}

/// One row of the GUI-facing plugin schema (MP_SQM_PLAN.md S2.7's
/// `mp_plugin_schema_snapshot`): enough to auto-render a parameter panel for
/// either a scheduler or a CC algorithm without hand-written per-plugin GUI
/// code.
#[derive(Clone, Debug, PartialEq)]
pub struct MpPluginSchemaEntry {
    pub kind: MpPluginKind,
    pub name: String,
    pub description: String,
    pub tunables: Vec<Tunable>,
}

/// The combined scheduler + congestion-control plugin registry
/// (MP_SQM_PLAN.md S2.4: "CC 与调度器进同一注册表（加 kind 区分）"). Existing
/// callers that only need one side keep using `MpSchedulerRegistry`/
/// `MpCcRegistry` directly; this is the unified surface a config validator or
/// GUI schema export wants.
pub struct MpPluginRegistry {
    pub schedulers: MpSchedulerRegistry,
    pub congestion_controls: MpCcRegistry,
}

impl Default for MpPluginRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}

impl MpPluginRegistry {
    pub fn with_builtins() -> Self {
        Self {
            schedulers: MpSchedulerRegistry::with_builtins(),
            congestion_controls: MpCcRegistry::with_builtins(),
        }
    }

    /// Unified, kind-discriminated schema for a GUI to render both plugin
    /// families uniformly. Scheduler entries are listed first, then CC.
    pub fn schema(&self) -> Vec<MpPluginSchemaEntry> {
        let mut entries: Vec<MpPluginSchemaEntry> = self
            .schedulers
            .list()
            .iter()
            .map(|p| MpPluginSchemaEntry {
                kind: MpPluginKind::Scheduler,
                name: p.name().to_string(),
                description: p.description().to_string(),
                tunables: p.tunables(),
            })
            .collect();
        entries.extend(self.congestion_controls.list().iter().map(|p| MpPluginSchemaEntry {
            kind: MpPluginKind::CongestionControl,
            name: p.name().to_string(),
            description: p.description().to_string(),
            tunables: p.tunables(),
        }));
        entries
    }

    /// The GUI snapshot `frontend-lib/src/generated/mp_plugins.json`
    /// (MP_SQM_PLAN.md S2.7): the schema in the proto JSON field names of
    /// `MpSchedulerPluginSchema`, unset optionals omitted.
    pub fn schema_json(&self) -> Value {
        Value::Array(
            self.schema()
                .into_iter()
                .map(|entry| {
                    let tunables = entry
                        .tunables
                        .iter()
                        .map(|tunable| {
                            let (kind, min, max, step, options) = tunable.kind.gui_parts();
                            let mut row = serde_json::Map::new();
                            row.insert("key".into(), tunable.key.clone().into());
                            row.insert("label".into(), tunable.label.clone().into());
                            row.insert("kind".into(), kind.into());
                            for (name, value) in [("min", min), ("max", max), ("step", step)] {
                                if let Some(value) = value {
                                    row.insert(name.into(), value.into());
                                }
                            }
                            row.insert("options".into(), options.into());
                            row.insert(
                                "default_json".into(),
                                serde_json::to_string(&tunable.default)
                                    .unwrap_or_else(|_| "null".into())
                                    .into(),
                            );
                            row.insert("help".into(), tunable.help.clone().into());
                            Value::Object(row)
                        })
                        .collect::<Vec<_>>();
                    serde_json::json!({
                        "name": entry.name,
                        "kind": entry.kind.as_str(),
                        "description": entry.description,
                        "tunables": tunables,
                    })
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Numbers compared as f64 (the committed file writes `0` for `0.0`).
    fn normalized(value: Value) -> Value {
        match value {
            Value::Number(n) => serde_json::json!(n.as_f64().unwrap()),
            Value::Array(items) => Value::Array(items.into_iter().map(normalized).collect()),
            Value::Object(map) => Value::Object(
                map.into_iter().map(|(k, v)| (k, normalized(v))).collect(),
            ),
            other => other,
        }
    }

    /// MP_SQM_PLAN.md S2.7: the GUI renders exactly the registry. Set
    /// `ET_UPDATE_SNAPSHOTS=1` to rewrite the GUI copy.
    #[test]
    fn mp_plugin_schema_snapshot() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../easytier-web/frontend-lib/src/generated/mp_plugins.json");
        let expected = MpPluginRegistry::with_builtins().schema_json();
        if std::env::var_os("ET_UPDATE_SNAPSHOTS").is_some() {
            std::fs::write(&path, serde_json::to_string_pretty(&expected).unwrap() + "\n").unwrap();
        }
        let actual: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            normalized(actual),
            normalized(expected),
            "{} is stale; rerun with ET_UPDATE_SNAPSHOTS=1",
            path.display()
        );
    }

    #[test]
    fn a_registered_plugin_shows_up_in_the_schema_without_gui_code() {
        struct Probe;
        impl MpCcPlugin for Probe {
            fn name(&self) -> &str {
                "probe"
            }
            fn description(&self) -> &str {
                "test"
            }
            fn tunables(&self) -> Vec<Tunable> {
                vec![Tunable {
                    key: "mode".into(),
                    label: "Mode".into(),
                    kind: TunableKind::Enum {
                        options: vec!["a".into(), "b".into()],
                    },
                    default: Value::from("a"),
                    help: String::new(),
                }]
            }
            fn resolve(&self, _params: &Value) -> Result<ResolvedCcConfig, String> {
                Ok(ResolvedCcConfig::Native)
            }
        }
        let mut registry = MpPluginRegistry::with_builtins();
        registry.congestion_controls.register(Box::new(Probe));
        let schema = registry.schema_json();
        let probe = schema
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "probe")
            .unwrap();
        assert_eq!(probe["kind"], "congestion_control");
        assert_eq!(probe["tunables"][0]["kind"], "enum");
        assert_eq!(probe["tunables"][0]["options"], serde_json::json!(["a", "b"]));
        assert_eq!(probe["tunables"][0]["default_json"], "\"a\"");
    }

    #[test]
    fn builtins_are_registered() {
        let r = MpSchedulerRegistry::with_builtins();
        assert_eq!(r.list().len(), 4);
        for name in ["min-rtt", "round-robin", "redundant", "sqm-weighted"] {
            assert!(r.get(name).is_some(), "missing built-in {name}");
        }
        assert!(r.get("nonexistent").is_none());
    }

    #[test]
    fn sqm_weighted_exposes_the_slider_tunable() {
        let r = MpSchedulerRegistry::with_builtins();
        let t = r.get("sqm-weighted").unwrap().tunables();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].key, LATENCY_BANDWIDTH_KEY);
        assert_eq!(
            t[0].kind,
            TunableKind::Slider {
                min: 0.0,
                max: 1.0,
                step: 0.01
            }
        );
        assert_eq!(t[0].default, json!(0.5));
    }

    #[test]
    fn fixed_algorithms_have_no_tunables() {
        let r = MpSchedulerRegistry::with_builtins();
        for name in ["min-rtt", "round-robin", "redundant"] {
            assert!(r.get(name).unwrap().tunables().is_empty(), "{name}");
        }
    }

    #[test]
    fn resolve_maps_names_to_algorithms() {
        let r = MpSchedulerRegistry::with_builtins();
        assert_eq!(
            r.resolve("min-rtt", &json!({})).unwrap().algorithm,
            MpAlgorithm::MinRtt
        );
        assert_eq!(
            r.resolve("redundant", &json!({})).unwrap().algorithm,
            MpAlgorithm::Redundant
        );
        assert_eq!(
            r.resolve("round-robin", &json!({})).unwrap().algorithm,
            MpAlgorithm::RoundRobin
        );
        assert_eq!(
            r.resolve("sqm-weighted", &json!({})).unwrap().algorithm,
            MpAlgorithm::SqmWeighted
        );
        assert!(r.resolve("bogus", &json!({})).is_none());
    }

    #[test]
    fn slider_param_is_read_and_clamped() {
        let r = MpSchedulerRegistry::with_builtins();
        let got = |v: Value| r.resolve("sqm-weighted", &v).unwrap().lambda;
        assert_eq!(got(json!({ "latency_bandwidth": 0.8 })), 0.8);
        assert_eq!(got(json!({})), 0.5, "missing -> default");
        assert_eq!(got(json!({ "latency_bandwidth": 5.0 })), 1.0, "clamp high");
        assert_eq!(got(json!({ "latency_bandwidth": -1.0 })), 0.0, "clamp low");
        assert_eq!(
            got(json!({ "latency_bandwidth": "nope" })),
            0.5,
            "bad type -> default"
        );
    }

    #[test]
    fn custom_plugin_can_be_registered_and_override_builtin() {
        struct MyPlugin;
        impl MpSchedulerPlugin for MyPlugin {
            fn name(&self) -> &str {
                "sqm-weighted"
            }
            fn description(&self) -> &str {
                "override"
            }
            fn tunables(&self) -> Vec<Tunable> {
                Vec::new()
            }
            fn resolve(&self, _p: &Value) -> ResolvedMpConfig {
                ResolvedMpConfig {
                    algorithm: MpAlgorithm::MinRtt,
                    lambda: 0.0,
                }
            }
        }
        let mut r = MpSchedulerRegistry::with_builtins();
        assert_eq!(r.list().len(), 4);
        r.register(Box::new(MyPlugin));
        assert_eq!(r.list().len(), 4, "same name replaces, not appends");
        assert_eq!(r.get("sqm-weighted").unwrap().description(), "override");
        assert!(r.get("sqm-weighted").unwrap().tunables().is_empty());
    }

    #[test]
    fn cc_registry_has_the_five_native_profiles_and_brutal() {
        let r = MpCcRegistry::with_builtins();
        assert_eq!(r.list().len(), 6);
        for name in ["engine-default", "bbr", "cubic", "bbr3", "copa", "brutal"] {
            assert!(r.get(name).is_some(), "missing CC plugin {name}");
        }
        assert!(r.get("dummy").is_none(), "dummy must stay unregistered");
    }

    #[test]
    fn native_cc_profiles_resolve_and_have_no_tunables() {
        let r = MpCcRegistry::with_builtins();
        for name in ["engine-default", "bbr", "cubic", "bbr3", "copa"] {
            assert!(r.get(name).unwrap().tunables().is_empty(), "{name}");
            assert_eq!(
                r.resolve(name, &json!({})).unwrap().unwrap(),
                ResolvedCcConfig::Native,
                "{name}"
            );
        }
    }

    #[test]
    fn brutal_defaults_an_omitted_up_mbps_and_rejects_a_bad_one() {
        let r = MpCcRegistry::with_builtins();
        for omitted in [json!({}), json!({ "up_mbps": null })] {
            assert_eq!(
                r.resolve("brutal", &omitted).unwrap().unwrap(),
                ResolvedCcConfig::Brutal(BrutalTunables {
                    up_mbps: 50.0,
                    down_mbps: 0.0,
                    disable_loss_compensation: false,
                }),
                "an omitted up_mbps sends at the 50 Mbit/s default"
            );
        }
        assert!(r.resolve("brutal", &json!({ "up_mbps": 0 })).unwrap().is_err());
        assert!(r.resolve("brutal", &json!({ "up_mbps": "fast" })).unwrap().is_err());
        assert!(
            r.resolve("brutal", &json!({ "up_mbps": -1 }))
                .unwrap()
                .is_err()
        );
        // §9 requires fractional Mbit/s values to be accepted (not just whole
        // integers, unlike the old bits/sec-named key this replaced).
        assert_eq!(
            r.resolve("brutal", &json!({ "up_mbps": 8.5 }))
                .unwrap()
                .unwrap(),
            ResolvedCcConfig::Brutal(BrutalTunables {
                up_mbps: 8.5,
                down_mbps: 0.0,
                disable_loss_compensation: false,
            })
        );
    }

    #[test]
    fn brutal_reads_optional_down_mbps_and_disable_loss_compensation() {
        let r = MpCcRegistry::with_builtins();
        assert_eq!(
            r.resolve(
                "brutal",
                &json!({ "up_mbps": 5.0, "down_mbps": 8.0, "disable_loss_compensation": true })
            )
            .unwrap()
            .unwrap(),
            ResolvedCcConfig::Brutal(BrutalTunables {
                up_mbps: 5.0,
                down_mbps: 8.0,
                disable_loss_compensation: true,
            })
        );
        // down_mbps == 0 (the schema default) means "don't announce", same as
        // an absent key -- not "announce a zero rate".
        assert_eq!(
            r.resolve("brutal", &json!({ "up_mbps": 5.0, "down_mbps": 0 }))
                .unwrap()
                .unwrap(),
            ResolvedCcConfig::Brutal(BrutalTunables {
                up_mbps: 5.0,
                down_mbps: 0.0,
                disable_loss_compensation: false,
            })
        );
        // A negative down_mbps is not a valid announcement; fall back to the
        // "don't announce" default rather than propagating a negative rate.
        assert_eq!(
            r.resolve("brutal", &json!({ "up_mbps": 5.0, "down_mbps": -1 }))
                .unwrap()
                .unwrap(),
            ResolvedCcConfig::Brutal(BrutalTunables {
                up_mbps: 5.0,
                down_mbps: 0.0,
                disable_loss_compensation: false,
            })
        );
    }

    #[test]
    fn brutal_exposes_three_tunables_with_a_50_mbps_up_default() {
        let r = MpCcRegistry::with_builtins();
        let t = r.get("brutal").unwrap().tunables();
        assert_eq!(t.len(), 3);
        let keys: Vec<&str> = t.iter().map(|t| t.key.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                BRUTAL_UP_MBPS_KEY,
                BRUTAL_DOWN_MBPS_KEY,
                BRUTAL_DISABLE_LOSS_COMPENSATION_KEY
            ]
        );
        assert_eq!(t[0].default, json!(50.0), "up_mbps defaults to 50 Mbit/s");
        assert_eq!(t[1].default, json!(0), "down_mbps defaults to 0 (no announcement)");
        assert_eq!(t[2].kind, TunableKind::Toggle);
        assert_eq!(t[2].default, json!(false));
    }

    #[test]
    fn brutal_mbps_conversion_helpers_use_the_documented_units() {
        // 20 Mbit/s -> 20_000_000 bits/sec (RoutePeerInfo.mp_max_rx_bps /
        // MpPeerStatus.brutal_tx_bps convention).
        assert_eq!(brutal_mbps_to_bits_per_sec(20.0), 20_000_000);
        // 20 Mbit/s -> 2_500_000 bytes/sec (TQUIC's RecoveryConfig::brutal_bps
        // convention) -- the exact review finding this guards: getting this
        // backwards (treating Mbit/s numerically as bytes/sec) would pace at
        // 8x the configured rate.
        assert_eq!(brutal_mbps_to_bytes_per_sec(20.0), 2_500_000);
        // Fractional Mbit/s must round rather than truncate away real signal.
        assert_eq!(brutal_mbps_to_bits_per_sec(8.5), 8_500_000);
        assert_eq!(brutal_mbps_to_bytes_per_sec(8.5), 1_062_500);
    }

    #[test]
    fn plugin_registry_schema_lists_schedulers_then_cc_kind_discriminated() {
        let registry = MpPluginRegistry::with_builtins();
        let schema = registry.schema();
        assert_eq!(schema.len(), 4 + 6);
        assert!(schema[..4]
            .iter()
            .all(|entry| entry.kind == MpPluginKind::Scheduler));
        assert!(schema[4..]
            .iter()
            .all(|entry| entry.kind == MpPluginKind::CongestionControl));
        let brutal = schema
            .iter()
            .find(|entry| entry.kind == MpPluginKind::CongestionControl && entry.name == "brutal")
            .expect("brutal must appear in the unified schema");
        assert_eq!(brutal.tunables.len(), 3);
    }
}

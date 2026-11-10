//! Which established paths carry data, and what rate each one is given.
//!
//! Every mature multipath implementation (Linux MPTCP, picoquic, noq, iroh)
//! has no bandwidth optimizer: the path manager only limits how many paths are
//! in use and marks the others as backup, and the scheduler plus each path's
//! own congestion control decide who sends how much. This module is that
//! small path manager. It replaced a Top-K utility search with a max-flow
//! allocator (MP_FIX_PHASES.md phase 4).
//!
//! [`select_paths`] is a translation of iroh's
//! `BiasedRttPathSelector::select` (`iroh/src/socket/biased_rtt_path_selector.rs`
//! lines 136-185: sort by `(tier, biased RTT)`, switch tier at once, switch
//! inside a tier only for a clearly better RTT). What ET changes is listed at
//! the items below, each marked "ET:". [`split_budgets`] has no reference
//! (Hysteria's Brutal is single-path, MPTCP has no Brutal) and is ET's own.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};

use crate::{
    connector::mp_path::{CarrierKind, ResourceGroupId},
    proto::common::{MpPathPolicy, MpSelectionConfig},
    tunnel::mpquic::PathKey,
};

/// iroh `IPV6_RTT_ADVANTAGE` (`biased_rtt_path_selector.rs:19`): an IPv6 path
/// ranks as if it were this much faster.
pub(crate) const IPV6_RTT_ADVANTAGE_MICROS: i64 = 3_000;

/// iroh `RTT_SWITCHING_MIN` (`biased_rtt_path_selector.rs:23`): inside a tier
/// a challenger must be at least this much better than the path it replaces.
pub(crate) const RTT_SWITCHING_MIN_MICROS: u64 = 5_000;

/// ET: iroh's 5 ms is a fixed number, too touchy on a link whose round trip is
/// hundreds of milliseconds (cellular, a relay). The switch threshold is also
/// this share of the replaced path's RTT, whichever is larger. The 10% is
/// ET's own choice; no reference has it.
pub(crate) const RTT_SWITCHING_FRACTION_PERCENT: u64 = 10;

/// What a path with no RTT sample yet counts as. noq reports the initial RTT
/// until the first sample (`RttEstimator::get`, `noq-proto/src/connection/paths.rs`
/// "smoothed.unwrap_or(latest)"), so iroh ranks such a path at that value
/// too; RFC 9002 Section 6.2.2 recommends 333 ms for it.
pub(crate) const UNMEASURED_RTT_MICROS: u64 = 333_000;

/// iroh `TransportType` (`biased_rtt_path_selector.rs:30-36`): primary paths
/// are used whenever any is available, backup paths only when none is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PathTier {
    Primary,
    Backup,
}

impl PathTier {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Backup => "backup",
        }
    }
}

/// The wire name of a carrier kind (`MpConfig.providers`).
pub(crate) const fn carrier_kind_name(kind: CarrierKind) -> &'static str {
    match kind {
        CarrierKind::UdpDirect => "udp-direct",
        CarrierKind::UdpPunch => "udp-punch",
        CarrierKind::FakeTcpPunch => "faketcp-punch",
        CarrierKind::RelayNextHop => "relay-next-hop",
        CarrierKind::Manual => "manual",
    }
}

/// One row of the selection table, parsed from `MpSelectionKindRule`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KindRule {
    carrier_kind: String,
    /// `None` = either family.
    ipv6: Option<bool>,
    tier: PathTier,
    bias_micros: i64,
}

/// The selector's tunables (`MpConfig.selection`): the constants above are
/// the defaults, so a config without the section selects exactly as before.
/// Like iroh's selector, one set per instance, not per peer.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SelectionParams {
    /// Empty = the built-in table of [`transport_bias`].
    kind_rules: Vec<KindRule>,
    pub(crate) switch_min_micros: u64,
    pub(crate) switch_percent: u64,
    /// Loss above which a path gives way to a cleaner one, 0.0..=1.0.
    pub(crate) lossy_loss: f64,
    pub(crate) unmeasured_rtt_micros: u64,
}

impl Default for SelectionParams {
    fn default() -> Self {
        Self {
            kind_rules: Vec::new(),
            switch_min_micros: RTT_SWITCHING_MIN_MICROS,
            switch_percent: RTT_SWITCHING_FRACTION_PERCENT,
            lossy_loss: crate::connector::mp_path::LOSSY_PATH_LOSS,
            unmeasured_rtt_micros: UNMEASURED_RTT_MICROS,
        }
    }
}

impl SelectionParams {
    /// A zero field or an absent section is the default. The config is
    /// validated on the way in (`validate_mp_selection`); a rule that would
    /// not parse is skipped rather than trusted.
    pub(crate) fn from_config(config: Option<&MpSelectionConfig>) -> Self {
        let mut params = Self::default();
        let Some(config) = config else {
            return params;
        };
        params.kind_rules = config
            .kind_rules
            .iter()
            .filter_map(|rule| {
                Some(KindRule {
                    carrier_kind: rule.carrier_kind.clone(),
                    ipv6: match rule.ip_family.as_str() {
                        "" => None,
                        "v4" => Some(false),
                        "v6" => Some(true),
                        _ => return None,
                    },
                    tier: match rule.tier.as_str() {
                        "primary" => PathTier::Primary,
                        "backup" => PathTier::Backup,
                        _ => return None,
                    },
                    bias_micros: i64::from(rule.rtt_bias_ms) * 1_000,
                })
            })
            .collect();
        if config.switch_min_ms > 0 {
            params.switch_min_micros = u64::from(config.switch_min_ms) * 1_000;
        }
        if config.switch_percent > 0 {
            params.switch_percent = u64::from(config.switch_percent);
        }
        if config.lossy_percent > 0 {
            params.lossy_loss = f64::from(config.lossy_percent) / 100.0;
        }
        if config.unmeasured_rtt_ms > 0 {
            params.unmeasured_rtt_micros = u64::from(config.unmeasured_rtt_ms) * 1_000;
        }
        params
    }

    /// The first rule naming this kind and family, then the first naming the
    /// kind for either family.
    fn rule_for(&self, carrier_kind: CarrierKind, remote: SocketAddr) -> Option<&KindRule> {
        let name = carrier_kind_name(carrier_kind);
        self.kind_rules
            .iter()
            .find(|rule| rule.carrier_kind == name && rule.ipv6 == Some(remote.is_ipv6()))
            .or_else(|| {
                self.kind_rules
                    .iter()
                    .find(|rule| rule.carrier_kind == name && rule.ipv6.is_none())
            })
    }
}

/// One established path as the selector sees it.
#[derive(Debug, Clone)]
pub(crate) struct SelectorPath {
    pub(crate) key: PathKey,
    pub(crate) tier: PathTier,
    /// ET: the path's propagation RTT (TQUIC's windowed minimum, 300 s), never
    /// the smoothed RTT. iroh sorts by `PathStats::rtt` (`select`, line 150),
    /// which in noq is the smoothed RTT (checked in the noq clone:
    /// `noq-proto/src/connection/mod.rs:2695` `stats.rtt = path.data.rtt.get()`,
    /// and `paths.rs:801-803` `RttEstimator::get` is `smoothed.unwrap_or(latest)`). A smoothed RTT
    /// includes our own queue, so a path loaded with our traffic looks slow
    /// and the selection moves off it (S-I4); the minimum does not.
    pub(crate) rtt_micros: u64,
    /// Added to the RTT before ranking; negative makes the path preferred
    /// (iroh `TransportBias::rtt_bias`).
    pub(crate) rtt_bias_micros: i64,
}

impl SelectorPath {
    /// `windowed_min_rtt_micros == 0` means no sample (the candidate has no
    /// telemetry yet) and counts as [`UNMEASURED_RTT_MICROS`].
    pub(crate) fn new(
        key: PathKey,
        tier: PathTier,
        windowed_min_rtt_micros: u64,
        rtt_bias_micros: i64,
    ) -> Self {
        Self::with_unmeasured(
            key,
            tier,
            windowed_min_rtt_micros,
            rtt_bias_micros,
            UNMEASURED_RTT_MICROS,
        )
    }

    /// [`Self::new`] with the configured RTT a path without a sample ranks as.
    pub(crate) fn with_unmeasured(
        key: PathKey,
        tier: PathTier,
        windowed_min_rtt_micros: u64,
        rtt_bias_micros: i64,
        unmeasured_rtt_micros: u64,
    ) -> Self {
        Self {
            key,
            tier,
            rtt_micros: if windowed_min_rtt_micros == 0 {
                unmeasured_rtt_micros
            } else {
                windowed_min_rtt_micros
            },
            rtt_bias_micros,
        }
    }

    pub(crate) fn biased_rtt(&self) -> i64 {
        (self.rtt_micros as i64).saturating_add(self.rtt_bias_micros)
    }

    /// iroh `sort_key` (`biased_rtt_path_selector.rs:129-133`), with the path's
    /// address as the last term: iroh walks a hash map and takes the first of
    /// equals, which would make a tie flip between control ticks.
    pub(crate) fn sort_key(&self) -> (PathTier, i64, usize, SocketAddr, SocketAddr) {
        (
            self.tier,
            self.biased_rtt(),
            self.key.carrier_id.0,
            self.key.local_addr,
            self.key.remote_addr,
        )
    }
}

/// iroh's default bias table (`BiasedRttPathSelector::default`,
/// `biased_rtt_path_selector.rs:94-107`): IPv4 primary, IPv6 primary with a
/// 3 ms advantage, relay backup. A relay-next-hop path is ET's relay; its
/// virtual address is an IPv6 ULA, which must not earn the IPv6 advantage.
/// FakeTCP and manual paths have no entry in iroh and are primary without a
/// bias (iroh's rule for an unlisted transport).
///
/// A configured rule (`params`) for the kind and family replaces that table
/// row; a kind without a rule keeps its built-in row.
pub(crate) fn transport_bias(
    carrier_kind: CarrierKind,
    remote: SocketAddr,
    params: &SelectionParams,
) -> (PathTier, i64) {
    if let Some(rule) = params.rule_for(carrier_kind, remote) {
        return (rule.tier, rule.bias_micros);
    }
    match carrier_kind {
        CarrierKind::RelayNextHop => (PathTier::Backup, 0),
        _ if remote.is_ipv6() => (PathTier::Primary, -IPV6_RTT_ADVANTAGE_MICROS),
        _ => (PathTier::Primary, 0),
    }
}

/// ET: the RTT advantage a `prefer` policy gives a path (iroh
/// `TransportBias::with_rtt_advantage`). The weight scales the RTT the path is
/// ranked by: weight 2 ranks it as if twice as fast, weight 0.5 as if twice as
/// slow. iroh's advantage is a fixed duration for a whole transport; a user
/// weight has no natural duration, so it is a ratio instead.
pub(crate) fn prefer_bias_micros(rtt_micros: u64, weight: f64) -> i64 {
    if !(weight.is_finite() && weight > 0.0) {
        return 0;
    }
    (rtt_micros as f64 * (1.0 / weight - 1.0)).round() as i64
}

/// How much better than `incumbent` a path of its tier must be to replace it.
pub(crate) fn switching_threshold_micros(incumbent: &SelectorPath, params: &SelectionParams) -> i64 {
    let proportional = incumbent.rtt_micros.saturating_mul(params.switch_percent) / 100;
    params.switch_min_micros.max(proportional) as i64
}

/// The paths that carry data: the others are put on standby.
///
/// `current` is the set chosen last time. With `kmax == 1` this is iroh's
/// `select` (`biased_rtt_path_selector.rs:137-184`):
/// - no current path (none given, or none of them still a candidate): the best;
/// - the best is in a better tier than the current path: switch at once;
/// - same tier: switch only if the best is better by the switching threshold.
///
/// ET extends it:
/// - a set of up to `kmax` paths instead of one. Incumbents keep their place;
///   a free place goes to the best path not yet chosen; a path outside the set
///   replaces the worst member only by the single-path rule above;
/// - only the best tier takes part (iroh: "backup paths are only used when no
///   primary path is available", `biased_rtt_path_selector.rs:25-29`), so a
///   relay never fills the second place beside a direct path;
/// - a `pin`ned candidate takes the whole set, whatever `kmax` is (the user
///   asked for traffic on that path only). Pins that are not candidates
///   (not established) are ignored.
pub(crate) fn select_paths(
    paths: &[SelectorPath],
    current: &[PathKey],
    kmax: usize,
    pinned: &HashSet<PathKey>,
    params: &SelectionParams,
) -> Vec<PathKey> {
    let mut ranked: Vec<&SelectorPath> = paths.iter().collect();
    ranked.sort_by_key(|path| path.sort_key());

    let pinned_paths: Vec<PathKey> = ranked
        .iter()
        .filter(|path| pinned.contains(&path.key))
        .map(|path| path.key)
        .collect();
    if !pinned_paths.is_empty() {
        return pinned_paths;
    }

    let Some(best_tier) = ranked.first().map(|path| path.tier) else {
        return Vec::new();
    };
    ranked.retain(|path| path.tier == best_tier);
    let places = kmax.max(1);

    // Incumbents that are still candidates, best first, keep their places.
    let mut chosen: Vec<&SelectorPath> = ranked
        .iter()
        .copied()
        .filter(|path| current.contains(&path.key))
        .take(places)
        .collect();
    // A free place goes to the best path not chosen yet.
    for &path in &ranked {
        if chosen.len() >= places {
            break;
        }
        if !chosen.iter().any(|member| member.key == path.key) {
            chosen.push(path);
        }
    }
    // The best path outside the set takes over the worst member's place only
    // if it is better by the switching threshold; the paths after it are worse.
    for &challenger in &ranked {
        if chosen.iter().any(|member| member.key == challenger.key) {
            continue;
        }
        let Some((worst_index, worst)) = chosen
            .iter()
            .copied()
            .enumerate()
            .max_by_key(|(_, member)| member.sort_key())
        else {
            break;
        };
        if challenger.biased_rtt() + switching_threshold_micros(worst, params) <=worst.biased_rtt() {
            chosen[worst_index] = challenger;
        } else {
            break;
        }
    }
    chosen.sort_by_key(|path| path.sort_key());
    chosen.into_iter().map(|path| path.key).collect()
}

/// A resource's budget: a NIC's Autorate estimate within the user's bounds
/// (`MpSessionManager::refresh_all_egress_capacities`), or a user-declared
/// shared bottleneck's capacity.
#[derive(Debug, Clone)]
pub(crate) struct ResourceCapacity {
    pub(crate) resource: ResourceGroupId,
    pub(crate) capacity_bps: u64,
}

/// A path and the budgeted resources it passes through: its NIC, then a
/// shared-bottleneck group it belongs to, if any.
#[derive(Debug, Clone)]
pub(crate) struct BudgetedPath {
    pub(crate) key: PathKey,
    pub(crate) resources: Vec<ResourceGroupId>,
}

/// ET (no reference): the rate Brutal sends each path at. Brutal does not
/// estimate bandwidth, so the rate comes from the egress: a resource's budget
/// is split evenly among the paths listed with it, and a path takes the
/// smallest share over its resources. A path with no budgeted resource (or a
/// budget of 0, which is "not estimated yet") gets no entry and runs at
/// Brutal's own configured rate. What the peer can receive is capped later,
/// by `clamp_targets_to_peer_rx_cap`.
pub(crate) fn split_budgets(
    paths: &[BudgetedPath],
    budgets: &[ResourceCapacity],
) -> HashMap<PathKey, u64> {
    let budget_of = |resource: &ResourceGroupId| {
        budgets
            .iter()
            .find(|budget| &budget.resource == resource && budget.capacity_bps > 0)
            .map(|budget| budget.capacity_bps)
    };
    let mut users = HashMap::<&ResourceGroupId, u64>::new();
    for path in paths {
        for resource in &path.resources {
            *users.entry(resource).or_default() += 1;
        }
    }
    paths
        .iter()
        .filter_map(|path| {
            path.resources
                .iter()
                .filter_map(|resource| Some(budget_of(resource)? / users.get(resource).copied().unwrap_or(1).max(1)))
                .min()
                .map(|rate| (path.key, rate))
        })
        .collect()
}

/// MP_SQM_PLAN.md S2.3: resolves the first ENABLED policy in `policies`
/// whose three `match_*` fields all match (empty = wildcard), in list order.
/// Matching uses the exact same string representations already shown to the
/// user in `MpPathStatus` -- MP_SQM_PLAN.md §9's GUI convention: "路径操作的
/// 匹配器 = (egress_device, carrier_kind, path.remote_addr) 精确值" -- so a
/// policy the GUI wrote against a displayed path matches that same path here.
pub(crate) fn resolve_path_policy<'a>(
    policies: &'a [MpPathPolicy],
    egress_device: &str,
    carrier_kind: &str,
    remote_endpoint: &str,
) -> Option<&'a MpPathPolicy> {
    policies.iter().find(|policy| {
        policy.enabled
            && (policy.match_egress_device.is_empty()
                || policy.match_egress_device == egress_device)
            && (policy.match_carrier_kind.is_empty() || policy.match_carrier_kind == carrier_kind)
            && (policy.match_remote_endpoint.is_empty()
                || policy.match_remote_endpoint == remote_endpoint)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::mpquic::{CarrierId, PathKey};

    const MS: u64 = 1_000;

    fn key(id: usize) -> PathKey {
        PathKey {
            carrier_id: CarrierId(id),
            local_addr: format!("127.0.0.1:{}", 35_000 + id).parse().unwrap(),
            remote_addr: format!("127.0.0.1:{}", 36_000 + id).parse().unwrap(),
        }
    }

    fn primary(id: usize, rtt_ms: u64) -> SelectorPath {
        SelectorPath::new(key(id), PathTier::Primary, rtt_ms * MS, 0)
    }

    fn backup(id: usize, rtt_ms: u64) -> SelectorPath {
        SelectorPath::new(key(id), PathTier::Backup, rtt_ms * MS, 0)
    }

    fn pick(paths: &[SelectorPath], current: &[PathKey], kmax: usize) -> Vec<PathKey> {
        select_paths(paths, current, kmax, &HashSet::new(), &SelectionParams::default())
    }

    fn v6_remote() -> SocketAddr {
        "[2001:db8::1]:9".parse().unwrap()
    }

    fn v4_remote() -> SocketAddr {
        "192.0.2.1:9".parse().unwrap()
    }

    /// iroh `ipv6_wins_over_ipv4_within_bias`: the table gives IPv6 3 ms.
    #[test]
    fn ipv6_wins_over_ipv4_only_within_its_advantage() {
        let defaults = SelectionParams::default();
        let (tier4, bias4) = transport_bias(CarrierKind::UdpDirect, v4_remote(), &defaults);
        let (tier6, bias6) = transport_bias(CarrierKind::UdpDirect, v6_remote(), &defaults);
        let v4 = SelectorPath::new(key(1), tier4, 10 * MS, bias4);
        let make_v6 = |rtt_ms| SelectorPath::new(key(2), tier6, rtt_ms * MS, bias6);

        assert_eq!(pick(&[v4.clone(), make_v6(10)], &[], 1), vec![key(2)]);
        assert_eq!(pick(&[v4.clone(), make_v6(12)], &[], 1), vec![key(2)]);
        assert_eq!(pick(&[v4, make_v6(20)], &[], 1), vec![key(1)]);
    }

    /// A relay path's virtual address is an IPv6 ULA; it is backup, not an
    /// IPv6 path.
    #[test]
    fn relay_next_hop_is_backup_and_gets_no_ipv6_advantage() {
        assert_eq!(
            transport_bias(
                CarrierKind::RelayNextHop,
                "[fd4d:5000::1]:9".parse().unwrap(),
                &SelectionParams::default()
            ),
            (PathTier::Backup, 0)
        );
        assert_eq!(
            transport_bias(CarrierKind::FakeTcpPunch, v4_remote(), &SelectionParams::default()),
            (PathTier::Primary, 0)
        );
    }

    /// iroh `primary_wins_over_backup_regardless_of_rtt`.
    #[test]
    fn primary_tier_wins_over_backup_whatever_the_rtt() {
        assert_eq!(pick(&[primary(1, 100), backup(2, 10)], &[], 1), vec![key(1)]);
        assert_eq!(pick(&[primary(1, 1000), backup(2, 1)], &[], 1), vec![key(1)]);
    }

    /// iroh `same_tier_only_switches_with_significant_rtt_diff`: 20 ms current,
    /// 5 ms threshold (the condition is `<=`).
    #[test]
    fn same_tier_switches_only_by_the_switching_threshold() {
        let current = [key(1)];
        for (challenger_ms, switches) in [(18, false), (16, false), (15, true), (14, true)] {
            let chosen = pick(&[primary(1, 20), primary(2, challenger_ms)], &current, 1);
            assert_eq!(
                chosen,
                vec![if switches { key(2) } else { key(1) }],
                "challenger at {challenger_ms} ms"
            );
        }
    }

    /// ET: on a 200 ms link the threshold is 10% of it (20 ms), not 5 ms.
    #[test]
    fn switching_threshold_grows_with_the_rtt_of_the_replaced_path() {
        let current = [key(1)];
        // 10% of 200 ms is 20 ms: 185 ms is only 15 ms better.
        assert_eq!(pick(&[primary(1, 200), primary(2, 185)], &current, 1), vec![key(1)]);
        assert_eq!(pick(&[primary(1, 200), primary(2, 181)], &current, 1), vec![key(1)]);
        assert_eq!(pick(&[primary(1, 200), primary(2, 180)], &current, 1), vec![key(2)]);
        // At 20 ms the 5 ms floor rules (10% would be 2 ms).
        assert_eq!(pick(&[primary(1, 20), primary(2, 17)], &current, 1), vec![key(1)]);
        let defaults = SelectionParams::default();
        assert_eq!(switching_threshold_micros(&primary(1, 20), &defaults), 5_000);
        assert_eq!(switching_threshold_micros(&primary(1, 200), &defaults), 20_000);
    }

    /// iroh `no_current_path_selects_best` and `empty_paths_returns_none`.
    #[test]
    fn without_a_current_path_the_best_is_chosen() {
        assert_eq!(pick(&[primary(1, 20), primary(2, 10)], &[], 1), vec![key(2)]);
        assert!(pick(&[], &[], 1).is_empty());
        assert!(pick(&[], &[key(1)], 1).is_empty());
        // The current path died (no longer a candidate): no stickiness to it.
        assert_eq!(pick(&[primary(2, 90), primary(3, 80)], &[key(1)], 1), vec![key(3)]);
    }

    /// MP weak-network plan E1: the loaded path (47 ms propagation delay, its
    /// samples queued at 150-220 ms) keeps its place against a quiet one at
    /// 117 ms, because it is ranked by the windowed minimum. Fed the queued
    /// sample (what the 10 s "replace once old" filter returned) the selector
    /// leaves it, which was the flapping.
    #[test]
    fn a_loaded_path_is_ranked_by_its_propagation_delay_not_its_queue() {
        let current = [key(1)];
        assert_eq!(pick(&[primary(1, 47), primary(2, 117)], &current, 1), vec![key(1)]);
        assert_eq!(pick(&[primary(1, 150), primary(2, 117)], &current, 1), vec![key(2)]);
    }

    /// ET: a path with no RTT sample ranks as the 333 ms initial RTT.
    #[test]
    fn a_path_without_an_rtt_sample_ranks_at_the_initial_rtt() {
        let unmeasured = SelectorPath::new(key(2), PathTier::Primary, 0, 0);
        assert_eq!(unmeasured.rtt_micros, UNMEASURED_RTT_MICROS);
        assert_eq!(pick(&[primary(1, 300), unmeasured.clone()], &[], 1), vec![key(1)]);
        assert_eq!(pick(&[primary(1, 400), unmeasured], &[], 1), vec![key(2)]);
    }

    /// ET: the K best paths of the best tier, deterministic on equal RTT.
    #[test]
    fn kmax_takes_the_best_paths_of_the_best_tier() {
        let paths = [primary(1, 30), primary(2, 10), primary(3, 20), backup(4, 1)];
        assert_eq!(pick(&paths, &[], 2), vec![key(2), key(3)]);
        assert_eq!(pick(&paths, &[], 3), vec![key(2), key(3), key(1)]);
        // More places than primary paths: the relay does not fill them.
        assert_eq!(pick(&paths, &[], 8), vec![key(2), key(3), key(1)]);
        // Only a relay left: it carries.
        assert_eq!(pick(&[backup(4, 1)], &[], 2), vec![key(4)]);
        // Equal RTT: the lower carrier id, every time.
        let tie = [primary(2, 10), primary(1, 10)];
        assert_eq!(pick(&tie, &[], 1), vec![key(1)]);
    }

    /// ET: incumbents keep their places; a newcomer replaces the worst member
    /// only by the switching threshold.
    #[test]
    fn a_set_member_is_replaced_only_by_the_switching_threshold() {
        let current = [key(1), key(2)];
        // 3 is 3 ms better than member 2 (30 ms): inside the 5 ms threshold.
        let paths = [primary(1, 10), primary(2, 30), primary(3, 27)];
        assert_eq!(pick(&paths, &current, 2), vec![key(1), key(2)]);
        // 5 ms better than member 2 meets the threshold.
        let paths = [primary(1, 10), primary(2, 30), primary(3, 25)];
        assert_eq!(pick(&paths, &current, 2), vec![key(1), key(3)]);
        // Lowering kmax drops the worst member at once.
        let paths = [primary(1, 10), primary(2, 30)];
        assert_eq!(pick(&paths, &current, 1), vec![key(1)]);
        // A relay incumbent leaves as soon as a direct path exists.
        let paths = [primary(1, 200), backup(9, 5)];
        assert_eq!(pick(&paths, &[key(9)], 1), vec![key(1)]);
    }

    /// `pin`: the pinned path is the whole set, whatever kmax and the RTTs.
    #[test]
    fn a_pinned_path_takes_the_whole_set() {
        let paths = [primary(1, 5), primary(2, 90), primary(3, 6)];
        let pinned = HashSet::from([key(2)]);
        let defaults = SelectionParams::default();
        assert_eq!(select_paths(&paths, &[key(1)], 3, &pinned, &defaults), vec![key(2)]);
        // A pin on a relay beats a direct path too.
        let paths = [primary(1, 5), backup(9, 90)];
        assert_eq!(
            select_paths(&paths, &[key(1)], 1, &HashSet::from([key(9)]), &defaults),
            vec![key(9)]
        );
        // Two pins are both kept, beyond kmax.
        let paths = [primary(1, 5), primary(2, 90), primary(3, 6)];
        assert_eq!(
            select_paths(&paths, &[], 1, &HashSet::from([key(2), key(3)]), &defaults),
            vec![key(3), key(2)]
        );
        // A pin that is not a candidate (not established) is ignored.
        assert_eq!(
            select_paths(&paths, &[], 1, &HashSet::from([key(7)]), &defaults),
            vec![key(1)]
        );
    }

    /// `prefer{weight}`: the RTT advantage scales the ranked RTT.
    #[test]
    fn prefer_weight_scales_the_ranked_rtt() {
        assert_eq!(prefer_bias_micros(30 * MS, 2.0), -15_000);
        assert_eq!(prefer_bias_micros(30 * MS, 0.5), 30_000);
        assert_eq!(prefer_bias_micros(30 * MS, 1.0), 0);
        assert_eq!(prefer_bias_micros(30 * MS, 0.0), 0);
        assert_eq!(prefer_bias_micros(30 * MS, f64::NAN), 0);

        let biased = |id, rtt_ms, weight| {
            SelectorPath::new(
                key(id),
                PathTier::Primary,
                rtt_ms * MS,
                prefer_bias_micros(rtt_ms * MS, weight),
            )
        };
        // Equal RTT: the preferred one wins; a 2x preference only cancels a
        // path that is twice as slow.
        assert_eq!(pick(&[biased(1, 20, 1.0), biased(2, 20, 2.0)], &[], 1), vec![key(2)]);
        assert_eq!(pick(&[biased(1, 20, 1.0), biased(2, 40, 2.0)], &[], 1), vec![key(1)]);
        assert_eq!(pick(&[biased(1, 20, 1.0), biased(2, 39, 2.0)], &[], 1), vec![key(2)]);
        // A weight below 1 puts a path behind.
        assert_eq!(pick(&[biased(1, 30, 0.5), biased(2, 50, 1.0)], &[], 1), vec![key(2)]);
    }

    fn rule(
        carrier_kind: &str,
        ip_family: &str,
        tier: &str,
        rtt_bias_ms: i32,
    ) -> crate::proto::common::MpSelectionKindRule {
        crate::proto::common::MpSelectionKindRule {
            carrier_kind: carrier_kind.into(),
            ip_family: ip_family.into(),
            tier: tier.into(),
            rtt_bias_ms,
        }
    }

    fn params_of(selection: MpSelectionConfig) -> SelectionParams {
        SelectionParams::from_config(Some(&selection))
    }

    fn pick_with(
        params: &SelectionParams,
        paths: &[SelectorPath],
        current: &[PathKey],
        kmax: usize,
    ) -> Vec<PathKey> {
        select_paths(paths, current, kmax, &HashSet::new(), params)
    }

    /// No section, an empty section and zero fields are all the built-in
    /// values: an old configuration selects as before.
    #[test]
    fn an_absent_or_zero_selection_config_is_the_default() {
        let defaults = SelectionParams::default();
        assert_eq!(SelectionParams::from_config(None), defaults);
        assert_eq!(params_of(MpSelectionConfig::default()), defaults);
        assert_eq!(defaults.switch_min_micros, 5_000);
        assert_eq!(defaults.switch_percent, 10);
        assert_eq!(defaults.lossy_loss, 0.10);
        assert_eq!(defaults.unmeasured_rtt_micros, 333_000);
    }

    /// With the IPv6 advantage set to 0 the faster IPv4 path wins; the
    /// default table gives IPv6 3 ms.
    #[test]
    fn a_v6_bias_of_zero_lets_the_faster_v4_path_win() {
        let rules = MpSelectionConfig {
            kind_rules: vec![rule("udp-direct", "v6", "primary", 0)],
            ..Default::default()
        };
        let tuned = params_of(rules);
        let build = |params: &SelectionParams| {
            let (tier4, bias4) = transport_bias(CarrierKind::UdpDirect, v4_remote(), params);
            let (tier6, bias6) = transport_bias(CarrierKind::UdpDirect, v6_remote(), params);
            [
                SelectorPath::new(key(1), tier4, 10 * MS, bias4),
                SelectorPath::new(key(2), tier6, 12 * MS, bias6),
            ]
        };
        let defaults = SelectionParams::default();
        assert_eq!(pick_with(&defaults, &build(&defaults), &[], 1), vec![key(2)]);
        assert_eq!(pick_with(&tuned, &build(&tuned), &[], 1), vec![key(1)]);
    }

    /// A rule for a kind and family beats a rule for the kind alone, which
    /// beats the built-in table; a kind without a rule keeps its built-in row.
    #[test]
    fn the_most_specific_rule_decides_and_other_kinds_keep_the_built_in_table() {
        let params = params_of(MpSelectionConfig {
            kind_rules: vec![
                rule("udp-direct", "", "backup", 7),
                rule("udp-direct", "v6", "primary", -9),
            ],
            ..Default::default()
        });
        assert_eq!(
            transport_bias(CarrierKind::UdpDirect, v6_remote(), &params),
            (PathTier::Primary, -9_000)
        );
        assert_eq!(
            transport_bias(CarrierKind::UdpDirect, v4_remote(), &params),
            (PathTier::Backup, 7_000)
        );
        assert_eq!(
            transport_bias(CarrierKind::UdpPunch, v6_remote(), &params),
            (PathTier::Primary, -3_000)
        );
        assert_eq!(
            transport_bias(CarrierKind::RelayNextHop, v4_remote(), &params),
            (PathTier::Backup, 0)
        );
    }

    /// A rule that does not parse is skipped, not trusted.
    #[test]
    fn a_rule_with_an_unknown_tier_or_family_is_skipped() {
        let params = params_of(MpSelectionConfig {
            kind_rules: vec![
                rule("udp-direct", "v5", "primary", 1),
                rule("udp-direct", "", "middle", 1),
            ],
            ..Default::default()
        });
        assert_eq!(
            transport_bias(CarrierKind::UdpDirect, v4_remote(), &params),
            (PathTier::Primary, 0)
        );
    }

    /// 12.4 ms is replaced by 9.2 ms only when the threshold is 2 ms (the
    /// default 5 ms needs 7.4 ms).
    #[test]
    fn a_lower_switch_threshold_replaces_a_path_by_a_smaller_gain() {
        let paths = [
            SelectorPath::new(key(1), PathTier::Primary, 12_400, 0),
            SelectorPath::new(key(2), PathTier::Primary, 9_200, 0),
        ];
        let current = [key(1)];
        assert_eq!(pick(&paths, &current, 1), vec![key(1)]);
        let tuned = params_of(MpSelectionConfig {
            switch_min_ms: 2,
            ..Default::default()
        });
        assert_eq!(pick_with(&tuned, &paths, &current, 1), vec![key(2)]);
        assert_eq!(switching_threshold_micros(&paths[0], &tuned), 2_000);
    }

    /// The share of the replaced path's RTT is a parameter too.
    #[test]
    fn the_switch_percent_scales_the_threshold_with_the_replaced_rtt() {
        let tuned = params_of(MpSelectionConfig {
            switch_percent: 50,
            ..Default::default()
        });
        assert_eq!(switching_threshold_micros(&primary(1, 200), &tuned), 100_000);
        assert_eq!(
            switching_threshold_micros(&primary(1, 200), &SelectionParams::default()),
            20_000
        );
    }

    /// A path without a sample ranks as the configured stand-in.
    #[test]
    fn the_unmeasured_rtt_changes_how_an_unsampled_path_ranks() {
        let sampled = primary(1, 100);
        let unsampled = |params: &SelectionParams| {
            SelectorPath::with_unmeasured(
                key(2),
                PathTier::Primary,
                0,
                0,
                params.unmeasured_rtt_micros,
            )
        };
        let defaults = SelectionParams::default();
        assert_eq!(
            pick_with(&defaults, &[sampled.clone(), unsampled(&defaults)], &[], 1),
            vec![key(1)]
        );
        let tuned = params_of(MpSelectionConfig {
            unmeasured_rtt_ms: 50,
            ..Default::default()
        });
        let candidate = unsampled(&tuned);
        assert_eq!(candidate.rtt_micros, 50_000);
        assert_eq!(pick_with(&tuned, &[sampled, candidate], &[], 1), vec![key(2)]);
    }

    /// Made primary, a relay competes with the direct paths by RTT instead of
    /// waiting behind them as a backup.
    #[test]
    fn a_relay_made_primary_competes_with_direct_paths() {
        let relay_rule = MpSelectionConfig {
            kind_rules: vec![rule("relay-next-hop", "", "primary", 0)],
            ..Default::default()
        };
        let tuned = params_of(relay_rule);
        let build = |params: &SelectionParams| {
            let (relay_tier, relay_bias) =
                transport_bias(CarrierKind::RelayNextHop, v4_remote(), params);
            [
                primary(1, 20),
                SelectorPath::new(key(2), relay_tier, 10 * MS, relay_bias),
            ]
        };
        let defaults = SelectionParams::default();
        assert_eq!(pick_with(&defaults, &build(&defaults), &[], 1), vec![key(1)]);
        assert_eq!(pick_with(&tuned, &build(&tuned), &[], 1), vec![key(2)]);
        assert_eq!(pick_with(&tuned, &build(&tuned), &[], 2), vec![key(2), key(1)]);
    }

    /// A rule can demote a kind to backup: it then carries only when nothing
    /// else does.
    #[test]
    fn a_kind_demoted_to_backup_carries_only_when_nothing_else_does() {
        let tuned = params_of(MpSelectionConfig {
            kind_rules: vec![rule("udp-direct", "", "backup", 0)],
            ..Default::default()
        });
        let (direct_tier, direct_bias) =
            transport_bias(CarrierKind::UdpDirect, v4_remote(), &tuned);
        let direct = SelectorPath::new(key(1), direct_tier, 5 * MS, direct_bias);
        let punched = primary(2, 50);
        assert_eq!(
            pick_with(&tuned, &[direct.clone(), punched], &[], 1),
            vec![key(2)]
        );
        assert_eq!(pick_with(&tuned, &[direct], &[], 1), vec![key(1)]);
    }

    fn budgeted(id: usize, resources: &[&ResourceGroupId]) -> BudgetedPath {
        BudgetedPath {
            key: key(id),
            resources: resources.iter().map(|r| (*r).clone()).collect(),
        }
    }

    fn nic(name: &str) -> ResourceGroupId {
        ResourceGroupId::egress_device(name).unwrap()
    }

    fn budget(resource: &ResourceGroupId, capacity_bps: u64) -> ResourceCapacity {
        ResourceCapacity {
            resource: resource.clone(),
            capacity_bps,
        }
    }

    /// The NIC's budget is split evenly among the selected paths on it; a path
    /// on another NIC has that NIC's budget alone.
    #[test]
    fn a_nics_budget_is_split_evenly_among_its_selected_paths() {
        let (a, b) = (nic("a"), nic("b"));
        let rates = split_budgets(
            &[budgeted(1, &[&a]), budgeted(2, &[&a]), budgeted(3, &[&b])],
            &[budget(&a, 90_000_000), budget(&b, 40_000_000)],
        );
        assert_eq!(rates[&key(1)], 45_000_000);
        assert_eq!(rates[&key(2)], 45_000_000);
        assert_eq!(rates[&key(3)], 40_000_000);
    }

    /// A user-declared shared bottleneck bounds its members on top of the NIC.
    #[test]
    fn a_shared_bottleneck_caps_its_members_besides_their_nics() {
        let (a, b) = (nic("a"), nic("b"));
        let group = ResourceGroupId::shared_bottleneck("office");
        let rates = split_budgets(
            &[budgeted(1, &[&a, &group]), budgeted(2, &[&b, &group])],
            &[
                budget(&a, 100_000_000),
                budget(&b, 100_000_000),
                budget(&group, 60_000_000),
            ],
        );
        assert_eq!(rates[&key(1)], 30_000_000);
        assert_eq!(rates[&key(2)], 30_000_000);
    }

    /// No budget (or 0, "not estimated yet"): no rate, Brutal's own applies.
    #[test]
    fn a_path_without_a_budget_gets_no_rate() {
        let (a, b) = (nic("a"), nic("b"));
        let rates = split_budgets(
            &[budgeted(1, &[&a]), budgeted(2, &[&b]), budgeted(3, &[])],
            &[budget(&a, 0)],
        );
        assert!(rates.is_empty());
    }

    fn policy(action: &str, prefer_weight: f64) -> MpPathPolicy {
        MpPathPolicy {
            match_egress_device: String::new(),
            match_carrier_kind: String::new(),
            match_remote_endpoint: String::new(),
            action: action.to_string(),
            prefer_weight,
            enabled: true,
            note: String::new(),
        }
    }

    /// MP_SQM_PLAN.md S2.3: empty `match_*` fields are wildcards; a disabled
    /// policy never matches even if every field would otherwise line up; the
    /// first enabled matching entry wins over later ones.
    #[test]
    fn resolve_path_policy_wildcards_disabled_and_first_match_order() {
        let wildcard = policy("pin", 1.0);
        assert_eq!(
            resolve_path_policy(&[wildcard.clone()], "eth0", "udp-direct", "1.2.3.4:9")
                .map(|p| p.action.as_str()),
            Some("pin")
        );

        let mut disabled = policy("exclude", 1.0);
        disabled.enabled = false;
        assert!(
            resolve_path_policy(&[disabled], "eth0", "udp-direct", "1.2.3.4:9").is_none(),
            "a disabled policy must never match"
        );

        let mut specific = policy("pause", 1.0);
        specific.match_egress_device = "eth1".to_string();
        assert!(
            resolve_path_policy(&[specific], "eth0", "udp-direct", "1.2.3.4:9").is_none(),
            "a non-matching match_egress_device must not match a different device"
        );

        let mut first = policy("pin", 1.0);
        first.match_egress_device = "eth0".to_string();
        let mut second = policy("exclude", 1.0);
        second.match_egress_device = "eth0".to_string();
        let both = [first, second];
        let resolved = resolve_path_policy(&both, "eth0", "udp-direct", "1.2.3.4:9")
            .expect("first entry matches");
        assert_eq!(
            resolved.action, "pin",
            "first enabled matching policy must win over a later one"
        );
    }
}

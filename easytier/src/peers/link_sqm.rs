//! Per-link SQM estimator registry (MP_SQM_PLAN.md §7.2 signal collection).
//!
//! Holds one egress [`LinkSqmEstimator`] per directly-connected peer and turns
//! raw signals — EasyTier's pingpong one-way-delay and the per-conn cumulative
//! byte counters — into a live *residual* (usable) bandwidth estimate. The route
//! cost calculator exposes that estimate through
//! [`RouteCostCalculatorInterface::directed_bandwidth_bps`] so the weighted
//! next-hop split (MP_SQM_PLAN.md §9.1) can bias by bandwidth, not just latency.
//!
//! Only egress (my_peer -> direct_peer) is tracked locally; the reverse
//! direction is estimated by the peer on its own side and gossiped back through
//! the global peer map, so up/down are handled independently and asymmetrically
//! (MP_SQM_PLAN.md §7.1) without any extra state here.

use std::collections::HashSet;

use dashmap::DashMap;

use crate::common::PeerId;

use crate::common::egress_quality::autorate::{
    DEFAULT_AUTORATE_START_BPS, LinkSqmEstimator, SqmConfig, SqmSample,
};

struct LinkState {
    estimator: LinkSqmEstimator,
    // last observed cumulative egress bytes to this peer, for rate differencing
    last_tx_bytes: u64,
    // whether we have a previous byte sample to difference against
    seen_tx: bool,
}

/// Registry of per-directed-link SQM estimators for the local node's egress
/// links to its directly-connected peers.
pub struct LinkSqmRegistry {
    links: DashMap<PeerId, LinkState>,
    cfg: SqmConfig,
}

impl Default for LinkSqmRegistry {
    fn default() -> Self {
        Self::with_config(SqmConfig::default())
    }
}

impl LinkSqmRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(cfg: SqmConfig) -> Self {
        Self {
            links: DashMap::new(),
            cfg,
        }
    }

    /// Feed one raw sample for the egress link to `peer`.
    ///
    /// * `owd_us` — pingpong-derived one-way delay proxy (µs). Only used relative
    ///   to a self-learned baseline, so its absolute scale/offset is irrelevant.
    /// * `cur_tx_bytes` — cumulative bytes sent to that peer so far.
    /// * `dt_us` — elapsed time since the previous sample for this registry.
    ///
    /// Returns the updated residual-bandwidth estimate (bps).
    pub fn observe(&self, peer: PeerId, owd_us: u64, cur_tx_bytes: u64, dt_us: u64) -> u64 {
        let mut st = self.links.entry(peer).or_insert_with(|| LinkState {
            // A link starts at the default uplink, the same as an egress
            // (`EgressQualityManager`): bufferbloat cuts it to what it carries.
            estimator: LinkSqmEstimator::new_with_start(self.cfg.clone(), DEFAULT_AUTORATE_START_BPS),
            last_tx_bytes: cur_tx_bytes,
            seen_tx: false,
        });
        let achieved_bps = if st.seen_tx {
            rate_bps(st.last_tx_bytes, cur_tx_bytes, dt_us)
        } else {
            0
        };
        st.last_tx_bytes = cur_tx_bytes;
        st.seen_tx = true;
        st.estimator
            .update(SqmSample { owd_us, achieved_bps })
            .residual_bps
    }

    /// Current residual-bandwidth estimate (bps) for the egress link to `peer`,
    /// or `None` if that link has never been sampled. A sampled link that is
    /// fully saturated returns `Some(0)` (known, no headroom) — distinct from an
    /// unsampled link — so the weight helper still de-prioritises it instead of
    /// falling back to a latency-only split.
    pub fn est_bw_bps(&self, peer: PeerId) -> Option<u64> {
        self.links
            .get(&peer)
            .filter(|s| s.seen_tx)
            .map(|s| s.estimator.estimate().residual_bps)
    }

    /// Drop estimators for peers that are no longer directly connected, so stale
    /// links cannot keep seeding weights after they disappear.
    pub fn retain(&self, live: &HashSet<PeerId>) {
        self.links.retain(|k, _| live.contains(k));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.links.len()
    }
}

/// Bits-per-second from a cumulative byte counter delta over `dt_us` µs.
/// A counter reset/wrap (`cur < prev`) or a zero interval both yield 0.
fn rate_bps(prev: u64, cur: u64, dt_us: u64) -> u64 {
    if dt_us == 0 || cur < prev {
        return 0;
    }
    let bytes = (cur - prev) as u128;
    ((bytes * 8 * 1_000_000) / dt_us as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_bps_basic() {
        // 1_000_000 bytes over 1s = 8 Mbit/s
        assert_eq!(rate_bps(0, 1_000_000, 1_000_000), 8_000_000);
        // half a second -> double the rate
        assert_eq!(rate_bps(0, 1_000_000, 500_000), 16_000_000);
    }

    #[test]
    fn rate_bps_guards() {
        assert_eq!(rate_bps(0, 1_000_000, 0), 0, "zero interval -> 0");
        assert_eq!(rate_bps(500, 100, 1_000_000), 0, "counter reset -> 0");
        assert_eq!(rate_bps(100, 100, 1_000_000), 0, "no bytes -> 0");
    }

    #[test]
    fn unknown_until_sampled() {
        let reg = LinkSqmRegistry::new();
        assert_eq!(reg.est_bw_bps(42), None);
        reg.observe(42, 20_000, 0, 500_000);
        assert!(reg.est_bw_bps(42).is_some(), "known after first sample");
    }

    #[test]
    fn retain_drops_gone_peers() {
        let reg = LinkSqmRegistry::new();
        reg.observe(1, 20_000, 0, 500_000);
        reg.observe(2, 20_000, 0, 500_000);
        reg.observe(3, 20_000, 0, 500_000);
        assert_eq!(reg.len(), 3);
        let live: HashSet<PeerId> = [1u32, 3u32].into_iter().collect();
        reg.retain(&live);
        assert_eq!(reg.len(), 2);
        assert!(reg.est_bw_bps(1).is_some());
        assert_eq!(reg.est_bw_bps(2), None, "dropped peer is unknown again");
        assert!(reg.est_bw_bps(3).is_some());
    }

    // bytes/dt helper for the closed-loop tests below.
    fn bytes_for(bps: u64, dt_us: u64) -> u64 {
        (bps as u128 * dt_us as u128 / 8 / 1_000_000) as u64
    }

    // Sustained moderate load with low delay -> the link shows positive usable
    // headroom (residual), driven purely by the
    // cumulative byte counter (MP_SQM_PLAN.md §7.2 signal path).
    #[test]
    fn residual_positive_under_headroom_via_bytes() {
        let reg = LinkSqmRegistry::new();
        let dt_us = 500_000u64; // 2 Hz
        let load_bps = 10_000_000u64; // constant 10 Mbps, no bloat
        let mut tx = 0u64;
        let mut last = 0u64;
        for _ in 0..80 {
            tx += bytes_for(load_bps, dt_us);
            last = reg.observe(1, 20_000, tx, dt_us);
        }
        assert!(last > 0, "residual should be positive under headroom, got {last}");
        assert_eq!(reg.est_bw_bps(1), Some(last));
    }

    // Establish capacity under light load, then slam the link with heavy load +
    // sustained delay bloat: the usable residual must collapse.
    #[test]
    fn residual_shrinks_under_bloat_via_bytes() {
        let reg = LinkSqmRegistry::with_config(SqmConfig::default());
        let dt_us = 500_000u64;
        let mut tx = 0u64;
        for _ in 0..20 {
            tx += bytes_for(10_000_000, dt_us);
            reg.observe(1, 20_000, tx, dt_us);
        }
        let before = reg.est_bw_bps(1).unwrap();
        for _ in 0..20 {
            tx += bytes_for(80_000_000, dt_us);
            reg.observe(1, 60_000, tx, dt_us); // +40 ms bloat, saturating load
        }
        let after = reg.est_bw_bps(1).unwrap();
        assert!(
            after < before,
            "residual must shrink under bloat: {after} !< {before}"
        );
    }
}

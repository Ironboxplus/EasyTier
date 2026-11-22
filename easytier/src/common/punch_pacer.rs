//! Per-NIC hole-punch packet budget (`MpConfig.punch_pps` /
//! `punch_rate_limits`). Only consulted while MP is on, so native punching is
//! untouched when MP is off. Over-budget packets are dropped rather than
//! delayed: the punch RPCs time out within a few seconds, and a late punch
//! packet is worth nothing.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
    time::{Duration, Instant},
};

use crate::proto::common::MpConfig;

use super::egress_inventory::EgressInventory;

/// Whole tokens `rate_per_sec` produces over `elapsed`.
fn refill_tokens(rate_per_sec: u64, elapsed: Duration) -> u64 {
    (rate_per_sec as u128 * elapsed.as_micros() / 1_000_000).min(u64::MAX as u128) as u64
}

/// How long a destination's resolved NIC is reused before routing is asked
/// again; punching to one peer lasts seconds, routes change rarely.
const ROUTE_CACHE_TTL: Duration = Duration::from_secs(10);

struct Bucket {
    pps: u64,
    available: u64,
    last_refill: Instant,
}

#[derive(Default)]
pub struct PunchPacer {
    buckets: Mutex<HashMap<String, Bucket>>,
    nic_by_dst: Mutex<HashMap<IpAddr, (Option<String>, Instant)>>,
}

/// Packets per second this NIC may send; 0 = unlimited.
pub fn punch_pps_for(config: &MpConfig, nic: Option<&str>) -> u32 {
    nic.and_then(|nic| {
        config
            .punch_rate_limits
            .iter()
            .find(|limit| limit.egress_device == nic)
    })
    .map(|limit| limit.pps)
    .unwrap_or(config.punch_pps)
}

impl PunchPacer {
    /// Takes one packet from `nic`'s budget. The bucket holds one second's
    /// worth, so a burst up to `pps` goes out at once and then refills.
    fn take(&self, nic: &str, pps: u32, now: Instant) -> bool {
        let pps = u64::from(pps);
        let mut buckets = self.buckets.lock().unwrap();
        let bucket = buckets.entry(nic.to_owned()).or_insert(Bucket {
            pps,
            available: pps,
            last_refill: now,
        });
        if bucket.pps != pps {
            *bucket = Bucket {
                pps,
                available: pps,
                last_refill: now,
            };
        }
        let added = refill_tokens(pps, now.saturating_duration_since(bucket.last_refill));
        if added > 0 {
            bucket.available = bucket.available.saturating_add(added).min(pps);
            // Advance only by the time the whole tokens took, so the
            // sub-token remainder still counts towards the next one.
            bucket.last_refill = if bucket.available == pps {
                now
            } else {
                bucket.last_refill + Duration::from_micros(added * 1_000_000 / pps)
            };
        }
        if bucket.available == 0 {
            return false;
        }
        bucket.available -= 1;
        true
    }

    async fn nic_for(
        &self,
        inventory: &EgressInventory,
        local: Option<SocketAddr>,
        dst: IpAddr,
    ) -> Option<String> {
        let snapshot = inventory.snapshot();
        // A socket bound to one NIC's address leaves through that NIC.
        if let Some(local_ip) = local.map(|addr| addr.ip()).filter(|ip| !ip.is_unspecified())
            && let Some(interface) = snapshot
                .interfaces
                .values()
                .find(|interface| interface.addresses.iter().any(|addr| addr.ip == local_ip))
        {
            return Some(interface.platform_name.clone());
        }
        let now = Instant::now();
        if let Some((nic, at)) = self.nic_by_dst.lock().unwrap().get(&dst)
            && now.saturating_duration_since(*at) < ROUTE_CACHE_TTL
        {
            return nic.clone();
        }
        let nic = inventory.best_route_to(dst).await.ok().and_then(|route| {
            snapshot
                .interfaces
                .values()
                .find(|interface| interface.runtime_ifindex == route.output_ifindex)
                .map(|interface| interface.platform_name.clone())
        });
        let mut cache = self.nic_by_dst.lock().unwrap();
        cache.retain(|_, (_, at)| now.saturating_duration_since(*at) < ROUTE_CACHE_TTL);
        cache.insert(dst, (nic.clone(), now));
        nic
    }

    /// Whether one punch packet from `local` to `dst` may be sent now.
    pub async fn allow(
        &self,
        config: &MpConfig,
        inventory: Option<&EgressInventory>,
        local: Option<SocketAddr>,
        dst: IpAddr,
    ) -> bool {
        if config.punch_pps == 0 && config.punch_rate_limits.is_empty() {
            return true;
        }
        let nic = match inventory {
            Some(inventory) => self.nic_for(inventory, local, dst).await,
            None => None,
        };
        let pps = punch_pps_for(config, nic.as_deref());
        if pps == 0 {
            return true;
        }
        // An unresolved NIC shares one budget so it is still bounded.
        self.take(nic.as_deref().unwrap_or(""), pps, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::common::MpPunchRateLimit;

    #[test]
    fn a_nic_override_beats_the_global_budget() {
        let config = MpConfig {
            punch_pps: 100,
            punch_rate_limits: vec![
                MpPunchRateLimit {
                    egress_device: "eth1".into(),
                    pps: 5,
                },
                MpPunchRateLimit {
                    egress_device: "eth2".into(),
                    pps: 0,
                },
            ],
            ..Default::default()
        };
        assert_eq!(punch_pps_for(&config, Some("eth0")), 100);
        assert_eq!(punch_pps_for(&config, Some("eth1")), 5);
        assert_eq!(punch_pps_for(&config, Some("eth2")), 0);
        assert_eq!(punch_pps_for(&config, None), 100);
    }

    #[test]
    fn the_budget_drops_the_excess_and_refills_over_time() {
        let pacer = PunchPacer::default();
        let start = Instant::now();
        let sent = (0..50).filter(|_| pacer.take("eth0", 10, start)).count();
        assert_eq!(sent, 10, "a one-second burst of pps packets goes out");
        assert!(!pacer.take("eth0", 10, start + Duration::from_millis(50)));
        assert!(pacer.take("eth0", 10, start + Duration::from_millis(150)));
        // Other NICs have their own budget.
        assert!(pacer.take("eth1", 10, start));
    }

    #[test]
    fn changing_the_rate_resets_the_bucket() {
        let pacer = PunchPacer::default();
        let start = Instant::now();
        while pacer.take("eth0", 2, start) {}
        assert!(pacer.take("eth0", 3, start));
    }

    #[tokio::test]
    async fn no_budget_configured_allows_everything() {
        let pacer = PunchPacer::default();
        let config = MpConfig::default();
        for _ in 0..1000 {
            assert!(
                pacer
                    .allow(&config, None, None, "1.2.3.4".parse().unwrap())
                    .await
            );
        }
    }
}

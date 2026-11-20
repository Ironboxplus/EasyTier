use cidr::Ipv6Inet;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use dashmap::DashMap;
use hotpath::instant::Instant;
use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use crate::{
    common::{PeerId, global_ctx::NetworkIdentity},
    proto::{
        api::instance::ListPublicIpv6InfoResponse,
        peer_rpc::{
            ForeignNetworkRouteInfoEntry, ForeignNetworkRouteInfoKey, PeerIdentityType,
            RouteForeignNetworkInfos, RouteForeignNetworkSummary, RoutePeerInfo,
        },
    },
};

#[derive(Clone, Debug, Default)]
pub enum NextHopPolicy {
    #[default]
    LeastHop,
    LeastCost,
    /// Multipath: split traffic across a weighted set of edge-disjoint next-hops
    /// (see MP_SQM_PLAN.md §9). Each lookup returns one next-hop chosen by weight
    /// (weighted round-robin), so repeated calls spread packets by weight.
    /// Falls back to the least-cost single next-hop when no weighted set exists.
    Weighted {
        /// Per-flow hash for sticky selection (MP_SQM_PLAN.md §9.3): `Some(h)`
        /// pins this flow to one next-hop (chosen deterministically from `h`) so
        /// realtime/connectionless flows are not reordered by the split; `None`
        /// uses the rolling weighted round-robin so packets spread by weight.
        flow_hash: Option<u64>,
    },
}

/// Multipath weighted routing is opt-in via `ET_MP_WEIGHTED=1` (off by default,
/// so default routing behavior and route-rebuild cost stay unchanged). Read once
/// and cached for the process lifetime. See MP_SQM_PLAN.md §9.
pub fn mp_weighted_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("ET_MP_WEIGHTED")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    })
}

/// Multipath slider λ ∈ [0,1] from `ET_MP_LAMBDA` (default 0.5). 0 = lowest
/// latency (concentrate weight on the best path), 1 = maximum bandwidth (spread
/// evenly). Maps to the weight exponent `k = (1-λ)·K_MAX`. See MP_SQM_PLAN.md §9.
pub fn mp_lambda() -> f64 {
    static LAMBDA: std::sync::OnceLock<f64> = std::sync::OnceLock::new();
    *LAMBDA.get_or_init(|| {
        std::env::var("ET_MP_LAMBDA")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .map(|v| v.clamp(0.0, 1.0))
            .unwrap_or(0.5)
    })
}

pub type ForeignNetworkRouteInfoMap =
    DashMap<ForeignNetworkRouteInfoKey, ForeignNetworkRouteInfoEntry>;

#[async_trait::async_trait]
pub trait RouteInterface {
    async fn list_peers(&self) -> Vec<PeerId>;
    fn my_peer_id(&self) -> PeerId;
    fn need_periodic_requery_peers(&self) -> bool {
        false
    }
    async fn close_peer(&self, _peer_id: PeerId) {}
    async fn get_peer_public_key(&self, _peer_id: PeerId) -> Option<Vec<u8>> {
        None
    }
    async fn get_peer_identity_type(&self, _peer_id: PeerId) -> Option<PeerIdentityType> {
        None
    }
    async fn list_foreign_networks(&self) -> ForeignNetworkRouteInfoMap {
        DashMap::new()
    }
}

pub type RouteInterfaceBox = Box<dyn RouteInterface + Send + Sync>;

#[auto_impl::auto_impl(Box , &mut)]
pub trait RouteCostCalculatorInterface: Send + Sync {
    fn begin_update(&mut self) {}
    fn end_update(&mut self) {}

    fn calculate_cost(&self, _src: PeerId, _dst: PeerId) -> i32 {
        1
    }

    /// Optional per-directed-link usable ("residual") bandwidth estimate in bps,
    /// produced by the per-link SQM estimator (MP_SQM_PLAN.md §7). Used by the
    /// multipath weighted router to bias splits toward higher-bandwidth paths
    /// (`w = est_bw * (min_srtt/srtt)^k`). Returning `None` (the default) makes
    /// weighted routing fall back to latency-only cold-start weights, so nodes
    /// without SQM data behave exactly as before.
    fn directed_bandwidth_bps(&self, _src: PeerId, _dst: PeerId) -> Option<u64> {
        None
    }

    fn need_update(&self) -> bool {
        false
    }

    fn dump(&self) -> String {
        "All routes have cost 1".to_string()
    }
}

#[derive(Clone, Debug, Default)]
pub struct DefaultRouteCostCalculator;

impl RouteCostCalculatorInterface for DefaultRouteCostCalculator {}

pub type RouteCostCalculator = Box<dyn RouteCostCalculatorInterface>;

#[async_trait::async_trait]
#[auto_impl::auto_impl(Box, Arc)]
pub trait Route {
    async fn open(&self, interface: RouteInterfaceBox) -> Result<u8, ()>;
    async fn close(&self);

    async fn get_next_hop(&self, peer_id: PeerId) -> Option<PeerId>;
    async fn get_next_hop_with_policy(
        &self,
        peer_id: PeerId,
        _policy: NextHopPolicy,
    ) -> Option<PeerId> {
        self.get_next_hop(peer_id).await
    }

    async fn list_routes(&self) -> Vec<crate::proto::api::instance::Route>;

    // TODO: rewrite route management, remove this
    async fn list_proxy_cidrs(&self) -> BTreeSet<Ipv4Cidr>;

    // TODO: rewrite route management, remove this
    async fn list_proxy_cidrs_v6(&self) -> BTreeSet<Ipv6Cidr>;

    async fn list_public_ipv6_routes(&self) -> BTreeSet<Ipv6Inet> {
        BTreeSet::new()
    }

    async fn get_my_public_ipv6_addr(&self) -> Option<Ipv6Inet> {
        None
    }

    async fn get_public_ipv6_gateway_peer_id(&self) -> Option<PeerId> {
        None
    }

    async fn get_local_public_ipv6_info(&self) -> ListPublicIpv6InfoResponse {
        ListPublicIpv6InfoResponse::default()
    }

    async fn get_peer_id_by_ipv4(&self, _ipv4: &Ipv4Addr) -> Option<PeerId> {
        None
    }

    async fn get_peer_id_by_ipv6(&self, _ipv6: &Ipv6Addr) -> Option<PeerId> {
        None
    }

    async fn get_peer_id_by_ip(&self, ip: &std::net::IpAddr) -> Option<PeerId> {
        match ip {
            std::net::IpAddr::V4(v4) => self.get_peer_id_by_ipv4(v4).await,
            std::net::IpAddr::V6(v6) => self.get_peer_id_by_ipv6(v6).await,
        }
    }

    async fn list_peers_own_foreign_network(
        &self,
        _network_identity: &NetworkIdentity,
    ) -> Vec<PeerId> {
        vec![]
    }

    async fn list_foreign_network_info(&self) -> RouteForeignNetworkInfos {
        Default::default()
    }

    async fn get_foreign_network_summary(&self) -> RouteForeignNetworkSummary {
        Default::default()
    }

    // my peer id in foreign network is different from the one in local network
    // this function is used to get the peer id in local network
    async fn get_origin_my_peer_id(
        &self,
        _network_name: &str,
        _foreign_my_peer_id: PeerId,
    ) -> Option<PeerId> {
        None
    }

    async fn set_route_cost_fn(&self, _cost_fn: RouteCostCalculator) {}

    async fn get_peer_info(&self, peer_id: PeerId) -> Option<RoutePeerInfo>;

    async fn get_peer_info_last_update_time(&self) -> Instant;

    fn get_peer_groups(&self, peer_id: PeerId) -> Arc<Vec<String>>;

    async fn refresh_acl_groups(&self) {}

    async fn get_peer_groups_by_ip(&self, ip: &std::net::IpAddr) -> Arc<Vec<String>> {
        match self.get_peer_id_by_ip(ip).await {
            Some(peer_id) => self.get_peer_groups(peer_id),
            None => Arc::new(Vec::new()),
        }
    }

    async fn get_peer_groups_by_ipv4(&self, ipv4: &Ipv4Addr) -> Arc<Vec<String>> {
        match self.get_peer_id_by_ipv4(ipv4).await {
            Some(peer_id) => self.get_peer_groups(peer_id),
            None => Arc::new(Vec::new()),
        }
    }

    async fn dump(&self) -> String {
        "this route implementation does not support dump".to_string()
    }
}

pub type ArcRoute = Arc<Box<dyn Route + Send + Sync>>;

pub struct MockRoute {}

#[async_trait::async_trait]
impl Route for MockRoute {
    async fn open(&self, _interface: RouteInterfaceBox) -> Result<u8, ()> {
        panic!("mock route")
    }

    async fn close(&self) {
        panic!("mock route")
    }

    async fn get_next_hop(&self, _peer_id: PeerId) -> Option<PeerId> {
        panic!("mock route")
    }

    async fn list_routes(&self) -> Vec<crate::proto::api::instance::Route> {
        panic!("mock route")
    }

    // TODO: rewrite route management, remove this
    async fn list_proxy_cidrs(&self) -> BTreeSet<Ipv4Cidr> {
        unimplemented!()
    }

    // TODO: rewrite route management, remove this
    async fn list_proxy_cidrs_v6(&self) -> BTreeSet<Ipv6Cidr> {
        unimplemented!()
    }

    async fn list_public_ipv6_routes(&self) -> BTreeSet<Ipv6Inet> {
        unimplemented!()
    }

    async fn get_my_public_ipv6_addr(&self) -> Option<Ipv6Inet> {
        panic!("mock route")
    }

    async fn get_peer_info(&self, _peer_id: PeerId) -> Option<RoutePeerInfo> {
        panic!("mock route")
    }

    async fn get_peer_info_last_update_time(&self) -> Instant {
        panic!("mock route")
    }

    fn get_peer_groups(&self, _peer_id: PeerId) -> Arc<Vec<String>> {
        panic!("mock route")
    }
}

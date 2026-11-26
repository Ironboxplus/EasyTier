//! Egress scope identity (MP_SQM_PLAN.md §4.2).
//!
//! An [`EgressScope`] names one physical egress direction (a NIC). The per-scope shaping state lives in `common::egress_quality`;
//! the one send queue of a scope is a CAKE instance in `tunnel::mpquic`
//! (CAKE_SQM_PLAN.md). This module used to hold a token-bucket ledger and
//! governor (reserve/commit/refund) in front of the socket; CAKE_SQM_PLAN.md
//! B4 replaced them with that queue and removed them.

use crate::common::egress_inventory::{EgressSocketBinding, EgressStableId};

/// A stable identity for one physical egress direction.
///
/// `stable_id` holds the platform inventory's own [`EgressStableId`] enum
/// directly instead of a second, independently-formatted string identity:
/// there is exactly one authoritative representation of "which physical
/// interface", so no caller may flatten it with `format!("{:?}", ..)` at a
/// call site and create a de-facto second identity.
///
/// `generation` mirrors `EgressSocketBinding::generation` (the interface's
/// own generation counter across remove/re-add), which is a different
/// counter from `EgressInventorySnapshot::revision` (a snapshot-wide
/// revision bumped by any reconcile, including unrelated interfaces). A
/// budget scope must never be compared against the snapshot revision.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EgressScope {
    pub stable_id: EgressStableId,
    pub direction: EgressDirection,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum EgressDirection {
    Egress,
    Ingress,
}

impl EgressScope {
    /// The single binding -> scope conversion point (MP_SQM_PLAN.md §4.3).
    /// `direction` is caller-supplied because one physical binding covers
    /// both an egress and a (future) ingress budget; `generation` comes from
    /// `EgressSocketBinding::generation` (the interface's own generation
    /// counter), never from `EgressInventorySnapshot::revision` (a
    /// snapshot-wide counter bumped by any reconcile, including unrelated
    /// interfaces) — the two must never be conflated. No other call site may
    /// build an `EgressScope` by re-deriving or re-formatting
    /// `binding.egress`; that would create a second, independently-drifting
    /// identity for the same physical interface.
    pub fn from_binding(binding: &EgressSocketBinding, direction: EgressDirection) -> Self {
        Self {
            stable_id: binding.egress.clone(),
            direction,
            generation: binding.generation,
        }
    }

    /// A second, narrower conversion point (MP_SQM_PLAN.md S1.3 remainder):
    /// for a caller that resolved *which* physical egress routes to a target
    /// via `EgressInventory::best_route_to`, but never bound a real per-NIC
    /// socket for it (a standalone `mpquic://` connector/listener stays bound
    /// to the OS-routed wildcard address; since MP_SQM_PLAN.md S2.14 only
    /// tests build a real [`EgressSocketBinding`]). `stable_id`/`generation` must still come from the
    /// inventory's own snapshot (an interface's `EgressInterfaceSnapshot::
    /// generation`), never re-derived or reformatted, for the same reason
    /// `from_binding` requires it: one authoritative representation of "which
    /// physical interface".
    pub fn from_resolved_route(
        stable_id: EgressStableId,
        generation: u64,
        direction: EgressDirection,
    ) -> Self {
        Self {
            stable_id,
            direction,
            generation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::egress_inventory::RouteResolution;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn binding(netns_inode: u64, ifindex: u32, generation: u64) -> EgressSocketBinding {
        let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        EgressSocketBinding {
            egress: EgressStableId::Linux {
                netns_inode,
                ifindex,
            },
            generation,
            // Deliberately different from `generation`: a scope must track
            // the interface's own generation, never the inventory-wide
            // snapshot revision.
            inventory_revision: generation + 1000,
            runtime_ifindex: ifindex,
            platform_name: format!("eth{ifindex}"),
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 40000),
            route: RouteResolution {
                target,
                requested_egress: None,
                selected_egress: None,
                output_ifindex: ifindex,
                source: None,
                gateway: None,
                metric: None,
                table: None,
                inventory_revision: generation + 1000,
            },
        }
    }

    #[test]
    fn binding_to_scope_is_the_single_conversion_point_and_uses_interface_generation() {
        let bound = binding(7, 2, 4);
        let scope = EgressScope::from_binding(&bound, EgressDirection::Egress);
        assert_eq!(scope.stable_id, bound.egress);
        assert_eq!(scope.direction, EgressDirection::Egress);
        // Must track `binding.generation` (interface generation), never
        // `binding.inventory_revision` (snapshot-wide) or
        // `binding.route.inventory_revision`.
        assert_eq!(scope.generation, 4);
        assert_ne!(scope.generation, bound.inventory_revision);
    }

    #[test]
    fn binding_to_scope_never_collides_across_distinct_interfaces() {
        let same_netns_different_if =
            EgressScope::from_binding(&binding(7, 3, 1), EgressDirection::Egress);
        let same_if_different_netns =
            EgressScope::from_binding(&binding(9, 2, 1), EgressDirection::Egress);
        let same_identity_different_generation =
            EgressScope::from_binding(&binding(7, 2, 2), EgressDirection::Egress);
        let same_identity_different_direction =
            EgressScope::from_binding(&binding(7, 2, 1), EgressDirection::Ingress);
        let baseline = EgressScope::from_binding(&binding(7, 2, 1), EgressDirection::Egress);

        assert_ne!(baseline, same_netns_different_if);
        assert_ne!(baseline, same_if_different_netns);
        assert_ne!(baseline, same_identity_different_generation);
        assert_ne!(baseline, same_identity_different_direction);
        // Same binding fields + same direction round-trips to an identical,
        // stable scope every time.
        assert_eq!(
            baseline,
            EgressScope::from_binding(&binding(7, 2, 1), EgressDirection::Egress)
        );
    }
}

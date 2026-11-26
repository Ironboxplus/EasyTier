#![cfg(target_os = "windows")]

use std::{net::IpAddr, time::Duration};

use easytier::common::{
    egress_inventory::{EgressInventory, EgressInventoryConfig, EgressStableId, RouteError},
    netns::NetNS,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a real Windows host with a live routed interface"]
async fn native_windows_route_lookup_uses_stable_interface_identity() {
    let inventory = EgressInventory::start(
        NetNS::new(None),
        EgressInventoryConfig {
            full_reconcile_interval: Duration::from_secs(3600),
            ..Default::default()
        },
    )
    .await
    .expect("failed to start native Windows egress inventory");
    let snapshot = inventory.snapshot();
    assert!(
        snapshot
            .interfaces
            .keys()
            .any(|id| matches!(id, EgressStableId::Windows { luid, guid } if *luid != 0 && !guid.is_empty())),
        "Windows inventory did not expose a stable LUID/GUID identity"
    );

    let target = std::env::var("EASYTIER_WINDOWS_ROUTE_TEST_TARGET")
        .unwrap_or_else(|_| "1.1.1.1".to_owned())
        .parse::<IpAddr>()
        .expect("invalid EASYTIER_WINDOWS_ROUTE_TEST_TARGET");
    let best = inventory
        .best_route_to(target)
        .await
        .expect("native Windows best-route lookup failed");
    let selected = best
        .selected_egress
        .clone()
        .expect("kernel-selected Windows interface was absent from inventory");
    assert!(matches!(selected, EgressStableId::Windows { .. }));
    assert_ne!(best.output_ifindex, 0);
    assert!(best.source.is_some());
    assert_eq!(best.inventory_revision, snapshot.revision);

    let scoped = inventory
        .route_to(&selected, target)
        .await
        .expect("native Windows egress-scoped route lookup failed");
    assert_eq!(scoped.requested_egress, Some(selected.clone()));
    assert_eq!(scoped.selected_egress, Some(selected.clone()));
    assert_eq!(scoped.output_ifindex, best.output_ifindex);

    let unknown = EgressStableId::Windows {
        luid: u64::MAX,
        guid: "ffffffff-ffff-ffff-ffff-ffffffffffff".to_owned(),
    };
    assert!(matches!(
        inventory.route_to(&unknown, target).await,
        Err(RouteError::UnknownEgress { egress, .. }) if egress == unknown
    ));
}

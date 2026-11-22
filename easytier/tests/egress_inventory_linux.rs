#![cfg(target_os = "linux")]

use std::{
    net::{IpAddr, Ipv4Addr},
    process::Command,
    sync::Arc,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use easytier::{
    common::{
        config::{ConfigLoader, TomlConfigLoader},
        egress_inventory::{
            EgressExclusionReason, EgressInventory, EgressInventoryConfig, EgressInventoryEvent,
            EgressInventoryHealth, EgressInventorySnapshot, EgressKind, EgressStableId,
            InventoryChangeCause, InventoryError, OperState, RouteError, RouteResolution,
        },
        netns::NetNS,
    },
    peers::{
        create_packet_recv_chan,
        peer_manager::{PeerManager, RouteAlgoType},
        rpc_service::PeerManagerRpcService,
    },
    proto::{
        api::instance::{GetEgressInventoryRequest, PeerManageRpc, ResolveEgressRouteRequest},
        rpc_types::controller::BaseController,
    },
};
use serial_test::serial;

static TEST_SEQUENCE: AtomicU32 = AtomicU32::new(0);

struct RealNetns {
    name: String,
    interface_name: String,
}

impl RealNetns {
    fn new() -> Self {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let suffix = (std::process::id() ^ sequence) & 0x00ff_ffff;
        let name = format!("etinv{suffix:06x}");
        let interface_name = format!("ei{suffix:06x}");

        run_ip(&["netns", "add", &name]);
        run_ip(&["-n", &name, "link", "set", "lo", "up"]);

        Self {
            name,
            interface_name,
        }
    }

    fn et_netns(&self) -> NetNS {
        NetNS::new(Some(self.name.clone()))
    }

    fn add_dummy(&self) {
        self.add_dummy_with_index(None);
    }

    fn add_unconfigured_dummy(&self, name: &str) {
        run_ip(&[
            "-n", &self.name, "link", "add", "name", name, "type", "dummy",
        ]);
    }

    fn add_configured_dummy(&self, name: &str, cidr: &str) {
        self.add_unconfigured_dummy(name);
        run_ip(&["-n", &self.name, "addr", "add", cidr, "dev", name]);
        run_ip(&["-n", &self.name, "link", "set", name, "up"]);
    }

    fn delete_namespace(&self) {
        run_ip(&["netns", "del", &self.name]);
    }

    fn add_dummy_with_index(&self, index: Option<u32>) {
        let index_text = index.map(|index| index.to_string());
        let mut args = vec![
            "-n",
            self.name.as_str(),
            "link",
            "add",
            "name",
            self.interface_name.as_str(),
        ];
        if let Some(index_text) = index_text.as_deref() {
            args.extend(["index", index_text]);
        }
        args.extend(["type", "dummy"]);
        run_ip(&args);
        run_ip(&[
            "-n",
            &self.name,
            "addr",
            "add",
            "192.0.2.10/24",
            "dev",
            &self.interface_name,
        ]);
        run_ip(&[
            "-n",
            &self.name,
            "link",
            "set",
            &self.interface_name,
            "mtu",
            "1420",
            "up",
        ]);
    }

    fn remove_dummy(&self) {
        run_ip(&["-n", &self.name, "link", "del", &self.interface_name]);
    }

    fn interface_index(&self) -> u32 {
        let output = run_ip_output(&[
            "-n",
            &self.name,
            "-o",
            "link",
            "show",
            "dev",
            &self.interface_name,
        ]);
        String::from_utf8(output.stdout)
            .expect("ip link output was not UTF-8")
            .split(':')
            .next()
            .expect("ip link output did not contain an interface index")
            .trim()
            .parse()
            .expect("ip link interface index was not numeric")
    }

    fn add_address(&self, cidr: &str) {
        run_ip(&[
            "-n",
            &self.name,
            "addr",
            "add",
            cidr,
            "dev",
            &self.interface_name,
        ]);
    }

    fn remove_address(&self, cidr: &str) {
        run_ip(&[
            "-n",
            &self.name,
            "addr",
            "del",
            cidr,
            "dev",
            &self.interface_name,
        ]);
    }
}

impl Drop for RealNetns {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["netns", "del", &self.name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

fn run_ip(args: &[&str]) {
    let _ = run_ip_output(args);
}

fn run_ip_output(args: &[&str]) -> std::process::Output {
    let output = Command::new("ip")
        .args(args)
        .output()
        .expect("failed to execute iproute2");
    assert!(
        output.status.success(),
        "ip {:?} failed: status={:?}, stdout={}, stderr={}",
        args,
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

async fn recv_reconciled(
    events: &mut tokio::sync::broadcast::Receiver<EgressInventoryEvent>,
) -> EgressInventoryEvent {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await {
                Ok(event @ EgressInventoryEvent::Reconciled { .. }) => return event,
                Ok(EgressInventoryEvent::RefreshFailed { error, .. }) => {
                    panic!("inventory refresh failed during real-system test: {error}")
                }
                Ok(EgressInventoryEvent::WatchFailed { error, .. }) => {
                    panic!("inventory watcher failed during real-system test: {error}")
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    panic!("inventory event receiver lagged by {skipped} events")
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    panic!("inventory event stream closed")
                }
            }
        }
    })
    .await
    .expect("timed out waiting for inventory reconciliation")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(egress_inventory_linux)]
async fn snapshot_reads_real_namespace_interface_metadata() {
    let namespace = RealNetns::new();
    namespace.add_dummy();

    let snapshot = EgressInventory::snapshot_once(namespace.et_netns())
        .await
        .expect("real namespace snapshot failed");
    let interface = snapshot
        .interfaces
        .values()
        .find(|interface| interface.platform_name == namespace.interface_name)
        .expect("real dummy interface missing from inventory snapshot");

    assert_eq!(interface.mtu, Some(1420));
    assert_eq!(interface.oper_state, OperState::Up);
    assert!(interface.addresses.iter().any(|address| {
        address.ip == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)) && address.prefix_len == 24
    }));
    assert!(matches!(
        interface.id,
        EgressStableId::Linux {
            netns_inode,
            ifindex
        } if netns_inode != 0 && ifindex != 0
    ));

    let loopback = snapshot
        .interfaces
        .values()
        .find(|interface| interface.platform_name == "lo")
        .expect("real namespace loopback missing from inventory snapshot");
    assert_eq!(loopback.kind, EgressKind::Loopback);
    assert!(!loopback.is_eligible);
    assert!(
        loopback
            .exclusion_reasons
            .contains(&EgressExclusionReason::Loopback)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(egress_inventory_linux)]
async fn snapshot_excludes_real_down_unaddressed_easytier_interface() {
    let namespace = RealNetns::new();
    let managed_name = format!("et_{}", &namespace.interface_name[2..]);
    namespace.add_unconfigured_dummy(&managed_name);

    let snapshot = EgressInventory::snapshot_once(namespace.et_netns())
        .await
        .expect("real namespace snapshot failed");
    let interface = snapshot
        .interfaces
        .values()
        .find(|interface| interface.platform_name == managed_name)
        .expect("real unconfigured EasyTier interface missing from inventory snapshot");

    assert_eq!(interface.oper_state, OperState::Down);
    assert!(!interface.is_eligible);
    assert!(
        interface
            .exclusion_reasons
            .contains(&EgressExclusionReason::InterfaceDown)
    );
    assert!(
        interface
            .exclusion_reasons
            .contains(&EgressExclusionReason::NoAddress)
    );
    assert!(
        interface
            .exclusion_reasons
            .contains(&EgressExclusionReason::EasyTierManaged)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(egress_inventory_linux)]
async fn manual_and_periodic_refresh_do_not_emit_false_diffs() {
    let namespace = RealNetns::new();
    namespace.add_dummy();
    let inventory = EgressInventory::start(
        namespace.et_netns(),
        EgressInventoryConfig {
            debounce: Duration::from_millis(5),
            full_reconcile_interval: Duration::from_millis(25),
            ..Default::default()
        },
    )
    .await
    .expect("failed to start real namespace inventory");
    let revision = inventory.snapshot().revision;
    let mut events = inventory.subscribe();

    assert!(inventory.request_refresh());
    assert!(
        tokio::time::timeout(Duration::from_millis(150), events.recv())
            .await
            .is_err(),
        "unchanged manual/periodic refresh emitted a false inventory diff"
    );
    assert_eq!(inventory.snapshot().revision, revision);

    drop(inventory);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(egress_inventory_linux)]
async fn missing_namespace_is_reported_for_one_shot_and_live_refresh() {
    let missing_name = format!(
        "etinv-missing-{:06x}",
        (std::process::id() ^ TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)) & 0x00ff_ffff
    );
    let error = EgressInventory::snapshot_once(NetNS::new(Some(missing_name)))
        .await
        .expect_err("missing namespace snapshot unexpectedly succeeded");
    assert!(matches!(error, InventoryError::Namespace(_)));

    let namespace = RealNetns::new();
    namespace.add_dummy();
    let inventory = EgressInventory::start(
        namespace.et_netns(),
        EgressInventoryConfig {
            debounce: Duration::from_millis(5),
            full_reconcile_interval: Duration::from_secs(3600),
            ..Default::default()
        },
    )
    .await
    .expect("failed to start real namespace inventory");
    let revision = inventory.snapshot().revision;
    let mut events = inventory.subscribe();

    namespace.delete_namespace();
    assert!(inventory.request_refresh());
    let event = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await {
                Ok(event @ EgressInventoryEvent::RefreshFailed { .. }) => return event,
                Ok(EgressInventoryEvent::Reconciled { .. }) => continue,
                Ok(EgressInventoryEvent::WatchFailed { error, .. }) => {
                    panic!("inventory watcher failed before refresh test: {error}")
                }
                Err(error) => panic!("inventory event stream failed: {error}"),
            }
        }
    })
    .await
    .expect("timed out waiting for missing-namespace refresh failure");

    match event {
        EgressInventoryEvent::RefreshFailed {
            revision: failed_revision,
            error,
            ..
        } => {
            assert_eq!(failed_revision, revision);
            assert!(!error.is_empty());
        }
        _ => unreachable!(),
    }

    let health = inventory.health();
    assert_eq!(health.consecutive_refresh_failures, 1);
    assert_eq!(
        health.last_refresh_error.as_ref().unwrap().revision,
        revision
    );
    assert!(!health.last_refresh_error.unwrap().message.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(egress_inventory_linux)]
async fn watcher_reconciles_real_interface_add_and_remove() {
    let namespace = RealNetns::new();
    let inventory = EgressInventory::start(
        namespace.et_netns(),
        EgressInventoryConfig {
            debounce: Duration::from_millis(25),
            ..Default::default()
        },
    )
    .await
    .expect("failed to start real namespace inventory");
    let initial_revision = inventory.snapshot().revision;
    let mut events = inventory.subscribe();

    namespace.add_dummy();
    let added_event = recv_reconciled(&mut events).await;
    let (added_revision, added_id) = match added_event {
        EgressInventoryEvent::Reconciled {
            revision,
            causes,
            diff,
            snapshot,
        } => {
            assert!(revision > initial_revision);
            assert!(causes.contains(&InventoryChangeCause::Interface));
            let added_id = diff
                .added
                .iter()
                .find(|id| {
                    snapshot.interfaces.get(*id).is_some_and(|interface| {
                        interface.platform_name == namespace.interface_name
                    })
                })
                .cloned()
                .expect("real interface addition was not represented in inventory diff");
            (revision, added_id)
        }
        _ => unreachable!(),
    };

    namespace.remove_dummy();
    let removed_event = recv_reconciled(&mut events).await;
    match removed_event {
        EgressInventoryEvent::Reconciled {
            revision,
            causes,
            diff,
            snapshot,
        } => {
            assert!(revision > added_revision);
            assert!(causes.contains(&InventoryChangeCause::Interface));
            assert!(diff.removed.contains(&added_id));
            assert!(!snapshot.interfaces.contains_key(&added_id));
        }
        _ => unreachable!(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(egress_inventory_linux)]
async fn watcher_reconciles_real_address_add_and_remove() {
    let namespace = RealNetns::new();
    namespace.add_dummy();
    let inventory = EgressInventory::start(
        namespace.et_netns(),
        EgressInventoryConfig {
            debounce: Duration::from_millis(25),
            ..Default::default()
        },
    )
    .await
    .expect("failed to start real namespace inventory");
    let id = inventory
        .snapshot()
        .interfaces
        .values()
        .find(|interface| interface.platform_name == namespace.interface_name)
        .expect("dummy interface missing from initial snapshot")
        .id
        .clone();
    let mut events = inventory.subscribe();

    namespace.add_address("198.51.100.7/24");
    match recv_reconciled(&mut events).await {
        EgressInventoryEvent::Reconciled {
            causes,
            diff,
            snapshot,
            ..
        } => {
            assert!(causes.contains(&InventoryChangeCause::Address));
            assert!(diff.changed.contains(&id));
            assert!(snapshot.interfaces[&id].addresses.iter().any(|address| {
                address.ip == "198.51.100.7".parse::<IpAddr>().unwrap() && address.prefix_len == 24
            }));
        }
        _ => unreachable!(),
    }

    namespace.remove_address("198.51.100.7/24");
    match recv_reconciled(&mut events).await {
        EgressInventoryEvent::Reconciled {
            causes,
            diff,
            snapshot,
            ..
        } => {
            assert!(causes.contains(&InventoryChangeCause::Address));
            assert!(diff.changed.contains(&id));
            assert!(
                !snapshot.interfaces[&id]
                    .addresses
                    .iter()
                    .any(|address| address.ip == "198.51.100.7".parse::<IpAddr>().unwrap())
            );
        }
        _ => unreachable!(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(egress_inventory_linux)]
async fn watcher_reconciles_real_ipv6_address_add_and_remove() {
    let namespace = RealNetns::new();
    namespace.add_dummy();
    let inventory = EgressInventory::start(
        namespace.et_netns(),
        EgressInventoryConfig {
            debounce: Duration::from_millis(25),
            ..Default::default()
        },
    )
    .await
    .expect("failed to start real namespace inventory");
    let id = inventory
        .snapshot()
        .interfaces
        .values()
        .find(|interface| interface.platform_name == namespace.interface_name)
        .expect("dummy interface missing from initial snapshot")
        .id
        .clone();
    let mut events = inventory.subscribe();
    let ipv6 = "2001:db8::7".parse::<IpAddr>().unwrap();

    namespace.add_address("2001:db8::7/64");
    match recv_reconciled(&mut events).await {
        EgressInventoryEvent::Reconciled {
            causes,
            diff,
            snapshot,
            ..
        } => {
            assert!(causes.contains(&InventoryChangeCause::Address));
            assert!(diff.changed.contains(&id));
            assert!(
                snapshot.interfaces[&id]
                    .addresses
                    .iter()
                    .any(|address| address.ip == ipv6 && address.prefix_len == 64)
            );
        }
        _ => unreachable!(),
    }

    namespace.remove_address("2001:db8::7/64");
    match recv_reconciled(&mut events).await {
        EgressInventoryEvent::Reconciled {
            causes,
            diff,
            snapshot,
            ..
        } => {
            assert!(causes.contains(&InventoryChangeCause::Address));
            assert!(diff.changed.contains(&id));
            assert!(
                !snapshot.interfaces[&id]
                    .addresses
                    .iter()
                    .any(|address| address.ip == ipv6)
            );
        }
        _ => unreachable!(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(egress_inventory_linux)]
async fn ifindex_reuse_increments_generation_for_same_stable_id() {
    let namespace = RealNetns::new();
    namespace.add_dummy();
    let reused_ifindex = namespace.interface_index();
    let inventory = EgressInventory::start(
        namespace.et_netns(),
        EgressInventoryConfig {
            debounce: Duration::from_millis(25),
            ..Default::default()
        },
    )
    .await
    .expect("failed to start real namespace inventory");
    let initial = inventory
        .snapshot()
        .interfaces
        .values()
        .find(|interface| interface.platform_name == namespace.interface_name)
        .expect("dummy interface missing from initial snapshot")
        .clone();
    let mut events = inventory.subscribe();

    namespace.remove_dummy();
    let removed = recv_reconciled(&mut events).await;
    assert!(matches!(
        removed,
        EgressInventoryEvent::Reconciled { ref diff, .. } if diff.removed.contains(&initial.id)
    ));

    namespace.add_dummy_with_index(Some(reused_ifindex));
    match recv_reconciled(&mut events).await {
        EgressInventoryEvent::Reconciled { diff, snapshot, .. } => {
            assert!(diff.added.contains(&initial.id));
            let recreated = &snapshot.interfaces[&initial.id];
            assert_eq!(recreated.runtime_ifindex, reused_ifindex);
            assert!(recreated.generation > initial.generation);
        }
        _ => unreachable!(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(egress_inventory_linux)]
async fn native_route_lookup_honors_kernel_policy_and_egress_scope() {
    let namespace = RealNetns::new();
    namespace.add_dummy();
    let secondary_name = format!("ri{}", &namespace.interface_name[2..]);
    namespace.add_configured_dummy(&secondary_name, "198.51.100.10/24");
    namespace.add_address("2001:db8:1::10/64");
    run_ip(&[
        "-n",
        &namespace.name,
        "addr",
        "add",
        "2001:db8:2::10/64",
        "dev",
        &secondary_name,
    ]);

    run_ip(&[
        "-n",
        &namespace.name,
        "route",
        "add",
        "203.0.113.0/24",
        "dev",
        &namespace.interface_name,
        "src",
        "192.0.2.10",
        "metric",
        "500",
    ]);
    run_ip(&[
        "-n",
        &namespace.name,
        "route",
        "add",
        "table",
        "100",
        "203.0.113.0/24",
        "dev",
        &secondary_name,
        "src",
        "198.51.100.10",
    ]);
    run_ip(&[
        "-n",
        &namespace.name,
        "rule",
        "add",
        "priority",
        "100",
        "to",
        "203.0.113.0/24",
        "lookup",
        "100",
    ]);
    run_ip(&[
        "-n",
        &namespace.name,
        "-6",
        "route",
        "add",
        "2001:db8:ffff::/64",
        "dev",
        &namespace.interface_name,
        "src",
        "2001:db8:1::10",
        "metric",
        "500",
    ]);
    run_ip(&[
        "-n",
        &namespace.name,
        "-6",
        "route",
        "add",
        "table",
        "101",
        "2001:db8:ffff::/64",
        "dev",
        &secondary_name,
        "src",
        "2001:db8:2::10",
    ]);
    run_ip(&[
        "-n",
        &namespace.name,
        "-6",
        "rule",
        "add",
        "priority",
        "101",
        "to",
        "2001:db8:ffff::/64",
        "lookup",
        "101",
    ]);

    let inventory = EgressInventory::start(
        namespace.et_netns(),
        EgressInventoryConfig {
            full_reconcile_interval: Duration::from_secs(3600),
            ..Default::default()
        },
    )
    .await
    .expect("failed to start real namespace inventory");
    let snapshot = inventory.snapshot();
    let secondary = snapshot
        .interfaces
        .values()
        .find(|interface| interface.platform_name == secondary_name)
        .expect("secondary policy-route interface missing from inventory")
        .clone();
    let target = "203.0.113.7".parse::<IpAddr>().unwrap();

    let best = inventory
        .best_route_to(target)
        .await
        .expect("native best-route lookup failed");
    assert_eq!(best.requested_egress, None);
    assert_eq!(best.selected_egress, Some(secondary.id.clone()));
    assert_eq!(best.output_ifindex, secondary.runtime_ifindex);
    assert_eq!(best.source, Some("198.51.100.10".parse().unwrap()));
    assert_eq!(best.table, Some(100));
    assert_eq!(best.inventory_revision, snapshot.revision);

    let scoped = inventory
        .route_to(&secondary.id, target)
        .await
        .expect("native egress-scoped route lookup failed");
    assert_eq!(scoped.requested_egress, Some(secondary.id.clone()));
    assert_eq!(scoped.selected_egress, Some(secondary.id.clone()));
    assert_eq!(scoped.output_ifindex, secondary.runtime_ifindex);
    assert_eq!(scoped.source, Some("198.51.100.10".parse().unwrap()));
    assert_eq!(scoped.table, Some(100));

    let ipv6_target = "2001:db8:ffff::7".parse::<IpAddr>().unwrap();
    let ipv6_best = inventory
        .best_route_to(ipv6_target)
        .await
        .expect("native IPv6 best-route lookup failed");
    assert_eq!(ipv6_best.selected_egress, Some(secondary.id.clone()));
    assert_eq!(ipv6_best.output_ifindex, secondary.runtime_ifindex);
    assert_eq!(ipv6_best.source, Some("2001:db8:2::10".parse().unwrap()));
    assert_eq!(ipv6_best.table, Some(101));

    let ipv6_scoped = inventory
        .route_to(&secondary.id, ipv6_target)
        .await
        .expect("native IPv6 egress-scoped route lookup failed");
    assert_eq!(ipv6_scoped.requested_egress, Some(secondary.id.clone()));
    assert_eq!(ipv6_scoped.selected_egress, Some(secondary.id.clone()));
    assert_eq!(ipv6_scoped.output_ifindex, secondary.runtime_ifindex);
    assert_eq!(ipv6_scoped.source, Some("2001:db8:2::10".parse().unwrap()));
    assert_eq!(ipv6_scoped.table, Some(101));

    let unknown = match secondary.id {
        EgressStableId::Linux {
            netns_inode,
            ifindex,
        } => EgressStableId::Linux {
            netns_inode,
            ifindex: ifindex.saturating_add(10_000),
        },
        _ => unreachable!(),
    };
    assert!(matches!(
        inventory.route_to(&unknown, target).await,
        Err(RouteError::UnknownEgress { egress, .. }) if egress == unknown
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(egress_inventory_linux)]
async fn peer_manager_rpc_exposes_live_inventory_and_scoped_route() {
    let namespace = RealNetns::new();
    namespace.add_dummy();

    let config = TomlConfigLoader::default();
    config.set_netns(Some(namespace.name.clone()));
    let global_ctx = Arc::new(easytier::common::global_ctx::GlobalCtx::new(config));
    let (packet_tx, _packet_rx) = create_packet_recv_chan();
    let peer_manager = Arc::new(PeerManager::new(RouteAlgoType::Ospf, global_ctx, packet_tx));
    peer_manager
        .start_egress_inventory()
        .await
        .expect("peer manager failed to start egress inventory");

    let service = PeerManagerRpcService::new(peer_manager.clone());
    let response = service
        .get_egress_inventory(
            BaseController::default(),
            GetEgressInventoryRequest::default(),
        )
        .await
        .expect("egress inventory RPC failed");
    assert_eq!(response.schema_version, 2);
    let snapshot: EgressInventorySnapshot =
        serde_json::from_str(&response.snapshot_json).expect("invalid inventory RPC JSON");
    let health: EgressInventoryHealth =
        serde_json::from_str(&response.health_json).expect("invalid inventory health RPC JSON");
    assert_eq!(
        health.watch_mode,
        easytier::common::egress_inventory::WatchMode::Native
    );
    assert_eq!(health.consecutive_watch_failures, 0);
    assert_eq!(health.consecutive_refresh_failures, 0);
    assert!(health.last_successful_reconcile_unix_ms > 0);
    let interface = snapshot
        .interfaces
        .values()
        .find(|interface| interface.platform_name == namespace.interface_name)
        .expect("RPC snapshot omitted the real egress interface");

    let target = "192.0.2.77".parse::<IpAddr>().unwrap();
    let response = service
        .resolve_egress_route(
            BaseController::default(),
            ResolveEgressRouteRequest {
                target: target.to_string(),
                egress_id_json: serde_json::to_string(&interface.id)
                    .expect("failed to encode stable egress ID"),
                ..Default::default()
            },
        )
        .await
        .expect("egress route RPC failed");
    assert_eq!(response.schema_version, 1);
    let resolution: RouteResolution =
        serde_json::from_str(&response.resolution_json).expect("invalid route RPC JSON");
    assert_eq!(resolution.target, target);
    assert_eq!(resolution.requested_egress, Some(interface.id.clone()));
    assert_eq!(resolution.selected_egress, Some(interface.id.clone()));
    assert_eq!(resolution.output_ifindex, interface.runtime_ifindex);
    assert_eq!(
        resolution.source,
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
    );
    assert_eq!(resolution.inventory_revision, snapshot.revision);
}

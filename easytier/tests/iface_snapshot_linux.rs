#![cfg(target_os = "linux")]

//! Connecting reads the event-driven interface inventory instead of
//! enumerating interfaces per attempt. Needs root (`ip netns`).

use std::{
    process::Command,
    sync::Arc,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use easytier::{
    common::{
        config::{ConfigLoader, TomlConfigLoader},
        egress_inventory::{EgressInventory, EgressInventoryConfig},
        global_ctx::{ArcGlobalCtx, GlobalCtx},
        netns::NetNS,
        network::interface_enumeration_count,
    },
    connector::create_connector_by_url,
    tunnel::{IpVersion, Tunnel, TunnelError, TunnelListener, tcp::TcpTunnelListener},
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
        let name = format!("etifs{suffix:06x}");
        let interface_name = format!("es{suffix:06x}");

        run_ip(&["netns", "add", &name]);
        run_ip(&["-n", &name, "link", "set", "lo", "up"]);
        run_ip(&[
            "-n",
            &name,
            "link",
            "add",
            "name",
            &interface_name,
            "type",
            "dummy",
        ]);
        run_ip(&[
            "-n",
            &name,
            "addr",
            "add",
            "192.0.2.10/24",
            "dev",
            &interface_name,
        ]);
        run_ip(&["-n", &name, "link", "set", &interface_name, "up"]);

        Self {
            name,
            interface_name,
        }
    }

    fn et_netns(&self) -> NetNS {
        NetNS::new(Some(self.name.clone()))
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
    let output = Command::new("ip")
        .args(args)
        .output()
        .expect("failed to execute iproute2");
    assert!(
        output.status.success(),
        "ip {:?} failed: status={:?}, stderr={}",
        args,
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );
}

async fn global_ctx_with_inventory(namespace: &RealNetns) -> ArcGlobalCtx {
    let config = TomlConfigLoader::default();
    config.set_netns(Some(namespace.name.clone()));
    let global_ctx = Arc::new(GlobalCtx::new(config));
    let inventory = EgressInventory::start(namespace.et_netns(), EgressInventoryConfig::default())
        .await
        .expect("inventory start failed");
    global_ctx.set_egress_inventory(inventory);
    global_ctx
}

/// Listen on `addr` inside the namespace and keep every accepted tunnel open.
async fn listen_and_hold(namespace: &RealNetns, addr: &str) -> u16 {
    let mut listener = TcpTunnelListener::new(format!("tcp://{addr}:0").parse().unwrap());
    namespace
        .et_netns()
        .run_async(|| listener.listen())
        .await
        .expect("listener did not bind");
    let port = listener.local_url().port().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok(tunnel) = listener.accept().await {
            held.push(tunnel);
        }
    });
    port
}

async fn connect_once(
    namespace: &RealNetns,
    global_ctx: &ArcGlobalCtx,
    url: &str,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    let mut connector = create_connector_by_url(url, global_ctx, IpVersion::V4)
        .await
        .expect("connector creation failed");
    namespace.et_netns().run_async(|| connector.connect()).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(iface_snapshot_linux)]
async fn steady_state_connects_never_enumerate_interfaces() {
    const CONNECTS: u64 = 5;
    let namespace = RealNetns::new();
    let global_ctx = global_ctx_with_inventory(&namespace).await;
    let port = listen_and_hold(&namespace, "192.0.2.10").await;
    let url = format!("tcp://192.0.2.10:{port}");

    // The first connect may fill the inventory-derived caches.
    connect_once(&namespace, &global_ctx, &url)
        .await
        .expect("warm-up connect failed");
    // Let the inventory settle after the namespace setup events.
    tokio::time::sleep(Duration::from_secs(1)).await;

    let before = interface_enumeration_count();
    for attempt in 0..CONNECTS {
        connect_once(&namespace, &global_ctx, &url)
            .await
            .unwrap_or_else(|error| panic!("connect {attempt} failed: {error:?}"));
    }
    let enumerations = interface_enumeration_count() - before;

    assert_eq!(
        enumerations, 0,
        "{CONNECTS} steady-state connects enumerated interfaces {enumerations} times"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(iface_snapshot_linux)]
async fn connect_recovers_within_seconds_after_address_handoff() {
    let namespace = RealNetns::new();
    let global_ctx = global_ctx_with_inventory(&namespace).await;
    let old_port = listen_and_hold(&namespace, "192.0.2.10").await;
    connect_once(
        &namespace,
        &global_ctx,
        &format!("tcp://192.0.2.10:{old_port}"),
    )
    .await
    .expect("connect before handoff failed");

    namespace.remove_address("192.0.2.10/24");
    namespace.add_address("198.51.100.10/24");
    let new_port = listen_and_hold(&namespace, "198.51.100.10").await;
    let url = format!("tcp://198.51.100.10:{new_port}");

    // Attempts inside the inventory's debounce window may still see the old
    // address and fail on the bind; they must request a refresh so a later
    // attempt succeeds. Never an unbounded stall on the stale snapshot.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let client = loop {
        match connect_once(&namespace, &global_ctx, &url).await {
            Ok(client) => break client,
            Err(error) if tokio::time::Instant::now() < deadline => {
                tracing_free_note(&error);
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(error) => panic!("no connect on the new address within 5 s: {error:?}"),
        }
    };
    drop(client);
}

fn tracing_free_note(error: &TunnelError) {
    eprintln!("connect attempt during handoff window failed: {error:?}");
}

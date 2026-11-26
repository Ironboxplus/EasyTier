use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Deref,
    panic::AssertUnwindSafe,
    sync::{
        Arc, Mutex as StdMutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(target_os = "windows")]
use network_interface::{
    Addr as SystemAddr, NetworkInterface as SystemNetworkInterface, NetworkInterfaceConfig,
};
use pnet::datalink::NetworkInterface;
#[cfg(target_os = "windows")]
use pnet::{ipnetwork::IpNetwork, util::MacAddr};
use tokio::{
    sync::{Mutex, RwLock},
    task::JoinSet,
};

use crate::proto::peer_rpc::GetIpListResponse;

#[allow(unused_imports)]
use super::{
    egress_inventory::{EgressInterfaceSnapshot, EgressInventory, EgressInventorySnapshot, OperState},
    netns::NetNS,
    stun::StunInfoCollectorTrait,
};

pub const CACHED_IP_LIST_TIMEOUT_SEC: u64 = 60;

/// Without an inventory, attempts within this window share one full collection.
const FALLBACK_COALESCE: Duration = Duration::from_secs(1);
/// A failed bind asks the inventory for a refresh at most this often.
const STALE_BIND_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// Whether an IPv4 interface address can be advertised to another peer as a
/// direct-connect candidate. IPv4 link-local addresses are scoped to one L2
/// segment and must never leave the host's interface inventory.
pub fn is_usable_interface_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && !ip.is_link_local()
}

struct InterfaceFilter {
    iface: NetworkInterface,
}

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    all(target_os = "macos", feature = "macos-ne"),
    target_env = "ohos"
))]
impl InterfaceFilter {
    async fn filter_iface(&self) -> bool {
        true
    }
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
impl InterfaceFilter {
    async fn is_tun_tap_device(&self) -> bool {
        let path = format!("/sys/class/net/{}/tun_flags", self.iface.name);
        tokio::fs::metadata(&path).await.is_ok()
    }

    async fn has_valid_ip(&self) -> bool {
        self.iface
            .ips
            .iter()
            .map(|ip| ip.ip())
            .any(|ip| !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast())
    }

    async fn filter_iface(&self) -> bool {
        tracing::trace!(
            "filter linux iface: {:?}, is_point_to_point: {}, is_loopback: {}, is_up: {}, is_lower_up: {}, is_tun: {}, has_valid_ip: {}",
            self.iface,
            self.iface.is_point_to_point(),
            self.iface.is_loopback(),
            self.iface.is_up(),
            self.iface.is_lower_up(),
            self.is_tun_tap_device().await,
            self.has_valid_ip().await
        );

        !self.iface.is_point_to_point()
            && !self.iface.is_loopback()
            && self.iface.is_up()
            && self.iface.is_lower_up()
            && !self.is_tun_tap_device().await
            && self.has_valid_ip().await
    }
}

// Cache for networksetup command output
#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
static NETWORKSETUP_CACHE: std::sync::OnceLock<Mutex<(String, std::time::Instant)>> =
    std::sync::OnceLock::new();

#[cfg(any(
    all(target_os = "macos", not(feature = "macos-ne")),
    target_os = "freebsd"
))]
impl InterfaceFilter {
    #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
    async fn get_networksetup_output() -> String {
        use anyhow::Context;
        use std::time::{Duration, Instant};
        let cache = NETWORKSETUP_CACHE.get_or_init(|| Mutex::new((String::new(), Instant::now())));
        let mut cache_guard = cache.lock().await;

        // Check if cache is still valid (less than 1 minute old)
        if cache_guard.1.elapsed() < Duration::from_secs(60) && !cache_guard.0.is_empty() {
            return cache_guard.0.clone();
        }

        // Cache is expired or empty, fetch new data
        let stdout = tokio::process::Command::new("networksetup")
            .args(["-listallhardwareports"])
            .output()
            .await
            .with_context(|| "Failed to execute networksetup command")
            .and_then(|output| {
                std::str::from_utf8(&output.stdout)
                    .map(|s| s.to_string())
                    .with_context(|| "Failed to convert networksetup output to string")
            })
            .unwrap_or_else(|e| {
                tracing::error!("Failed to execute networksetup command: {:?}", e);
                String::new()
            });

        // Update cache
        cache_guard.0 = stdout.clone();
        cache_guard.1 = Instant::now();

        stdout
    }

    #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
    async fn is_interface_physical(&self) -> bool {
        let interface_name = &self.iface.name;
        let stdout = Self::get_networksetup_output().await;

        let lines: Vec<&str> = stdout.lines().collect();

        for i in 0..lines.len() {
            let line = lines[i];

            if line.contains("Device:") && line.contains(interface_name) {
                let next_line = lines[i + 1];
                return !next_line.contains("Virtual Interface");
            }
        }

        false
    }

    #[cfg(target_os = "freebsd")]
    async fn is_interface_physical(&self) -> bool {
        // if mac addr is not zero, then it's physical interface
        self.iface.mac.map(|mac| !mac.is_zero()).unwrap_or(false)
    }

    async fn filter_iface(&self) -> bool {
        !self.iface.is_point_to_point()
            && !self.iface.is_loopback()
            && self.iface.is_up()
            && self.is_interface_physical().await
    }
}

#[cfg(target_os = "windows")]
impl InterfaceFilter {
    async fn filter_iface(&self) -> bool {
        tracing::debug!(
            "iface_name: {:?}, p2p: {:?}, is_up: {:?}, iface: {:?}",
            self.iface.name,
            self.iface.is_point_to_point(),
            self.iface.is_up(),
            self.iface
        );
        !self.iface.is_point_to_point()
            && !self.iface.is_loopback()
            && self
                .iface
                .ips
                .iter()
                .map(|ip| ip.ip())
                .any(|ip| !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast())
            && self.iface.mac.map(|mac| !mac.is_zero()).unwrap_or(false)
    }
}

pub async fn local_ipv4() -> std::io::Result<std::net::Ipv4Addr> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect("8.8.8.8:80").await?;
    let addr = socket.local_addr()?;
    match addr.ip() {
        std::net::IpAddr::V4(ip) => Ok(ip),
        std::net::IpAddr::V6(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no ipv4 address",
        )),
    }
}

pub async fn local_ipv6() -> std::io::Result<std::net::Ipv6Addr> {
    let socket = tokio::net::UdpSocket::bind("[::]:0").await?;
    socket
        .connect("[2001:4860:4860:0000:0000:0000:0000:8888]:80")
        .await?;
    let addr = socket.local_addr()?;
    match addr.ip() {
        std::net::IpAddr::V6(ip) => Ok(ip),
        std::net::IpAddr::V4(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no ipv4 address",
        )),
    }
}

static INTERFACE_ENUMERATIONS: AtomicU64 = AtomicU64::new(0);

/// Record one full interface enumeration (a getifaddrs/netlink dump plus a
/// per-interface lookup, hundreds of syscalls on a phone with 40+ interfaces).
pub(crate) fn note_interface_enumeration() {
    INTERFACE_ENUMERATIONS.fetch_add(1, Ordering::Relaxed);
}

/// Full interface enumerations done by this process so far. Tests use the
/// delta to prove a code path reads the inventory snapshot instead.
#[doc(hidden)]
pub fn interface_enumeration_count() -> u64 {
    INTERFACE_ENUMERATIONS.load(Ordering::Relaxed)
}

/// Every interface of the current network namespace. Windows goes through
/// `network-interface` (with a pnet fallback), everything else through pnet.
pub(crate) fn enumerate_interfaces() -> Vec<NetworkInterface> {
    note_interface_enumeration();
    #[cfg(target_os = "windows")]
    {
        IPCollector::collect_interfaces_windows()
    }
    #[cfg(not(target_os = "windows"))]
    {
        pnet::datalink::interfaces()
    }
}

/// What the connect path knows about the interfaces of one network namespace:
/// the event-driven inventory it reads, and the addresses derived from the
/// snapshot revision it last saw. Links are also listed process-wide so code
/// without a collector at hand (the device lookup in `bind`) can read the
/// same snapshots.
struct InventoryLink {
    net_ns: NetNS,
    state: StdMutex<LinkState>,
    /// Used only while no inventory is attached.
    fallback: Mutex<Option<(Instant, GetIpListResponse)>>,
}

#[derive(Default)]
struct LinkState {
    inventory: Option<EgressInventory>,
    /// Inode of the namespace the inventory describes, to match the
    /// namespace of the thread that binds a socket.
    netns_id: Option<u64>,
    derived: Option<(u64, GetIpListResponse)>,
    last_stale_refresh: Option<Instant>,
}

static INVENTORY_LINKS: StdMutex<Vec<Weak<InventoryLink>>> = StdMutex::new(Vec::new());

impl InventoryLink {
    fn new(net_ns: NetNS) -> Arc<Self> {
        let link = Arc::new(Self {
            net_ns,
            state: StdMutex::new(LinkState::default()),
            fallback: Mutex::new(None),
        });
        let mut links = INVENTORY_LINKS.lock().unwrap();
        links.retain(|link| link.strong_count() > 0);
        links.push(Arc::downgrade(&link));
        link
    }

    fn inventory(&self) -> Option<EgressInventory> {
        self.state.lock().unwrap().inventory.clone()
    }

    fn memo(&self, revision: u64) -> Option<GetIpListResponse> {
        match &self.state.lock().unwrap().derived {
            Some((memo_revision, derived)) if *memo_revision == revision => Some(derived.clone()),
            _ => None,
        }
    }

    fn store(&self, revision: u64, derived: GetIpListResponse) {
        self.state.lock().unwrap().derived = Some((revision, derived));
    }

    fn in_namespace(&self, current: Option<u64>) -> bool {
        #[cfg(target_os = "linux")]
        {
            current.is_some() && self.state.lock().unwrap().netns_id == current
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = current;
            true
        }
    }

    /// A bind failed because the address is gone: the snapshot is behind the
    /// system. Ask for a refresh (the next attempt reads the new snapshot) and
    /// drop the coalesced fallback result.
    fn note_stale_bind(&self) {
        let inventory = {
            let mut state = self.state.lock().unwrap();
            if state
                .last_stale_refresh
                .is_some_and(|last| last.elapsed() < STALE_BIND_REFRESH_INTERVAL)
            {
                return;
            }
            state.last_stale_refresh = Some(Instant::now());
            state.inventory.clone()
        };
        if let Some(inventory) = inventory {
            inventory.request_refresh();
        }
        if let Ok(mut fallback) = self.fallback.try_lock() {
            *fallback = None;
        }
    }
}

fn live_links() -> Vec<Arc<InventoryLink>> {
    let mut links = INVENTORY_LINKS.lock().unwrap();
    links.retain(|link| link.strong_count() > 0);
    links.iter().filter_map(Weak::upgrade).collect()
}

/// Inode of the network namespace the calling thread is in. `/proc/self` would
/// name the main thread's namespace, which differs inside `NetNS::guard`.
fn current_thread_netns_id() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/thread-self/ns/net")
            .ok()
            .map(|meta| meta.ino())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn netns_id_of(net_ns: &NetNS) -> Option<u64> {
    std::panic::catch_unwind(AssertUnwindSafe(|| net_ns.run(current_thread_netns_id)))
        .ok()
        .flatten()
}

/// A bind failed with "address not available". Every attached inventory is
/// refreshed (rate limited); a refresh is one debounced enumeration.
pub(crate) fn note_stale_bind_address() {
    for link in live_links() {
        link.note_stale_bind();
    }
}

/// The name of the interface that holds `ip`, read from the inventory snapshot
/// of the calling thread's network namespace. `None` when no inventory covers
/// this namespace or the snapshot does not know the address (it is then
/// refreshed, and the caller falls back to one full enumeration).
pub(crate) fn interface_name_from_inventory(ip: &IpAddr) -> Option<String> {
    let current = current_thread_netns_id();
    let links: Vec<_> = live_links()
        .into_iter()
        .filter(|link| link.inventory().is_some() && link.in_namespace(current))
        .collect();
    for link in &links {
        let snapshot = link.inventory()?.snapshot();
        let name = snapshot
            .interfaces
            .values()
            .find(|interface| interface.addresses.iter().any(|addr| addr.ip == *ip))
            .map(|interface| interface.platform_name.clone());
        if name.is_some() {
            return name;
        }
    }
    for link in &links {
        link.note_stale_bind();
    }
    None
}

/// Whether the platform's old `InterfaceFilter` would offer this interface as
/// a bind candidate. Linux checks the flags pnet used to read (point-to-point,
/// tun/tap) in sysfs; both are fixed for the life of an interface.
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
fn interface_is_bind_candidate(interface: &EgressInterfaceSnapshot) -> bool {
    const IFF_POINTOPOINT: u32 = 0x10;
    let sysfs = |file: &str| format!("/sys/class/net/{}/{file}", interface.platform_name);
    let point_to_point = std::fs::read_to_string(sysfs("flags"))
        .ok()
        .and_then(|flags| u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).ok())
        .is_some_and(|flags| flags & IFF_POINTOPOINT != 0);
    interface.oper_state == OperState::Up
        && interface.kind != super::egress_inventory::EgressKind::Loopback
        && has_valid_ip(interface)
        && !point_to_point
        && !std::path::Path::new(&sysfs("tun_flags")).exists()
}

#[cfg(target_os = "windows")]
fn interface_is_bind_candidate(interface: &EgressInterfaceSnapshot) -> bool {
    use pnet::util::MacAddr;
    has_valid_ip(interface)
        && interface
            .hardware_address
            .as_deref()
            .and_then(|mac| mac.parse::<MacAddr>().ok())
            .is_some_and(|mac| !mac.is_zero())
}

#[allow(dead_code)]
fn has_valid_ip(interface: &EgressInterfaceSnapshot) -> bool {
    interface
        .addresses
        .iter()
        .any(|addr| !addr.ip.is_loopback() && !addr.ip.is_unspecified() && !addr.ip.is_multicast())
}

/// The interface addresses a new socket may bind, from one snapshot. IPv4
/// comes from interfaces `candidate` accepts; IPv6 from every interface, as
/// the enumeration it replaces did.
#[allow(dead_code)]
fn derive_interface_addrs(
    snapshot: &EgressInventorySnapshot,
    candidate: impl Fn(&EgressInterfaceSnapshot) -> bool,
) -> GetIpListResponse {
    let mut ret = GetIpListResponse::default();
    for interface in snapshot.interfaces.values() {
        if !candidate(interface) {
            continue;
        }
        for addr in &interface.addresses {
            if let IpAddr::V4(v4) = addr.ip
                && is_usable_interface_ipv4(v4)
            {
                ret.interface_ipv4s.push(v4.into());
            }
        }
    }
    for interface in snapshot.interfaces.values() {
        for addr in &interface.addresses {
            if let IpAddr::V6(v6) = addr.ip
                && !(v6.is_multicast() || v6.is_loopback() || v6.is_unicast_link_local())
            {
                ret.interface_ipv6s.push(v6.into());
            }
        }
    }
    ret
}

/// Source addresses of the default routes. A route lookup, not an
/// enumeration: it also finds the egress a filter rejected (Android's cellular
/// interface) and follows a default-network switch that changed no address.
fn probe_default_route_addrs(net_ns: &NetNS) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    fn probe(bind: &str, target: &str) -> Option<IpAddr> {
        let socket = std::net::UdpSocket::bind(bind).ok()?;
        socket.connect(target).ok()?;
        socket.local_addr().ok().map(|addr| addr.ip())
    }
    let _g = net_ns.guard();
    let v4 = match probe("0.0.0.0:0", "8.8.8.8:80") {
        Some(IpAddr::V4(ip)) => Some(ip),
        _ => None,
    };
    let v6 = match probe("[::]:0", "[2001:4860:4860:0000:0000:0000:0000:8888]:80") {
        Some(IpAddr::V6(ip)) => Some(ip),
        _ => None,
    };
    (v4, v6)
}

fn add_default_route_addrs(
    ret: &mut GetIpListResponse,
    (v4, v6): (Option<Ipv4Addr>, Option<Ipv6Addr>),
) {
    if let Some(v4_addr) = v4
        && is_usable_interface_ipv4(v4_addr)
        && !ret.interface_ipv4s.contains(&v4_addr.into())
    {
        ret.interface_ipv4s.push(v4_addr.into());
    }
    if let Some(v6_addr) = v6
        && !ret.interface_ipv6s.contains(&v6_addr.into())
    {
        ret.interface_ipv6s.push(v6_addr.into());
    }
}

pub struct IPCollector {
    cached_ip_list: Arc<RwLock<GetIpListResponse>>,
    collect_ip_task: Mutex<JoinSet<()>>,
    net_ns: NetNS,
    stun_info_collector: Arc<Box<dyn StunInfoCollectorTrait>>,
    link: Arc<InventoryLink>,
}

impl IPCollector {
    pub fn new<T: StunInfoCollectorTrait + 'static>(net_ns: NetNS, stun_info_collector: T) -> Self {
        Self {
            cached_ip_list: Arc::new(RwLock::new(GetIpListResponse::default())),
            collect_ip_task: Mutex::new(JoinSet::new()),
            link: InventoryLink::new(net_ns.clone()),
            net_ns,
            stun_info_collector: Arc::new(Box::new(stun_info_collector)),
        }
    }

    /// Let [`Self::collect_current_ip_addrs`] and the device lookup of `bind`
    /// read this inventory's snapshot instead of enumerating interfaces.
    /// Only the first inventory is kept.
    pub async fn attach_inventory(&self, inventory: EgressInventory) {
        if self.link.inventory().is_some() {
            return;
        }
        // The namespace switch must not nest in the caller's guard.
        let net_ns = self.net_ns.clone();
        let netns_id = tokio::task::spawn_blocking(move || netns_id_of(&net_ns))
            .await
            .ok()
            .flatten();
        let mut state = self.link.state.lock().unwrap();
        if state.inventory.is_none() {
            state.inventory = Some(inventory);
            state.netns_id = netns_id;
        }
    }

    pub async fn collect_ip_addrs(&self) -> GetIpListResponse {
        let mut task = self.collect_ip_task.lock().await;
        if task.is_empty() {
            let cached_ip_list = self.cached_ip_list.clone();
            *cached_ip_list.write().await =
                Self::do_collect_local_ip_addrs(self.net_ns.clone()).await;
            let net_ns = self.net_ns.clone();
            let stun_info_collector = self.stun_info_collector.clone();
            let cached_ip_list = self.cached_ip_list.clone();
            task.spawn(async move {
                let mut last_fetch_iface_time = std::time::Instant::now();
                loop {
                    if last_fetch_iface_time.elapsed().as_secs() > CACHED_IP_LIST_TIMEOUT_SEC {
                        let ifaces = Self::do_collect_local_ip_addrs(net_ns.clone()).await;
                        *cached_ip_list.write().await = ifaces;
                        last_fetch_iface_time = std::time::Instant::now();
                    }

                    let stun_info = stun_info_collector.get_stun_info();
                    {
                        let mut cached = cached_ip_list.write().await;
                        Self::merge_public_ips(&mut cached, &stun_info.public_ip);
                    }

                    tracing::debug!(
                        "got public ip: {:?}, {:?}",
                        cached_ip_list.read().await.public_ipv4,
                        cached_ip_list.read().await.public_ipv6
                    );

                    let sleep_sec = if cached_ip_list.read().await.public_ipv4.is_some() {
                        CACHED_IP_LIST_TIMEOUT_SEC
                    } else {
                        3
                    };
                    tokio::time::sleep(std::time::Duration::from_secs(sleep_sec)).await;
                }
            });
        }

        self.cached_ip_list.read().await.deref().clone()
    }

    /// Return the current interface addresses for a new socket bind.
    ///
    /// The cached list above is for peer advertisement and may legitimately
    /// lag a link handoff. A fresh transport must not bind an address that has
    /// already been removed, so this follows the inventory's snapshot, which
    /// the system's address and route events keep current. The addresses are
    /// derived once per snapshot revision; only the default-route probe runs
    /// per call. Without an inventory this collects in full, shared between
    /// attempts within one second.
    pub async fn collect_current_ip_addrs(&self) -> GetIpListResponse {
        let mut current = match self.link.inventory() {
            Some(inventory) => self.addrs_from_snapshot(&inventory).await,
            None => self.collect_coalesced().await,
        };
        Self::merge_public_ips(
            &mut current,
            &self.stun_info_collector.get_stun_info().public_ip,
        );
        current
    }

    async fn addrs_from_snapshot(&self, inventory: &EgressInventory) -> GetIpListResponse {
        let snapshot = inventory.snapshot();
        let mut ret = match self.link.memo(snapshot.revision) {
            Some(derived) => derived,
            None => {
                let derived = self.derive_interface_addrs(&snapshot).await;
                self.link.store(snapshot.revision, derived.clone());
                derived
            }
        };
        // A route lookup in a namespace-local thread: the namespace switch
        // must not nest in this task's thread.
        let net_ns = self.net_ns.clone();
        let probed = tokio::task::spawn_blocking(move || probe_default_route_addrs(&net_ns)).await;
        if let Ok(probed) = probed {
            add_default_route_addrs(&mut ret, probed);
        }
        ret
    }

    #[cfg(any(
        target_os = "windows",
        all(target_os = "linux", not(target_env = "ohos"))
    ))]
    async fn derive_interface_addrs(&self, snapshot: &EgressInventorySnapshot) -> GetIpListResponse {
        derive_interface_addrs(snapshot, interface_is_bind_candidate)
    }

    /// macOS and FreeBSD filter on facts the snapshot does not carry (the
    /// hardware port list), so they enumerate once per snapshot revision.
    #[cfg(not(any(
        target_os = "windows",
        all(target_os = "linux", not(target_env = "ohos"))
    )))]
    async fn derive_interface_addrs(
        &self,
        _snapshot: &EgressInventorySnapshot,
    ) -> GetIpListResponse {
        Self::collect_interface_addrs_by_enumeration(self.net_ns.clone()).await
    }

    async fn collect_coalesced(&self) -> GetIpListResponse {
        let mut fallback = self.link.fallback.lock().await;
        if let Some((at, collected)) = fallback.as_ref()
            && at.elapsed() < FALLBACK_COALESCE
        {
            return collected.clone();
        }
        let collected = Self::do_collect_local_ip_addrs(self.net_ns.clone()).await;
        *fallback = Some((Instant::now(), collected.clone()));
        collected
    }

    fn merge_public_ips(result: &mut GetIpListResponse, ips: &[String]) {
        for ip in ips {
            match ip.parse::<IpAddr>() {
                Ok(IpAddr::V4(ip)) => {
                    result.public_ipv4.replace(ip.into());
                }
                Ok(IpAddr::V6(ip)) => {
                    result.public_ipv6.replace(ip.into());
                }
                Err(_) => {}
            }
        }
    }

    pub async fn collect_interfaces(net_ns: NetNS, filter: bool) -> Vec<NetworkInterface> {
        let _g = net_ns.guard();
        let ifaces = enumerate_interfaces();
        let mut ret = vec![];
        for iface in ifaces {
            let f = InterfaceFilter {
                iface: iface.clone(),
            };

            if filter && !f.filter_iface().await {
                continue;
            }

            ret.push(iface);
        }

        ret
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn collect_interfaces_windows() -> Vec<NetworkInterface> {
        match SystemNetworkInterface::show() {
            Ok(ifaces) => ifaces
                .into_iter()
                .map(Self::convert_windows_interface)
                .collect(),
            Err(e) => {
                tracing::warn!(
                    ?e,
                    "failed to enumerate interfaces via network-interface, falling back to pnet"
                );
                match std::panic::catch_unwind(pnet::datalink::interfaces) {
                    Ok(ifaces) => ifaces,
                    Err(_) => {
                        tracing::error!(
                            "failed to enumerate interfaces via both network-interface and pnet"
                        );
                        Vec::new()
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn convert_windows_interface(iface: SystemNetworkInterface) -> NetworkInterface {
        let mac = iface.mac_addr.as_deref().and_then(|mac| {
            mac.parse::<MacAddr>()
                .map_err(|e| {
                    tracing::debug!(iface = %iface.name, mac, ?e, "failed to parse interface mac")
                })
                .ok()
        });

        let ips = iface
            .addr
            .into_iter()
            .filter_map(Self::convert_windows_interface_addr)
            .collect();

        NetworkInterface {
            name: iface.name,
            description: String::new(),
            index: iface.index,
            mac,
            ips,
            // pnet does not populate Windows flags either, so keep the existing semantics.
            flags: 0,
        }
    }

    #[cfg(target_os = "windows")]
    fn convert_windows_interface_addr(addr: SystemAddr) -> Option<IpNetwork> {
        match addr {
            SystemAddr::V4(addr) => {
                let netmask = addr
                    .netmask
                    .map(IpAddr::V4)
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(255, 255, 255, 255)));
                IpNetwork::with_netmask(IpAddr::V4(addr.ip), netmask)
                    .map_err(|e| {
                        tracing::debug!(ip = %addr.ip, ?addr.netmask, ?e, "failed to convert ipv4")
                    })
                    .ok()
            }
            SystemAddr::V6(addr) => {
                let netmask = addr
                    .netmask
                    .map(IpAddr::V6)
                    .unwrap_or(IpAddr::V6(std::net::Ipv6Addr::from(u128::MAX)));
                IpNetwork::with_netmask(IpAddr::V6(addr.ip), netmask)
                    .map_err(|e| {
                        tracing::debug!(ip = %addr.ip, ?addr.netmask, ?e, "failed to convert ipv6")
                    })
                    .ok()
            }
        }
    }

    #[tracing::instrument(skip(net_ns))]
    async fn do_collect_local_ip_addrs(net_ns: NetNS) -> GetIpListResponse {
        #[cfg(target_os = "linux")]
        {
            // setns is thread-local. Like upstream collect_local_ip_addrs,
            // keep the guard and every await on a namespace-local runtime.
            return tokio::task::spawn_blocking(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build namespace-local runtime");
                let collect_ns = net_ns.clone();
                net_ns.run(move || {
                    runtime.block_on(Self::collect_local_ip_addrs_in_namespace(collect_ns))
                })
            })
            .await
            .expect("namespace-local address collection panicked");
        }
        #[cfg(not(target_os = "linux"))]
        Self::collect_local_ip_addrs_in_namespace(net_ns).await
    }

    async fn collect_local_ip_addrs_in_namespace(net_ns: NetNS) -> GetIpListResponse {
        let mut ret = Self::collect_interface_addrs_by_enumeration(net_ns.clone()).await;

        // The enumeration's guards switched back on drop; probe inside the namespace.
        let _g = net_ns.guard();
        if let Ok(v4_addr) = local_ipv4().await {
            tracing::trace!("got local ipv4: {}", v4_addr);
            if is_usable_interface_ipv4(v4_addr) && !ret.interface_ipv4s.contains(&v4_addr.into()) {
                ret.interface_ipv4s.push(v4_addr.into());
            }
        }

        if let Ok(v6_addr) = local_ipv6().await {
            tracing::trace!("got local ipv6: {}", v6_addr);
            if !ret.interface_ipv6s.contains(&v6_addr.into()) {
                ret.interface_ipv6s.push(v6_addr.into());
            }
        }

        ret
    }

    /// Enumerate the namespace's interfaces and filter them (twice, as the
    /// IPv4 and IPv6 lists use different filters).
    async fn collect_interface_addrs_by_enumeration(net_ns: NetNS) -> GetIpListResponse {
        let mut ret = GetIpListResponse::default();

        let ifaces = Self::collect_interfaces(net_ns.clone(), true).await;
        let _g = net_ns.guard();
        for iface in ifaces {
            for ip in iface.ips {
                let ip: std::net::IpAddr = ip.ip();
                if let std::net::IpAddr::V4(v4) = ip {
                    if !is_usable_interface_ipv4(v4) {
                        continue;
                    }
                    ret.interface_ipv4s.push(v4.into());
                }
            }
        }

        let ifaces = Self::collect_interfaces(net_ns.clone(), false).await;
        let _g = net_ns.guard();
        for iface in ifaces {
            for ip in iface.ips {
                let ip: std::net::IpAddr = ip.ip();
                if let std::net::IpAddr::V6(v6) = ip {
                    if v6.is_multicast() || v6.is_loopback() || v6.is_unicast_link_local() {
                        continue;
                    }
                    ret.interface_ipv6s.push(v6.into());
                }
            }
        }

        ret
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, net::IpAddr};

    use super::*;
    use crate::common::egress_inventory::{
        EgressInventoryConfig, EgressKind, EgressStableId, InterfaceAddress, WatchMode,
    };
    use crate::common::stun::MockStunInfoCollector;
    use crate::proto::common::NatType;

    fn test_interface(
        ifindex: u32,
        name: &str,
        oper_state: OperState,
        kind: EgressKind,
        addresses: &[&str],
    ) -> EgressInterfaceSnapshot {
        let id = EgressStableId::Linux {
            netns_inode: 1,
            ifindex,
        };
        EgressInterfaceSnapshot {
            id,
            revision: 1,
            generation: 1,
            platform_name: name.to_owned(),
            display_name: name.to_owned(),
            aliases: vec![name.to_owned()],
            hardware_address: None,
            runtime_ifindex: ifindex,
            kind,
            oper_state,
            addresses: addresses
                .iter()
                .map(|ip| InterfaceAddress {
                    ip: ip.parse::<IpAddr>().unwrap(),
                    prefix_len: 24,
                })
                .collect(),
            mtu: Some(1500),
            transmit_speed_bps: None,
            receive_speed_bps: None,
            is_eligible: true,
            exclusion_reasons: Vec::new(),
            watch_mode: WatchMode::Native,
        }
    }

    fn test_snapshot(interfaces: Vec<EgressInterfaceSnapshot>) -> EgressInventorySnapshot {
        EgressInventorySnapshot {
            revision: 1,
            observed_at_unix_ms: 1,
            interfaces: interfaces
                .into_iter()
                .map(|interface| (interface.id.clone(), interface))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    #[test]
    fn snapshot_derivation_matches_the_enumeration_filters() {
        let snapshot = test_snapshot(vec![
            test_interface(
                1,
                "lo",
                OperState::Up,
                EgressKind::Loopback,
                &["127.0.0.1", "::1"],
            ),
            test_interface(
                2,
                "eth0",
                OperState::Up,
                EgressKind::Unknown,
                &["192.168.1.5", "169.254.9.9", "2001:db8::5", "fe80::1"],
            ),
            test_interface(
                3,
                "wlan0",
                OperState::Down,
                EgressKind::Unknown,
                &["10.0.0.7", "2001:db8::7"],
            ),
        ]);

        let derived = derive_interface_addrs(&snapshot, |interface| {
            interface.oper_state == OperState::Up && interface.kind != EgressKind::Loopback
        });

        // IPv4 only from interfaces the filter accepts, never link-local;
        // IPv6 from every interface, never loopback or link-local.
        assert_eq!(
            derived.interface_ipv4s,
            vec![Ipv4Addr::new(192, 168, 1, 5).into()]
        );
        assert_eq!(
            derived.interface_ipv6s,
            vec![
                "2001:db8::5".parse::<Ipv6Addr>().unwrap().into(),
                "2001:db8::7".parse::<Ipv6Addr>().unwrap().into(),
            ]
        );
    }

    #[test]
    fn derived_addresses_are_kept_per_snapshot_revision() {
        let link = InventoryLink::new(NetNS::new(None));
        assert!(link.memo(1).is_none());

        let mut derived = GetIpListResponse::default();
        derived.interface_ipv4s.push(Ipv4Addr::new(192, 0, 2, 1).into());
        link.store(1, derived.clone());

        assert_eq!(link.memo(1), Some(derived));
        assert!(link.memo(2).is_none(), "a new revision must derive again");
    }

    #[tokio::test]
    async fn current_addresses_after_the_first_read_do_not_enumerate() {
        let inventory = EgressInventory::start(NetNS::new(None), EgressInventoryConfig::default())
            .await
            .unwrap();
        let collector = IPCollector::new(
            NetNS::new(None),
            MockStunInfoCollector {
                udp_nat_type: NatType::Unknown,
            },
        );
        collector.attach_inventory(inventory).await;

        collector.collect_current_ip_addrs().await;
        let before = interface_enumeration_count();
        for _ in 0..5 {
            collector.collect_current_ip_addrs().await;
        }
        assert_eq!(
            interface_enumeration_count(),
            before,
            "an unchanged snapshot must not trigger enumeration"
        );
    }

    #[tokio::test]
    async fn without_an_inventory_attempts_within_a_second_share_one_collection() {
        let collector = IPCollector::new(
            NetNS::new(None),
            MockStunInfoCollector {
                udp_nat_type: NatType::Unknown,
            },
        );
        collector.collect_current_ip_addrs().await;
        let before = interface_enumeration_count();
        for _ in 0..5 {
            collector.collect_current_ip_addrs().await;
        }
        assert_eq!(interface_enumeration_count(), before);
    }

    #[test]
    fn interface_ipv4_advertisement_rejects_link_local_but_keeps_lan_addresses() {
        assert!(!is_usable_interface_ipv4("169.254.45.58".parse().unwrap()));
        assert!(is_usable_interface_ipv4("192.168.6.159".parse().unwrap()));
    }
}

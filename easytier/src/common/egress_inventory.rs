use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

use super::netns::NetNS;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EgressStableId {
    Linux {
        netns_inode: u64,
        ifindex: u32,
    },
    Windows {
        luid: u64,
        guid: String,
    },
    MacOs {
        ifindex: u32,
        bsd_name: String,
    },
    Android {
        network_handle: Option<u64>,
        ifindex: Option<u32>,
    },
    Fallback {
        platform: String,
        opaque: String,
    },
}

impl EgressStableId {
    fn runtime_ifindex(&self) -> Option<u32> {
        match self {
            Self::Linux { ifindex, .. } | Self::MacOs { ifindex, .. } => Some(*ifindex),
            Self::Android { ifindex, .. } => *ifindex,
            Self::Windows { .. } | Self::Fallback { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct InterfaceAddress {
    pub ip: IpAddr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperState {
    Up,
    Down,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressKind {
    Physical,
    Virtual,
    Loopback,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressExclusionReason {
    InterfaceDown,
    NoAddress,
    Loopback,
    EasyTierManaged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchMode {
    OneShot,
    Native,
    PollingFallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteResolution {
    pub target: IpAddr,
    pub requested_egress: Option<EgressStableId>,
    pub selected_egress: Option<EgressStableId>,
    pub output_ifindex: u32,
    pub source: Option<IpAddr>,
    pub gateway: Option<IpAddr>,
    pub metric: Option<u32>,
    pub table: Option<u32>,
    pub inventory_revision: u64,
}

/// Immutable identity attached to a UDP socket created for one concrete
/// egress. Punch/STUN code can pass the socket onward without re-enumerating
/// interfaces or guessing the NIC from the eventual local address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressSocketBinding {
    pub egress: EgressStableId,
    pub generation: u64,
    pub inventory_revision: u64,
    pub runtime_ifindex: u32,
    pub platform_name: String,
    pub local_addr: SocketAddr,
    pub route: RouteResolution,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressInterfaceSnapshot {
    pub id: EgressStableId,
    pub revision: u64,
    pub generation: u64,
    pub platform_name: String,
    pub display_name: String,
    pub aliases: Vec<String>,
    pub hardware_address: Option<String>,
    pub runtime_ifindex: u32,
    pub kind: EgressKind,
    pub oper_state: OperState,
    pub addresses: Vec<InterfaceAddress>,
    pub mtu: Option<u32>,
    pub transmit_speed_bps: Option<u64>,
    pub receive_speed_bps: Option<u64>,
    pub is_eligible: bool,
    pub exclusion_reasons: Vec<EgressExclusionReason>,
    pub watch_mode: WatchMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressInventorySnapshot {
    pub revision: u64,
    pub observed_at_unix_ms: u64,
    #[serde(
        serialize_with = "serialize_interface_map",
        deserialize_with = "deserialize_interface_map"
    )]
    pub interfaces: BTreeMap<EgressStableId, EgressInterfaceSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryObservedError {
    pub revision: u64,
    pub observed_at_unix_ms: u64,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressInventoryHealth {
    pub watch_mode: WatchMode,
    pub consecutive_watch_failures: u64,
    pub consecutive_refresh_failures: u64,
    pub last_watch_error: Option<InventoryObservedError>,
    pub last_refresh_error: Option<InventoryObservedError>,
    pub last_successful_reconcile_unix_ms: u64,
}

impl EgressInventoryHealth {
    fn new(watch_mode: WatchMode, observed_at_unix_ms: u64) -> Self {
        Self {
            watch_mode,
            consecutive_watch_failures: 0,
            consecutive_refresh_failures: 0,
            last_watch_error: None,
            last_refresh_error: None,
            last_successful_reconcile_unix_ms: observed_at_unix_ms,
        }
    }

    fn record_watch_error(&mut self, revision: u64, failure: &WatchFailure) {
        self.consecutive_watch_failures = self.consecutive_watch_failures.saturating_add(1);
        if failure.fatal {
            self.watch_mode = WatchMode::PollingFallback;
        }
        self.last_watch_error = Some(InventoryObservedError {
            revision,
            observed_at_unix_ms: unix_time_ms(),
            message: failure.error.clone(),
        });
    }

    fn record_watcher_signal_success(&mut self) {
        self.consecutive_watch_failures = 0;
    }

    fn record_refresh_error(&mut self, revision: u64, error: String) {
        self.consecutive_refresh_failures = self.consecutive_refresh_failures.saturating_add(1);
        self.last_refresh_error = Some(InventoryObservedError {
            revision,
            observed_at_unix_ms: unix_time_ms(),
            message: error,
        });
    }

    fn record_refresh_success(&mut self, observed_at_unix_ms: u64) {
        self.consecutive_refresh_failures = 0;
        self.last_successful_reconcile_unix_ms = observed_at_unix_ms;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryChangeCause {
    Interface,
    Address,
    Route,
    ManualRefresh,
    Periodic,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct InventoryDiff {
    pub added: BTreeSet<EgressStableId>,
    pub removed: BTreeSet<EgressStableId>,
    pub changed: BTreeSet<EgressStableId>,
}

impl InventoryDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

#[derive(Debug, Clone)]
pub enum EgressInventoryEvent {
    Reconciled {
        revision: u64,
        causes: BTreeSet<InventoryChangeCause>,
        diff: InventoryDiff,
        snapshot: Arc<EgressInventorySnapshot>,
    },
    RefreshFailed {
        revision: u64,
        causes: BTreeSet<InventoryChangeCause>,
        error: String,
    },
    WatchFailed {
        revision: u64,
        error: String,
    },
}

#[derive(Debug, Clone)]
pub struct EgressInventoryConfig {
    pub debounce: Duration,
    pub event_capacity: usize,
    pub full_reconcile_interval: Duration,
}

impl Default for EgressInventoryConfig {
    fn default() -> Self {
        Self {
            debounce: Duration::from_millis(350),
            event_capacity: 256,
            full_reconcile_interval: Duration::from_secs(300),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InventoryError {
    #[error("interface enumeration failed: {0}")]
    Enumeration(#[source] std::io::Error),
    #[error("network namespace operation panicked: {0}")]
    Namespace(String),
    #[error("inventory worker failed: {0}")]
    Worker(String),
}

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error("egress {egress:?} is absent from inventory revision {inventory_revision}")]
    UnknownEgress {
        egress: EgressStableId,
        inventory_revision: u64,
    },
    #[error("native per-destination route lookup is unsupported on {platform}")]
    UnsupportedPlatform { platform: &'static str },
    #[error("network namespace operation failed: {0}")]
    Namespace(String),
    #[error("native route lookup failed: {0}")]
    Lookup(String),
    #[error("route lookup worker failed: {0}")]
    Worker(String),
    #[error(
        "kernel route selected ifindex {selected_ifindex}, not requested egress {requested:?} (ifindex {requested_ifindex})"
    )]
    EgressMismatch {
        requested: EgressStableId,
        requested_ifindex: u32,
        selected_ifindex: u32,
    },
}

#[derive(Debug, Default)]
struct DirtySignal {
    causes: BTreeSet<InventoryChangeCause>,
    added_ifindices: BTreeSet<u32>,
    watch_errors: Vec<WatchFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WatchFailure {
    error: String,
    fatal: bool,
}

impl DirtySignal {
    fn merge(&mut self, other: Self) {
        self.causes.extend(other.causes);
        self.added_ifindices.extend(other.added_ifindices);
        self.watch_errors.extend(other.watch_errors);
    }
}

struct InventoryInner {
    netns: NetNS,
    snapshot: ArcSwap<EgressInventorySnapshot>,
    events: broadcast::Sender<EgressInventoryEvent>,
    dirty_tx: mpsc::UnboundedSender<DirtySignal>,
    health: Mutex<EgressInventoryHealth>,
    shutdown: CancellationToken,
    watcher: Mutex<Option<netwatcher::WatchHandle>>,
}

impl Drop for InventoryInner {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.watcher.lock().unwrap().take();
    }
}

#[derive(Clone)]
pub struct EgressInventory {
    inner: Arc<InventoryInner>,
}

impl EgressInventory {
    pub async fn snapshot_once(netns: NetNS) -> Result<EgressInventorySnapshot, InventoryError> {
        tokio::task::spawn_blocking(move || snapshot_in_namespace(&netns, WatchMode::OneShot))
            .await
            .map_err(|error| InventoryError::Worker(error.to_string()))?
    }

    pub async fn start(
        netns: NetNS,
        config: EgressInventoryConfig,
    ) -> Result<Self, InventoryError> {
        let mut initial = Self::snapshot_once(netns.clone()).await?;
        let (events, _) = broadcast::channel(config.event_capacity.max(1));
        let (dirty_tx, dirty_rx) = mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();

        let watcher_result = {
            let _guard = netns.guard();
            start_native_watcher(dirty_tx.clone())
        };
        let (watcher, watch_error, watch_mode) = match watcher_result {
            Ok(watcher) => (Some(watcher), None, WatchMode::Native),
            Err(error) => (None, Some(error), WatchMode::PollingFallback),
        };
        for interface in initial.interfaces.values_mut() {
            interface.watch_mode = watch_mode;
        }

        let mut health = EgressInventoryHealth::new(watch_mode, initial.observed_at_unix_ms);
        if let Some(error) = &watch_error {
            health.record_watch_error(
                initial.revision,
                &WatchFailure {
                    error: error.clone(),
                    fatal: true,
                },
            );
        }

        let inner = Arc::new(InventoryInner {
            netns,
            snapshot: ArcSwap::from_pointee(initial),
            events,
            dirty_tx,
            health: Mutex::new(health),
            shutdown: shutdown.clone(),
            watcher: Mutex::new(watcher),
        });

        if let Some(error) = watch_error {
            let _ = inner.events.send(EgressInventoryEvent::WatchFailed {
                revision: inner.snapshot.load().revision,
                error,
            });
        }

        spawn_reconciler(&inner, dirty_rx, config);
        Ok(Self { inner })
    }

    pub fn snapshot(&self) -> Arc<EgressInventorySnapshot> {
        self.inner.snapshot.load_full()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EgressInventoryEvent> {
        self.inner.events.subscribe()
    }

    pub fn health(&self) -> EgressInventoryHealth {
        self.inner.health.lock().unwrap().clone()
    }

    pub fn request_refresh(&self) -> bool {
        self.inner
            .dirty_tx
            .send(DirtySignal {
                causes: BTreeSet::from([InventoryChangeCause::ManualRefresh]),
                added_ifindices: BTreeSet::new(),
                watch_errors: Vec::new(),
            })
            .is_ok()
    }

    pub async fn best_route_to(&self, target: IpAddr) -> Result<RouteResolution, RouteError> {
        self.resolve_route(None, target).await
    }

    pub async fn route_to(
        &self,
        egress: &EgressStableId,
        target: IpAddr,
    ) -> Result<RouteResolution, RouteError> {
        self.resolve_route(Some(egress.clone()), target).await
    }

    async fn resolve_route(
        &self,
        requested_egress: Option<EgressStableId>,
        target: IpAddr,
    ) -> Result<RouteResolution, RouteError> {
        let snapshot = self.snapshot();
        let requested_ifindex = requested_egress
            .as_ref()
            .map(|egress| {
                snapshot
                    .interfaces
                    .get(egress)
                    .map(|interface| interface.runtime_ifindex)
                    .ok_or_else(|| RouteError::UnknownEgress {
                        egress: egress.clone(),
                        inventory_revision: snapshot.revision,
                    })
            })
            .transpose()?;
        let netns = self.inner.netns.clone();
        let native = tokio::task::spawn_blocking(move || {
            native_route_in_namespace(&netns, target, requested_ifindex)
        })
        .await
        .map_err(|error| RouteError::Worker(error.to_string()))??;

        if let (Some(requested), Some(requested_ifindex)) =
            (requested_egress.as_ref(), requested_ifindex)
            && native.output_ifindex != requested_ifindex
        {
            return Err(RouteError::EgressMismatch {
                requested: requested.clone(),
                requested_ifindex,
                selected_ifindex: native.output_ifindex,
            });
        }
        let selected_egress = snapshot
            .interfaces
            .values()
            .find(|interface| interface.runtime_ifindex == native.output_ifindex)
            .map(|interface| interface.id.clone());

        Ok(RouteResolution {
            target,
            requested_egress,
            selected_egress,
            output_ifindex: native.output_ifindex,
            source: native.source,
            gateway: native.gateway,
            metric: native.metric,
            table: native.table,
            inventory_revision: snapshot.revision,
        })
    }
}

#[cfg(target_os = "linux")]
fn native_route_in_namespace(
    netns: &NetNS,
    target: IpAddr,
    output_ifindex: Option<u32>,
) -> Result<super::ifcfg::NativeRouteLookup, RouteError> {
    validate_network_namespace(netns).map_err(RouteError::Namespace)?;
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _guard = netns.guard();
        super::ifcfg::native_route_to(target, output_ifindex)
            .map_err(|error| RouteError::Lookup(error.to_string()))
    }))
    .map_err(|panic| RouteError::Namespace(panic_message(panic)))?
}

#[cfg(target_os = "windows")]
fn native_route_in_namespace(
    _netns: &NetNS,
    target: IpAddr,
    output_ifindex: Option<u32>,
) -> Result<super::ifcfg::NativeRouteLookup, RouteError> {
    super::ifcfg::native_route_to(target, output_ifindex)
        .map_err(|error| RouteError::Lookup(error.to_string()))
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn native_route_in_namespace(
    _netns: &NetNS,
    _target: IpAddr,
    _output_ifindex: Option<u32>,
) -> Result<super::ifcfg::NativeRouteLookup, RouteError> {
    Err(RouteError::UnsupportedPlatform {
        platform: std::env::consts::OS,
    })
}

fn start_native_watcher(
    dirty_tx: mpsc::UnboundedSender<DirtySignal>,
) -> Result<netwatcher::WatchHandle, String> {
    #[cfg(not(target_os = "android"))]
    {
        let update_tx = dirty_tx.clone();
        return netwatcher::watch_interfaces_with_callback_and_error(
            move |update| send_watcher_update(&update_tx, update),
            move |error| {
                let _ = dirty_tx.send(DirtySignal {
                    watch_errors: vec![WatchFailure {
                        fatal: matches!(
                            error.kind,
                            netwatcher::WatchRuntimeErrorKind::NotificationWait
                                | netwatcher::WatchRuntimeErrorKind::UpdateCallback
                        ),
                        error: error.to_string(),
                    }],
                    ..Default::default()
                });
            },
        )
        .map_err(|error| error.to_string());
    }

    #[cfg(target_os = "android")]
    netwatcher::watch_interfaces_with_callback(move |update| send_watcher_update(&dirty_tx, update))
        .map_err(|error| error.to_string())
}

fn send_watcher_update(dirty_tx: &mpsc::UnboundedSender<DirtySignal>, update: netwatcher::Update) {
    if update.is_initial {
        return;
    }

    let mut signal = DirtySignal::default();
    if !update.diff.added.is_empty() || !update.diff.removed.is_empty() {
        signal.causes.insert(InventoryChangeCause::Interface);
    }
    signal
        .added_ifindices
        .extend(update.diff.added.keys().copied());

    for diff in update.diff.modified.values() {
        if diff.name_changed || diff.hw_addr_changed {
            signal.causes.insert(InventoryChangeCause::Interface);
        }
        if !diff.addrs_added.is_empty() || !diff.addrs_removed.is_empty() {
            signal.causes.insert(InventoryChangeCause::Address);
        }
    }
    if update.addrs_added().next().is_some() || update.addrs_removed().next().is_some() {
        signal.causes.insert(InventoryChangeCause::Address);
    }
    if update
        .native_changes
        .contains(&netwatcher::NativeChangeKind::Route)
    {
        signal.causes.insert(InventoryChangeCause::Route);
    }
    if signal.causes.is_empty() {
        signal.causes.insert(InventoryChangeCause::Interface);
    }
    let _ = dirty_tx.send(signal);
}

fn spawn_reconciler(
    inner: &Arc<InventoryInner>,
    mut dirty_rx: mpsc::UnboundedReceiver<DirtySignal>,
    config: EgressInventoryConfig,
) {
    let weak = Arc::downgrade(inner);
    let shutdown = inner.shutdown.clone();
    tokio::spawn(async move {
        let mut generations: HashMap<EgressStableId, u64> = weak
            .upgrade()
            .map(|inner| {
                inner
                    .snapshot
                    .load()
                    .interfaces
                    .values()
                    .map(|interface| (interface.id.clone(), interface.generation))
                    .collect()
            })
            .unwrap_or_default();
        let mut periodic =
            tokio::time::interval(config.full_reconcile_interval.max(Duration::from_millis(1)));
        periodic.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        periodic.tick().await;

        loop {
            let mut signal = tokio::select! {
                _ = shutdown.cancelled() => break,
                maybe_signal = dirty_rx.recv() => match maybe_signal {
                    Some(signal) => signal,
                    None => break,
                },
                _ = periodic.tick() => DirtySignal {
                    causes: BTreeSet::from([InventoryChangeCause::Periodic]),
                    added_ifindices: BTreeSet::new(),
                    watch_errors: Vec::new(),
                },
            };

            if !config.debounce.is_zero() {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(config.debounce) => {}
                }
            }
            while let Ok(next) = dirty_rx.try_recv() {
                signal.merge(next);
            }

            let Some(inner) = weak.upgrade() else {
                break;
            };
            reconcile(&inner, signal, &mut generations).await;
        }
    });
}

async fn reconcile(
    inner: &Arc<InventoryInner>,
    signal: DirtySignal,
    generations: &mut HashMap<EgressStableId, u64>,
) {
    let revision = inner.snapshot.load().revision;
    {
        let mut health = inner.health.lock().unwrap();
        for failure in &signal.watch_errors {
            health.record_watch_error(revision, failure);
        }
        let native_signal_succeeded = signal.watch_errors.is_empty()
            && signal.causes.iter().any(|cause| {
                matches!(
                    cause,
                    InventoryChangeCause::Interface
                        | InventoryChangeCause::Address
                        | InventoryChangeCause::Route
                )
            });
        if native_signal_succeeded {
            health.record_watcher_signal_success();
        }
    }
    emit_watch_errors(&inner.events, revision, &signal.watch_errors);

    let mut refreshed = match EgressInventory::snapshot_once(inner.netns.clone()).await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let error = error.to_string();
            inner
                .health
                .lock()
                .unwrap()
                .record_refresh_error(revision, error.clone());
            let _ = inner.events.send(EgressInventoryEvent::RefreshFailed {
                revision,
                causes: signal.causes,
                error,
            });
            return;
        }
    };

    inner
        .health
        .lock()
        .unwrap()
        .record_refresh_success(refreshed.observed_at_unix_ms);
    let watch_mode = inner.health.lock().unwrap().watch_mode;

    let previous = inner.snapshot.load_full();
    for interface in refreshed.interfaces.values_mut() {
        let was_explicitly_added = signal.added_ifindices.contains(&interface.runtime_ifindex);
        let generation = match previous.interfaces.get(&interface.id) {
            Some(previous_interface) if !was_explicitly_added => previous_interface.generation,
            Some(previous_interface) => previous_interface.generation.saturating_add(1),
            None => generations
                .get(&interface.id)
                .copied()
                .map(|generation| generation.saturating_add(1))
                .unwrap_or(1),
        };
        interface.generation = generation;
        interface.watch_mode = watch_mode;
        generations.insert(interface.id.clone(), generation);
    }

    let diff = diff_snapshots(&previous, &refreshed);
    if diff.is_empty() {
        return;
    }

    refreshed.revision = previous.revision.saturating_add(1);
    refreshed.observed_at_unix_ms = unix_time_ms();
    for interface in refreshed.interfaces.values_mut() {
        interface.revision = refreshed.revision;
    }
    let refreshed = Arc::new(refreshed);
    inner.snapshot.store(refreshed.clone());
    let _ = inner.events.send(EgressInventoryEvent::Reconciled {
        revision: refreshed.revision,
        causes: signal.causes,
        diff,
        snapshot: refreshed,
    });
}

fn emit_watch_errors(
    events: &broadcast::Sender<EgressInventoryEvent>,
    revision: u64,
    errors: &[WatchFailure],
) {
    for failure in errors {
        let _ = events.send(EgressInventoryEvent::WatchFailed {
            revision,
            error: failure.error.clone(),
        });
    }
}

fn diff_snapshots(
    previous: &EgressInventorySnapshot,
    current: &EgressInventorySnapshot,
) -> InventoryDiff {
    let previous_ids: BTreeSet<_> = previous.interfaces.keys().cloned().collect();
    let current_ids: BTreeSet<_> = current.interfaces.keys().cloned().collect();
    let added = current_ids.difference(&previous_ids).cloned().collect();
    let removed = previous_ids.difference(&current_ids).cloned().collect();
    let changed = previous_ids
        .intersection(&current_ids)
        .filter(|id| {
            let previous = &previous.interfaces[*id];
            let current = &current.interfaces[*id];
            !same_observation(previous, current)
        })
        .cloned()
        .collect();
    InventoryDiff {
        added,
        removed,
        changed,
    }
}

fn same_observation(previous: &EgressInterfaceSnapshot, current: &EgressInterfaceSnapshot) -> bool {
    previous.platform_name == current.platform_name
        && previous.display_name == current.display_name
        && previous.aliases == current.aliases
        && previous.hardware_address == current.hardware_address
        && previous.runtime_ifindex == current.runtime_ifindex
        && previous.kind == current.kind
        && previous.oper_state == current.oper_state
        && previous.addresses == current.addresses
        && previous.mtu == current.mtu
        && previous.transmit_speed_bps == current.transmit_speed_bps
        && previous.receive_speed_bps == current.receive_speed_bps
        && previous.is_eligible == current.is_eligible
        && previous.exclusion_reasons == current.exclusion_reasons
}

fn snapshot_in_namespace(
    netns: &NetNS,
    watch_mode: WatchMode,
) -> Result<EgressInventorySnapshot, InventoryError> {
    #[cfg(target_os = "linux")]
    validate_network_namespace(netns).map_err(InventoryError::Namespace)?;

    std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _guard = netns.guard();
        snapshot_current_namespace(watch_mode)
    }))
    .map_err(|panic| InventoryError::Namespace(panic_message(panic)))?
}

#[cfg(target_os = "linux")]
fn validate_network_namespace(netns: &NetNS) -> Result<(), String> {
    let Some(name) = netns.name() else {
        return Ok(());
    };
    let path = if name == super::netns::ROOT_NETNS_NAME {
        "/proc/1/ns/net".into()
    } else {
        format!("/var/run/netns/{name}")
    };
    std::fs::metadata(&path)
        .map(|_| ())
        .map_err(|error| format!("failed to access network namespace {path}: {error}"))
}

fn snapshot_current_namespace(
    watch_mode: WatchMode,
) -> Result<EgressInventorySnapshot, InventoryError> {
    #[cfg(target_os = "linux")]
    let netns_inode = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self/ns/net")
            .map_err(InventoryError::Enumeration)?
            .ino()
    };
    #[cfg(not(target_os = "linux"))]
    let netns_inode = 0;

    let mut interfaces = BTreeMap::new();
    for interface in crate::common::network::enumerate_interfaces() {
        let runtime_ifindex = interface.index;
        let platform_name = interface.name.clone();
        let id = stable_id(netns_inode, runtime_ifindex, &platform_name)?;
        let link = super::ifcfg::interface_link_state(&interface);
        let oper_state = if link.up && link.running {
            OperState::Up
        } else if !link.up {
            OperState::Down
        } else {
            OperState::Unknown
        };
        let kind = classify_kind(&platform_name, link.loopback);
        let mut addresses: Vec<_> = interface
            .ips
            .iter()
            .map(|network| InterfaceAddress {
                ip: network.ip(),
                prefix_len: network.prefix(),
            })
            .collect();
        addresses.sort();
        addresses.dedup();

        let mut exclusion_reasons = Vec::new();
        if oper_state != OperState::Up {
            exclusion_reasons.push(EgressExclusionReason::InterfaceDown);
        }
        if addresses.is_empty() {
            exclusion_reasons.push(EgressExclusionReason::NoAddress);
        }
        if kind == EgressKind::Loopback {
            exclusion_reasons.push(EgressExclusionReason::Loopback);
        }
        if is_easytier_managed_name(&platform_name) {
            exclusion_reasons.push(EgressExclusionReason::EasyTierManaged);
        }
        exclusion_reasons.sort();
        exclusion_reasons.dedup();

        let snapshot = EgressInterfaceSnapshot {
            id: id.clone(),
            revision: 1,
            generation: 1,
            platform_name: platform_name.clone(),
            display_name: platform_name.clone(),
            aliases: vec![platform_name],
            hardware_address: interface.mac.map(|address| address.to_string()),
            runtime_ifindex,
            kind,
            oper_state,
            addresses,
            mtu: link.mtu,
            transmit_speed_bps: None,
            receive_speed_bps: None,
            is_eligible: exclusion_reasons.is_empty(),
            exclusion_reasons,
            watch_mode,
        };
        interfaces.insert(id, snapshot);
    }

    Ok(EgressInventorySnapshot {
        revision: 1,
        observed_at_unix_ms: unix_time_ms(),
        interfaces,
    })
}

fn classify_kind(name: &str, loopback: bool) -> EgressKind {
    if loopback {
        return EgressKind::Loopback;
    }
    let lower = name.to_ascii_lowercase();
    if [
        "tun",
        "tap",
        "wintun",
        "wireguard",
        "wg",
        "utun",
        "easytier",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        EgressKind::Virtual
    } else {
        EgressKind::Unknown
    }
}

fn is_easytier_managed_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("easytier") || lower.starts_with("et_") || lower.starts_with("et-")
}

#[cfg(target_os = "linux")]
fn stable_id(
    netns_inode: u64,
    ifindex: u32,
    _platform_name: &str,
) -> Result<EgressStableId, InventoryError> {
    Ok(EgressStableId::Linux {
        netns_inode,
        ifindex,
    })
}

#[cfg(target_os = "windows")]
fn stable_id(
    _netns_inode: u64,
    ifindex: u32,
    _platform_name: &str,
) -> Result<EgressStableId, InventoryError> {
    let (luid, guid) = super::ifcfg::windows_stable_interface_identity(ifindex)
        .map_err(|error| InventoryError::Worker(error))?;
    Ok(EgressStableId::Windows { luid, guid })
}

#[cfg(target_os = "macos")]
fn stable_id(
    _netns_inode: u64,
    ifindex: u32,
    platform_name: &str,
) -> Result<EgressStableId, InventoryError> {
    Ok(EgressStableId::MacOs {
        ifindex,
        bsd_name: platform_name.to_owned(),
    })
}

#[cfg(target_os = "android")]
fn stable_id(
    _netns_inode: u64,
    ifindex: u32,
    _platform_name: &str,
) -> Result<EgressStableId, InventoryError> {
    Ok(EgressStableId::Android {
        network_handle: None,
        ifindex: Some(ifindex),
    })
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "windows",
    target_os = "macos",
    target_os = "android"
)))]
fn stable_id(
    _netns_inode: u64,
    ifindex: u32,
    platform_name: &str,
) -> Result<EgressStableId, InventoryError> {
    Ok(EgressStableId::Fallback {
        platform: std::env::consts::OS.to_owned(),
        opaque: format!("{ifindex}:{platform_name}"),
    })
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn serialize_interface_map<S>(
    interfaces: &BTreeMap<EgressStableId, EgressInterfaceSnapshot>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;

    let mut sequence = serializer.serialize_seq(Some(interfaces.len()))?;
    for interface in interfaces.values() {
        sequence.serialize_element(interface)?;
    }
    sequence.end()
}

fn deserialize_interface_map<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<EgressStableId, EgressInterfaceSnapshot>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let interfaces = Vec::<EgressInterfaceSnapshot>::deserialize(deserializer)?;
    let mut map = BTreeMap::new();
    for interface in interfaces {
        let id = interface.id.clone();
        if map.insert(id.clone(), interface).is_some() {
            return Err(serde::de::Error::custom(format!(
                "duplicate egress interface ID: {id:?}"
            )));
        }
    }
    Ok(map)
}

fn panic_message(panic: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = panic.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = panic.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interface(id: EgressStableId, name: &str) -> EgressInterfaceSnapshot {
        EgressInterfaceSnapshot {
            runtime_ifindex: id.runtime_ifindex().unwrap_or_default(),
            id,
            revision: 1,
            generation: 1,
            platform_name: name.to_owned(),
            display_name: name.to_owned(),
            aliases: vec![name.to_owned()],
            hardware_address: None,
            kind: EgressKind::Unknown,
            oper_state: OperState::Up,
            addresses: Vec::new(),
            mtu: Some(1500),
            transmit_speed_bps: None,
            receive_speed_bps: None,
            is_eligible: true,
            exclusion_reasons: Vec::new(),
            watch_mode: WatchMode::Native,
        }
    }

    fn snapshot(
        interfaces: impl IntoIterator<Item = EgressInterfaceSnapshot>,
    ) -> EgressInventorySnapshot {
        EgressInventorySnapshot {
            revision: 1,
            observed_at_unix_ms: 1,
            interfaces: interfaces
                .into_iter()
                .map(|interface| (interface.id.clone(), interface))
                .collect(),
        }
    }

    #[test]
    fn deterministic_diff_covers_added_removed_changed_and_unchanged() {
        let unchanged_id = EgressStableId::Linux {
            netns_inode: 1,
            ifindex: 1,
        };
        let changed_id = EgressStableId::Linux {
            netns_inode: 1,
            ifindex: 2,
        };
        let removed_id = EgressStableId::Linux {
            netns_inode: 1,
            ifindex: 3,
        };
        let added_id = EgressStableId::Linux {
            netns_inode: 1,
            ifindex: 4,
        };
        let before = snapshot([
            interface(unchanged_id.clone(), "same"),
            interface(changed_id.clone(), "before"),
            interface(removed_id.clone(), "removed"),
        ]);
        let after = snapshot([
            interface(unchanged_id, "same"),
            interface(changed_id.clone(), "after"),
            interface(added_id.clone(), "added"),
        ]);

        let diff = diff_snapshots(&before, &after);
        assert_eq!(diff.added, BTreeSet::from([added_id]));
        assert_eq!(diff.removed, BTreeSet::from([removed_id]));
        assert_eq!(diff.changed, BTreeSet::from([changed_id]));
    }

    #[test]
    fn dirty_signal_merge_is_a_set_union() {
        let mut signal = DirtySignal {
            causes: BTreeSet::from([InventoryChangeCause::Interface]),
            added_ifindices: BTreeSet::from([1]),
            watch_errors: vec![WatchFailure {
                error: "first".to_owned(),
                fatal: false,
            }],
        };
        signal.merge(DirtySignal {
            causes: BTreeSet::from([
                InventoryChangeCause::Interface,
                InventoryChangeCause::Address,
            ]),
            added_ifindices: BTreeSet::from([1, 2]),
            watch_errors: vec![WatchFailure {
                error: "second".to_owned(),
                fatal: true,
            }],
        });
        assert_eq!(
            signal.causes,
            BTreeSet::from([
                InventoryChangeCause::Interface,
                InventoryChangeCause::Address,
            ])
        );
        assert_eq!(signal.added_ifindices, BTreeSet::from([1, 2]));
        assert_eq!(signal.watch_errors.len(), 2);
        assert_eq!(signal.watch_errors[0].error, "first");
        assert!(!signal.watch_errors[0].fatal);
        assert_eq!(signal.watch_errors[1].error, "second");
        assert!(signal.watch_errors[1].fatal);
    }

    #[test]
    fn watcher_runtime_errors_are_emitted_with_current_revision() {
        let (events, mut receiver) = broadcast::channel(4);
        emit_watch_errors(
            &events,
            17,
            &[
                WatchFailure {
                    error: "enumeration failed".to_owned(),
                    fatal: false,
                },
                WatchFailure {
                    error: "callback failed".to_owned(),
                    fatal: true,
                },
            ],
        );

        for expected in ["enumeration failed", "callback failed"] {
            match receiver.try_recv().expect("watch error event missing") {
                EgressInventoryEvent::WatchFailed { revision, error } => {
                    assert_eq!(revision, 17);
                    assert_eq!(error, expected);
                }
                event => panic!("unexpected event: {event:?}"),
            }
        }
    }

    #[test]
    fn inventory_health_tracks_failure_streaks_and_recovery() {
        let mut health = EgressInventoryHealth::new(WatchMode::Native, 10);

        health.record_watch_error(
            3,
            &WatchFailure {
                error: "watch failed".to_owned(),
                fatal: false,
            },
        );
        health.record_watch_error(
            3,
            &WatchFailure {
                error: "watch failed again".to_owned(),
                fatal: true,
            },
        );
        health.record_refresh_error(3, "refresh failed".to_owned());
        assert_eq!(health.consecutive_watch_failures, 2);
        assert_eq!(health.watch_mode, WatchMode::PollingFallback);
        assert_eq!(health.consecutive_refresh_failures, 1);
        assert_eq!(health.last_watch_error.as_ref().unwrap().revision, 3);
        assert_eq!(health.last_refresh_error.as_ref().unwrap().revision, 3);

        health.record_watcher_signal_success();
        health.record_refresh_success(20);
        assert_eq!(health.consecutive_watch_failures, 0);
        assert_eq!(health.consecutive_refresh_failures, 0);
        assert_eq!(health.last_successful_reconcile_unix_ms, 20);
        assert!(health.last_watch_error.is_some());
        assert!(health.last_refresh_error.is_some());
    }

    #[test]
    fn snapshot_json_uses_an_interface_array_and_round_trips() {
        let id = EgressStableId::Linux {
            netns_inode: 7,
            ifindex: 9,
        };
        let snapshot = snapshot([interface(id.clone(), "eth-test")]);

        let json = serde_json::to_value(&snapshot).expect("snapshot serialization failed");
        assert!(json["interfaces"].is_array());
        assert_eq!(json["interfaces"].as_array().unwrap().len(), 1);

        let decoded: EgressInventorySnapshot =
            serde_json::from_value(json).expect("snapshot deserialization failed");
        assert_eq!(decoded, snapshot);
        assert!(decoded.interfaces.contains_key(&id));
    }

    #[test]
    fn snapshot_json_rejects_duplicate_stable_ids() {
        let id = EgressStableId::Linux {
            netns_inode: 7,
            ifindex: 9,
        };
        let snapshot = snapshot([interface(id, "eth-test")]);
        let mut json = serde_json::to_value(snapshot).expect("snapshot serialization failed");
        let interfaces = json["interfaces"]
            .as_array_mut()
            .expect("snapshot interfaces were not serialized as an array");
        interfaces.push(interfaces[0].clone());

        let error = serde_json::from_value::<EgressInventorySnapshot>(json)
            .expect_err("duplicate stable IDs were accepted");
        assert!(error.to_string().contains("duplicate egress interface ID"));
    }
}

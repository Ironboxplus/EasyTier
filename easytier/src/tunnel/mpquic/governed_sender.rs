//! The send side of the mpquic driver: every packet TQUIC sends goes into
//! the CAKE queue of the egress it leaves through (`egress_cake`, one per NIC
//! or NIC and WAN, CAKE_SQM_PLAN.md B3) and is sent from there. There is no
//! code path in this module that reaches a carrier's raw
//! `MpDatagramPath::try_send_to` from the TQUIC send callback.
//!
//! `CarrierId`/`PathKey`/`carrier_id`/`path_key` live here and are
//! re-exported from `tunnel::mpquic` so existing callers
//! (`connector::mp_path`, `connector::mp_session`, `instance::instance`,
//! `connector::mp_optimizer`) compile unmodified.
//!
//! MP_SQM_PLAN.md S1.3: `MpQuicTunnelConnector`/`MpQuicTunnelListener`,
//! constructed via their real factory path (`new_with_mp_config`, used by
//! `connector::create_connector_by_url`/`instance::listeners`), share the
//! process's one `GlobalCtx::egress_quality_manager()` and (when
//! `GlobalCtx::get_egress_inventory()` has been published) resolve a real
//! `EgressScope` for their standalone paths via `resolve_egress_scope` below
//! -- accounting only, never a bind change: the socket stays exactly where
//! it was bound (`bind_udp`/`listen()`), only the egress it is shaped by
//! changes. A resolution failure (no inventory yet, no route, manual
//! multi-NIC `bind_devs`/`ET_MPQUIC_DEVS`) falls back to
//! `EgressStableId::Fallback`, same as standalone/test construction
//! (`new`/`new_with_runtime`), which never has an inventory to resolve
//! against at all. Only the MP-managed path (`connector::mp_session`) hands
//! over the NIC scope it resolved itself -- from an `EgressSocketBinding`
//! (built only by tests since MP_SQM_PLAN.md S2.14) or its device-name route
//! index -- so the carrier and the session's own egress sampling land on one
//! scope; see `scope_for`'s priority order below.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::common::egress_inventory::EgressStableId;
use crate::common::egress_quality::EgressQualityManager;
use crate::common::transport_quality::{EgressDirection, EgressScope};
use crate::tunnel::datagram_carrier::GovernedCarrier;

use super::egress_cake::{EgressCake, QueuedPacket};
use super::owd::OwdProbes;
use super::{MpDatagramPath, PathReceiverEvent, is_carrier_gone_error, is_icmp_error};

/// A send that failed for a reason other than a full socket buffer. The
/// packet is dropped and QUIC's loss recovery resends its frames; an error
/// returned to TQUIC instead ended the endpoint's whole send round, stalling
/// every other path. A carrier whose NIC or address is gone is retired so
/// the session stops scheduling onto it.
pub(super) fn on_send_error(
    error: &std::io::Error,
    id: CarrierId,
    local: SocketAddr,
    remote: SocketAddr,
    event_tx: &mpsc::UnboundedSender<PathReceiverEvent>,
) {
    if is_icmp_error(error) {
        tracing::debug!(target: "mpq", ?error, ?local, ?remote, "mpquic: send hit an ICMP error, packet dropped");
    } else if is_carrier_gone_error(error) {
        tracing::warn!(target: "mpq", ?error, ?local, ?remote, "mpquic: carrier gone, retiring it");
        let _ = event_tx.send(PathReceiverEvent::Failed(id));
    } else {
        tracing::warn!(target: "mpq", ?error, ?local, ?remote, "mpquic: send failed, packet dropped");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CarrierId(pub(crate) usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PathKey {
    pub(crate) carrier_id: CarrierId,
    pub(crate) local_addr: SocketAddr,
    pub(crate) remote_addr: SocketAddr,
}

/// Derived from the *original* `Arc<dyn MpDatagramPath>`'s address, before it
/// is ever wrapped in a [`GovernedCarrier`]. This is deliberate, not
/// incidental: computing it from the wrapper instead would mint a fresh,
/// distinct `CarrierId` every time the same physical path got wrapped again
/// (e.g. a second `register()` call for a second remote on the same local
/// socket), which would silently defeat `MpPathRegistry`'s "one physical
/// carrier, one entry" invariant and let the same OS socket end up governed
/// by two independent `GovernedCarrier`/`EgressHandle` pairs.
pub(crate) fn carrier_id(path: &Arc<dyn MpDatagramPath>) -> CarrierId {
    CarrierId(Arc::as_ptr(path) as *const () as usize)
}

pub(crate) fn path_key(path: &Arc<dyn MpDatagramPath>, remote_addr: SocketAddr) -> PathKey {
    PathKey {
        carrier_id: carrier_id(path),
        local_addr: path.local_addr(),
        remote_addr,
    }
}

/// `nic_scope` is the real, inventory-resolved identity of `local_addr`'s
/// physical egress when one is known (the MP-managed path,
/// `connector::mp_session::path_nic_scope`, from `MpPathSpec::egress_binding`
/// or its device-name route index -- the same scope its egress sampling uses).
/// `None` is an honest last resort, not a silent default to reach for: it
/// means nothing upstream of this registry has resolved a real interface
/// identity for `local_addr` yet (`MpQuicTunnelConnector`/`MpQuicTunnelListener`,
/// pending MP_SQM_PLAN.md §4.4 (b) step 4's `EgressInventory::best_route_to`
/// threading). `generation: 0` is likewise a placeholder: a `Fallback`
/// `EgressStableId` is never a target of
/// `EgressQualityManager::invalidate_stale_generations` (that only acts on
/// `(stable_id, direction)` pairs a real inventory reconcile can name), so
/// there is no live "current generation" to compare against.
/// `resolved_route` is the MP_SQM_PLAN.md S1.3 remainder: a standalone
/// `mpquic://` connector/listener never binds a real per-NIC socket (so it
/// never has a `nic_scope`), but can still resolve which physical interface
/// the OS would route a given remote through via
/// `EgressInventory::best_route_to` -- see `resolve_egress_scope`. It is
/// only ever `Some` when `nic_scope` is `None`: the MP-managed path's scope
/// takes priority over it.
fn scope_for(
    local_addr: SocketAddr,
    nic_scope: Option<EgressScope>,
    resolved_route: Option<EgressScope>,
) -> EgressScope {
    if let Some(scope) = nic_scope.or(resolved_route) {
        return scope;
    }
    EgressScope {
        stable_id: EgressStableId::Fallback {
            platform: std::env::consts::OS.to_string(),
            opaque: format!("mpquic-carrier:{local_addr}"),
        },
        direction: EgressDirection::Egress,
        generation: 0,
    }
}

/// Resolve `remote`'s real physical egress via `EgressInventory::
/// best_route_to`, for accounting only -- MP_SQM_PLAN.md S1.3 explicitly
/// forbids binding a per-NIC socket here (that would change a
/// standalone connector/listener's actual bind strategy, not just which
/// ledger governs it). `None` on any resolution failure (no inventory yet,
/// no route, the selected interface not in the current snapshot): the
/// caller must fall back to `EgressStableId::Fallback`, exactly like today.
pub(super) async fn resolve_egress_scope(
    inventory: &crate::common::egress_inventory::EgressInventory,
    remote: SocketAddr,
    direction: EgressDirection,
) -> Option<EgressScope> {
    let route = inventory.best_route_to(remote.ip()).await.ok()?;
    let stable_id = route.selected_egress?;
    let snapshot = inventory.snapshot();
    let interface = snapshot.interfaces.get(&stable_id)?;
    Some(EgressScope::from_resolved_route(
        stable_id,
        interface.generation,
        direction,
    ))
}

/// Routes each TQUIC packet to the datagram path whose local address matches
/// `PacketInfo.src`. New path carriers (FakeTCP first) implement
/// `MpDatagramPath`; the QUIC session no longer needs carrier-specific logic.
///
/// Every carrier this registry hands out is a [`GovernedCarrier`]: there is
/// no accessor here (and none on `GovernedCarrier` itself) that returns the
/// raw `Arc<dyn MpDatagramPath>` once a path is registered, so a caller
/// cannot reach around the ledger even by accident.
pub(super) struct MpPathRegistry {
    pub(super) carriers: HashMap<SocketAddr, (CarrierId, Arc<GovernedCarrier>)>,
    pub(super) paths: HashSet<PathKey>,
    egress_quality: Arc<EgressQualityManager>,
}

impl MpPathRegistry {
    pub(super) fn new(egress_quality: Arc<EgressQualityManager>) -> Self {
        Self {
            carriers: HashMap::new(),
            paths: HashSet::new(),
            egress_quality,
        }
    }

    pub(super) fn take_carrier_paths(&mut self, carrier_id: CarrierId) -> Vec<PathKey> {
        let mut removed = self
            .paths
            .iter()
            .filter(|key| key.carrier_id == carrier_id)
            .copied()
            .collect::<Vec<_>>();
        removed.sort_by_key(|key| (key.local_addr, key.remote_addr));
        self.paths.retain(|key| key.carrier_id != carrier_id);
        self.carriers.retain(|_, (id, _)| *id != carrier_id);
        removed
    }

    pub(super) fn key_for_addresses(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Option<PathKey> {
        self.paths
            .iter()
            .find(|key| key.local_addr == local_addr && key.remote_addr == remote_addr)
            .copied()
    }

    /// Returns the governed carrier for `(local_addr, remote_addr)` together
    /// with its `CarrierId`, so a caller (`DatagramSender::on_packets_send`)
    /// that must retire this carrier on an `Unattainable`/`Retired` outcome
    /// has the id ready without a second lookup.
    pub(super) fn carrier_for(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Option<(CarrierId, Arc<GovernedCarrier>)> {
        let (id, carrier) = self.carriers.get(&local_addr)?;
        let exact = PathKey {
            carrier_id: *id,
            local_addr,
            remote_addr,
        };
        let registered = self.paths.contains(&exact)
            || self.paths.iter().any(|path| {
                path.carrier_id == *id
                    && path.local_addr == local_addr
                    && path.remote_addr.ip().is_unspecified()
                    && path.remote_addr.port() == 0
            });
        registered.then(|| (*id, carrier.clone()))
    }

    /// Every physical local socket has exactly one `GovernedCarrier`
    /// (`carrier_id`'s doc comment), so unlike `carrier_for` this does not
    /// need a remote address to disambiguate -- used by the driver's own
    /// periodic standalone-autorate tick (MP_SQM_PLAN.md S2.5), which samples
    /// per local egress, not per remote path.
    pub(super) fn carrier_for_local(&self, local_addr: SocketAddr) -> Option<Arc<GovernedCarrier>> {
        self.carriers.get(&local_addr).map(|(_, carrier)| carrier.clone())
    }

    pub(super) fn register(
        &mut self,
        path: Arc<dyn MpDatagramPath>,
        remote_addr: SocketAddr,
        nic_scope: Option<EgressScope>,
        resolved_route: Option<EgressScope>,
    ) -> Result<PathKey, String> {
        let key = path_key(&path, remote_addr);
        let local_addr = key.local_addr;
        let id = key.carrier_id;
        match self.carriers.get(&local_addr) {
            Some((existing_id, _)) if *existing_id != id => {
                return Err(format!(
                    "mpquic local address {local_addr} is already owned by another carrier"
                ));
            }
            Some(_) => {}
            None => {
                // Only reached the first time this physical local socket is
                // registered (see `carrier_id`'s doc comment) -- exactly one
                // `GovernedCarrier`/`EgressHandle` is ever created per
                // physical path, never re-created for a later remote on the
                // same local socket. `path` already satisfies
                // `GovernedCarrier::new`'s bound directly (MP_SQM_PLAN.md
                // S1.2 deleted the `MpDatagramPathCarrier` adapter this used
                // to wrap through): `MpDatagramPath` and
                // `tunnel::datagram_carrier::DatagramCarrier` are the same
                // trait now.
                let scope = scope_for(local_addr, nic_scope, resolved_route);
                // Real carrier in hand: pass its actual MTU into the
                // burst/control-reserve clamp instead of the manager's
                // 1500-byte default (MP_SQM_PLAN.md S1.3).
                let handle = self.egress_quality.handle_for(scope);
                let governed = Arc::new(GovernedCarrier::new(path, handle));
                self.carriers.insert(local_addr, (id, governed));
            }
        }

        if !self.paths.insert(key) {
            return Err(format!(
                "mpquic path {local_addr} -> {remote_addr} already exists"
            ));
        }
        Ok(key)
    }

    /// MP_SQM_PLAN.md S1.3 remainder: a listener has no remote address to
    /// resolve a route against until it accepts a session, so its initial
    /// `register()` call above always lands on `EgressStableId::Fallback`.
    /// Once the driver learns the real peer address (the first inbound
    /// datagram), it can resolve a real scope and swap this already-governed
    /// carrier onto it -- replacing the whole registry entry with a freshly
    /// built one, never mutating `GovernedCarrier` in place (it deliberately
    /// exposes no such seam, see its doc comment) and never touching the
    /// underlying `path`/socket. A no-op if `local_addr` was never
    /// registered (defensive; should not happen for a caller that only
    /// calls this after its own successful `register()`).
    pub(super) fn rescope(&mut self, local_addr: SocketAddr, path: Arc<dyn MpDatagramPath>, scope: EgressScope) {
        let Some((id, _)) = self.carriers.get(&local_addr) else {
            return;
        };
        let id = *id;
        let handle = self.egress_quality.handle_for(scope);
        let governed = Arc::new(GovernedCarrier::new(path, handle));
        self.carriers.insert(local_addr, (id, governed));
    }

    pub(super) fn unregister(&mut self, key: PathKey) -> bool {
        if !self.paths.remove(&key) {
            return false;
        }

        if self
            .paths
            .iter()
            .any(|registered| registered.carrier_id == key.carrier_id)
        {
            return false;
        }

        self.carriers.remove(&key.local_addr);
        true
    }
}

/// Fallback wake when the queue gave no time (defensive).
const NO_ETA_WAKE_FALLBACK: Duration = Duration::from_millis(50);

/// Queues each TQUIC packet in its egress's CAKE queue ([`EgressCake`]) --
/// the only way a packet reaches a carrier. `next_wake` is how the queue's
/// next send time reaches `drive()`'s own sleep computation (see
/// `arm_wake`); `event_tx` is the same channel `spawn_path_receiver` uses to
/// report a dead carrier.
pub(super) struct DatagramSender {
    pub(super) registry: Arc<std::sync::RwLock<MpPathRegistry>>,
    pub(super) next_wake: std::rc::Rc<Cell<Option<Instant>>>,
    pub(super) event_tx: mpsc::UnboundedSender<PathReceiverEvent>,
    /// Egress queues this driver has packets in or waits on; it drains them
    /// every turn (`pump`), see `egress_cake`'s module doc.
    queues: RefCell<Vec<Arc<EgressCake>>>,
    /// The session's one-way delay probes, when it sends any
    /// (OWD_AUTORATE_PLAN.md 1.1): the packet that carries one is marked so
    /// the egress queue stamps the time it leaves.
    probes: Option<Arc<OwdProbes>>,
}

impl DatagramSender {
    pub(super) fn new(
        registry: Arc<std::sync::RwLock<MpPathRegistry>>,
        next_wake: std::rc::Rc<Cell<Option<Instant>>>,
        event_tx: mpsc::UnboundedSender<PathReceiverEvent>,
    ) -> Self {
        Self {
            registry,
            next_wake,
            event_tx,
            queues: RefCell::new(Vec::new()),
            probes: None,
        }
    }

    pub(super) fn with_probes(mut self, probes: Arc<OwdProbes>) -> Self {
        self.probes = Some(probes);
        self
    }

    fn arm_wake(&self, retry_at: Option<Instant>) {
        let candidate = retry_at.unwrap_or_else(|| Instant::now() + NO_ETA_WAKE_FALLBACK);
        let updated = match self.next_wake.get() {
            Some(existing) => existing.min(candidate),
            None => candidate,
        };
        self.next_wake.set(Some(updated));
    }

    fn watch(&self, queue: Arc<EgressCake>) {
        let mut queues = self.queues.borrow_mut();
        if !queues.iter().any(|known| Arc::ptr_eq(known, &queue)) {
            queues.push(queue);
        }
    }

    fn enqueue(
        &self,
        id: CarrierId,
        carrier: &Arc<GovernedCarrier>,
        buf: &[u8],
        info: &tquic::PacketInfo,
    ) {
        let queue = EgressCake::of(carrier);
        queue.enqueue(
            carrier,
            info.send_meta.flow_hash,
            QueuedPacket {
                carrier: Arc::downgrade(carrier),
                id,
                buf: buf.to_vec(),
                wire_bytes: carrier.wire_bytes(buf.len(), info.dst),
                local: info.src,
                remote: info.dst,
                event_tx: self.event_tx.clone(),
                probe: self.probes.as_ref().and_then(|probes| {
                    let seq = probes.claim(info.send_meta.flow_hash?)?;
                    Some((probes.clone(), seq))
                }),
            },
        );
        self.watch(queue);
    }

    /// Sends what CAKE releases from every egress queue this driver waits
    /// on, and wakes the driver when the next packet can go. Called every
    /// driver turn: the queues have no task of their own.
    pub(super) fn pump(&self) {
        let mut wake: Option<Instant> = None;
        self.queues.borrow_mut().retain(|queue| match queue.pump() {
            Some(at) => {
                wake = Some(wake.map_or(at, |earlier| earlier.min(at)));
                true
            }
            None => false,
        });
        if wake.is_some() {
            self.arm_wake(wake);
        }
    }

    /// Queue every packet of `pkts`; all are accepted (a packet for a vanished
    /// path is dropped like a lost one, QUIC recovers it). Left unreported it
    /// would stay at the head of the endpoint's queue, which generates
    /// nothing more while its queue is not empty (`send_packets_out`).
    fn queue_all(&self, pkts: &[(Vec<u8>, tquic::PacketInfo)]) -> tquic::Result<()> {
        let registry = self
            .registry
            .read()
            .map_err(|_| tquic::Error::InvalidOperation("MP path registry poisoned".into()))?;
        for (buf, info) in pkts {
            if let Some((id, carrier)) = registry.carrier_for(info.src, info.dst) {
                self.enqueue(id, &carrier, buf, info);
            }
        }
        drop(registry);
        self.pump();
        Ok(())
    }
}

/// What one path may have waiting in its egress's CAKE queue before the
/// congestion-controlled data of its connection holds back: Linux's TCP small
/// queues (`tcp_small_queue_check`) allow a socket two packets or one
/// millisecond of its pacing rate (`pacing_rate >> 10`), whichever is more.
/// Here the rate is the egress's shaping rate.
fn small_queue_limit(mtu: usize, shaping_bytes_per_sec: u64) -> u64 {
    (2 * mtu as u64).max(shaping_bytes_per_sec / 1_000)
}

impl tquic::PacketSendHandler for DatagramSender {
    /// TCP small queues for the connection's congestion-controlled data
    /// (MP_FIX_PHASES.md S-I12): a path that already has its share waiting in
    /// CAKE takes no more STREAM bytes, so a stream's backlog lives in the
    /// stream queues, where COBALT manages it, and not in CAKE, where it
    /// would delay every other flow on the egress. Datagrams bypass the gate
    /// (the egress queue is their AQM), and ACK, PING and probes are never
    /// gated. The queue wakes the driver when it can send again.
    fn can_send_data(&self, local: SocketAddr, remote: SocketAddr, bytes: usize) -> bool {
        let Ok(registry) = self.registry.read() else {
            return true;
        };
        let Some((_, carrier)) = registry.carrier_for(local, remote) else {
            return true;
        };
        drop(registry);
        let queue = EgressCake::of(&carrier);
        let limit = small_queue_limit(carrier.mtu(), EgressCake::rate_of(&carrier));
        if queue.queued_bytes(local, remote) + bytes as u64 <= limit {
            return true;
        }
        self.watch(queue.clone());
        self.arm_wake(queue.next_send());
        false
    }

    fn on_packets_send(&self, pkts: &[(Vec<u8>, tquic::PacketInfo)]) -> tquic::Result<usize> {
        self.queue_all(pkts)?;
        Ok(pkts.len())
    }

    /// Sparse variant of `on_packets_send`; a packet handed to its egress
    /// queue is reported sent, as a kernel reports a packet handed to its
    /// qdisc.
    fn on_packets_send_sparse(
        &self,
        pkts: &[(Vec<u8>, tquic::PacketInfo)],
    ) -> tquic::Result<Vec<usize>> {
        self.queue_all(pkts)?;
        Ok((0..pkts.len()).collect())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod resolve_egress_scope_tests {
    //! MP_SQM_PLAN.md S1.3 (remainder), team-lead-ordered RED test: "two
    //! remotes routed via different interfaces resolve to different
    //! scopes. Use loopback plus a real non-loopback address of .88; no
    //! root needed." `EgressInventory::best_route_to`/`resolve_route` is a
    //! pure routing-table lookup (`native_route_in_namespace`, netlink
    //! `RTM_GETROUTE`-equivalent) -- it never sends a packet and never
    //! needs the destination to actually be reachable, so a well-known
    //! public IP works fine here as the "real non-loopback address" without
    //! requiring this test host to have real internet connectivity, and
    //! without root (no bind, no namespace mutation -- `NetNS::new(None)` is
    //! the current/default namespace, read-only).
    use super::*;
    use crate::common::egress_inventory::{EgressInventory, EgressInventoryConfig};
    use crate::common::netns::NetNS;

    #[tokio::test]
    async fn best_route_to_resolves_loopback_and_a_real_remote_to_different_scopes() {
        let inventory =
            EgressInventory::start(NetNS::new(None), EgressInventoryConfig::default())
                .await
                .expect("failed to start egress inventory on the real host network");

        let loopback_scope = resolve_egress_scope(
            &inventory,
            "127.0.0.1:0".parse().unwrap(),
            EgressDirection::Egress,
        )
        .await
        .expect("loopback must resolve to a real EgressScope, not fall back");

        // A well-known public IP: routed via this host's real default-route
        // interface, never via loopback -- a route-table lookup, so no
        // actual reachability is required for it to resolve.
        let real_scope = resolve_egress_scope(
            &inventory,
            "1.1.1.1:0".parse().unwrap(),
            EgressDirection::Egress,
        )
        .await
        .expect(
            "a real non-loopback destination must resolve to a real EgressScope, not fall back",
        );

        assert_ne!(
            loopback_scope.stable_id, real_scope.stable_id,
            "loopback and a real routed destination must resolve to different egress scopes"
        );
    }
}

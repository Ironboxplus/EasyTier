use std::{
    collections::{HashMap, hash_map::Entry},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    common::egress_inventory::EgressSocketBinding,
    tunnel::mpquic::{
        MpDatagramPath, PathKey, SharedUdpDatagramPath, SharedUnconnectedUdpDatagramPath, path_key,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CarrierKind {
    UdpDirect,
    UdpPunch,
    FakeTcpPunch,
    RelayNextHop,
    Manual,
}

/// Source-side information for a relay-next-hop carrier.  The downstream
/// route is deliberately not claimed here: only the locally selected direct
/// first hop is observable and controlled by this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RelayPathMetadata {
    /// First hop that distinguishes the virtual end-to-end TQUIC path.
    pub(crate) first_hop_peer_id: crate::common::PeerId,
    /// Direct peer used by this endpoint for actual EasyTier packet egress.
    pub(crate) egress_first_hop_peer_id: crate::common::PeerId,
    pub(crate) route_generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ResourceGroupKind {
    EgressDevice,
    RemoteEndpoint,
    SharedBottleneck,
    AddressFallback,
    UserDefined,
    /// A WAN identified by the public IP the peer observes for a path
    /// (MP_SQM_PLAN.md S2.14); several WANs can share one local NIC.
    Wan,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ResourceGroupId {
    key: String,
    kind: ResourceGroupKind,
}

impl ResourceGroupId {
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self {
            key: value.into(),
            kind: ResourceGroupKind::UserDefined,
        }
    }

    pub(crate) fn egress_device(device: &str) -> Result<Self, String> {
        let device = device.trim();
        if device.is_empty() {
            return Err("egress device name is empty".into());
        }
        if crate::common::config::is_tunnel_or_loopback_device(device) {
            return Err(format!(
                "refusing to use tunnel/loopback interface {device:?} as an SQM egress resource"
            ));
        }
        Ok(Self {
            key: format!("egress-device:{device}"),
            kind: ResourceGroupKind::EgressDevice,
        })
    }

    pub(crate) fn remote_endpoint(addr: SocketAddr) -> Self {
        Self {
            key: format!("remote-endpoint:{}", addr.ip()),
            kind: ResourceGroupKind::RemoteEndpoint,
        }
    }

    pub(crate) fn address_fallback(addr: SocketAddr) -> Self {
        Self {
            key: format!("address-fallback:{}", addr.ip()),
            kind: ResourceGroupKind::AddressFallback,
        }
    }

    pub(crate) fn shared_bottleneck(name: impl Into<String>) -> Self {
        Self {
            key: format!("shared-bottleneck:{}", name.into()),
            kind: ResourceGroupKind::SharedBottleneck,
        }
    }

    pub(crate) fn wan(public_ip: std::net::IpAddr) -> Self {
        Self {
            key: format!("wan:{public_ip}"),
            kind: ResourceGroupKind::Wan,
        }
    }

    pub(crate) fn wan_ip(&self) -> Option<std::net::IpAddr> {
        (self.kind == ResourceGroupKind::Wan)
            .then(|| self.key.strip_prefix("wan:")?.parse().ok())
            .flatten()
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.key
    }

    pub(crate) fn kind(&self) -> ResourceGroupKind {
        self.kind
    }

    pub(crate) fn egress_device_name(&self) -> Option<&str> {
        (self.kind == ResourceGroupKind::EgressDevice)
            .then(|| self.key.strip_prefix("egress-device:"))
            .flatten()
    }
}

#[derive(Clone)]
pub(crate) struct MpPathSpec {
    pub(crate) key: PathKey,
    pub(crate) carrier: Arc<dyn MpDatagramPath>,
    /// Immutable transport-derived resource identities. Runtime resource-group
    /// edits rebuild the effective resources from these bases, so removing or
    /// replacing a group never leaves a path stuck in its former group.
    pub(crate) base_local_resource: ResourceGroupId,
    pub(crate) local_resource: ResourceGroupId,
    /// Physical egress device used for SQM sampling. `local_resource` may be
    /// rewritten to a shared bottleneck group, but this identity must remain
    /// the concrete WAN device whose counters are sampled.
    pub(crate) egress_resource: Option<ResourceGroupId>,
    /// Immutable inventory metadata used to own and reconcile the
    /// connectivity attempt. This is deliberately separate from
    /// `egress_resource`, whose platform-facing device name is consumed by SQM.
    pub(crate) egress_binding: Option<EgressSocketBinding>,
    pub(crate) base_remote_resource: ResourceGroupId,
    pub(crate) remote_resource: ResourceGroupId,
    pub(crate) carrier_kind: CarrierKind,
    pub(crate) relay_metadata: Option<RelayPathMetadata>,
}

impl MpPathSpec {
    /// The NIC this path leaves through, as `MpPathStatus.egress_device`
    /// reports it and path policies match it: the binding's name, else the
    /// egress resource's. Since S2.14 only tests build a binding, and once a
    /// path's WAN is known its `local_resource` names the WAN, not the NIC.
    pub(crate) fn egress_device_name(&self) -> &str {
        self.egress_binding
            .as_ref()
            .map(|binding| binding.platform_name.as_str())
            .or_else(|| {
                self.egress_resource
                    .as_ref()
                    .and_then(|resource| resource.egress_device_name())
            })
            .unwrap_or("")
    }

    pub(crate) fn with_default_resources(
        carrier: Arc<dyn MpDatagramPath>,
        remote_addr: SocketAddr,
        carrier_kind: CarrierKind,
    ) -> Self {
        let local_addr = carrier.local_addr();
        Self::new(
            carrier,
            remote_addr,
            ResourceGroupId::address_fallback(local_addr),
            ResourceGroupId::remote_endpoint(remote_addr),
            carrier_kind,
        )
    }

    pub(crate) fn with_egress_device(
        carrier: Arc<dyn MpDatagramPath>,
        remote_addr: SocketAddr,
        egress_device: &str,
        carrier_kind: CarrierKind,
    ) -> Result<Self, String> {
        Ok(Self::new(
            carrier,
            remote_addr,
            ResourceGroupId::egress_device(egress_device)?,
            ResourceGroupId::remote_endpoint(remote_addr),
            carrier_kind,
        ))
    }

    pub(crate) fn with_egress_binding(
        carrier: Arc<dyn MpDatagramPath>,
        remote_addr: SocketAddr,
        egress_binding: EgressSocketBinding,
        carrier_kind: CarrierKind,
    ) -> Result<Self, String> {
        let mut spec = Self::with_egress_device(
            carrier,
            remote_addr,
            &egress_binding.platform_name,
            carrier_kind,
        )?;
        spec.egress_binding = Some(egress_binding);
        Ok(spec)
    }

    pub(crate) fn new(
        carrier: Arc<dyn MpDatagramPath>,
        remote_addr: SocketAddr,
        local_resource: ResourceGroupId,
        remote_resource: ResourceGroupId,
        carrier_kind: CarrierKind,
    ) -> Self {
        let key = path_key(&carrier, remote_addr);
        let egress_resource = (local_resource.kind() == ResourceGroupKind::EgressDevice)
            .then(|| local_resource.clone());
        Self {
            key,
            carrier,
            base_local_resource: local_resource.clone(),
            local_resource,
            egress_resource,
            egress_binding: None,
            base_remote_resource: remote_resource.clone(),
            remote_resource,
            carrier_kind,
            relay_metadata: None,
        }
    }

    pub(crate) fn with_relay_metadata(
        mut self,
        first_hop_peer_id: crate::common::PeerId,
        egress_first_hop_peer_id: crate::common::PeerId,
        route_generation: u64,
    ) -> Self {
        self.relay_metadata = Some(RelayPathMetadata {
            first_hop_peer_id,
            egress_first_hop_peer_id,
            route_generation,
        });
        self
    }
}

/// A path is being validated, established, or gone. This is the whole of
/// iroh's path model (`remote_state.rs` handles only `Established`,
/// `Abandoned` and `Discarded`, and `PathStatus` is `Available` or `Backup`)
/// and of noq's: a validated path carries data and its congestion control
/// decides how much (draft-ietf-quic-multipath Section 5.5). It replaces nine
/// states, of which `ProbingBw`/`Eligible` only existed to hold a path back
/// until a bandwidth sample came.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathLifecycleState {
    /// Offered and waiting for the peer to answer the path challenge.
    Validating,
    /// Validated. `standby` paths carry data only while no available path is
    /// left (draft-ietf-quic-multipath Section 3.3 backup status).
    Established { standby: bool },
    Dead,
}

impl PathLifecycleState {
    /// Established and used for data (iroh `PathStatus::Available`).
    pub(crate) const AVAILABLE: Self = Self::Established { standby: false };
    /// Established but kept for failover (iroh `PathStatus::Backup`).
    pub(crate) const STANDBY: Self = Self::Established { standby: true };

    /// Validated: selectable, selected, or on standby. A path needs no
    /// bandwidth sample to be used once its validation succeeded.
    pub(crate) fn is_established(self) -> bool {
        matches!(self, Self::Established { .. })
    }

    /// The name `MpPathStatus.lifecycle_state` reports.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Validating => "validating",
            Self::Established { standby: false } => "available",
            Self::Established { standby: true } => "standby",
            Self::Dead => "dead",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct PathMeasurements {
    pub(crate) btlbw: u64,
    pub(crate) delivery_rate: u64,
    /// The path's propagation delay: the smallest round trip of the last 300 s
    /// (`tquic::PathStats::windowed_min_rtt`, Linux's windowed `tcp_min_rtt`), without
    /// the queueing a smoothed RTT carries. The path selector ranks by this, not
    /// `srtt`: a path loaded with our own traffic looks slow by its own queue,
    /// and a standby path's smoothed RTT stays where its last load left it.
    pub(crate) propagation_rtt_micros: u64,
    pub(crate) loss_rate: f64,
    pub(crate) app_limited: bool,
    pub(crate) sample_age_micros: Option<u64>,
    pub(crate) congestion_control_state: tquic::CongestionControlState,
    /// Our own public endpoint as the peer sees it on this path (TQUIC
    /// OBSERVED_ADDRESS). Its IP identifies the WAN the path leaves through.
    pub(crate) observed_local_addr: Option<SocketAddr>,
}

pub(crate) struct PathCandidate {
    pub(crate) spec: MpPathSpec,
    pub(crate) state: PathLifecycleState,
    pub(crate) measurements: PathMeasurements,
    pub(crate) last_seen: Instant,
    /// TQUIC's cumulative (sent, lost) bytes at the last sample.
    traffic_counters: (u64, u64),
    /// Moving average of the share of bytes lost (see `record_traffic`).
    pub(crate) recent_loss: Option<f64>,
    /// TQUIC's cumulative received bytes when the path was first sampled as
    /// usable, and whether more arrived since (see `record_received`).
    received: Option<(u64, bool)>,
    /// Whether what is sent on the path still gets acknowledged (see
    /// `record_acks`).
    acks: AckProgress,
}

/// TQUIC's cumulative (sent, acked) bytes of a path at the last sample where
/// its acked count moved, and since when bytes sent after that went without
/// any acknowledgement.
#[derive(Debug, Clone, Copy, Default)]
struct AckProgress {
    sent: u64,
    acked: u64,
    unacked_since: Option<Instant>,
    unacked: bool,
}

/// ET: how long bytes sent on a path may go without any acknowledgement
/// before the path counts as unacked: three probe timeouts, at least 1 s,
/// the probe timeout estimated as `last_path_grace` in `tunnel/mpquic.rs`
/// does (`srtt + 4 * rttvar` with `rttvar = srtt / 2`).
///
/// QUIC restarts a path's probe timer on every ack-eliciting packet it
/// sends (RFC 9002 §6.2.1), so a path that keeps carrying a steady trickle
/// of data while every acknowledgement is lost never times out and never
/// backs off (incident 2026-11-05: 13 s of data on such a path while the
/// other one was fine). TCP restarts its retransmission timer only when new
/// data is acknowledged (RFC 6298 §5.3), and Linux MPTCP marks a subflow
/// stale when its last acknowledgement is that old with data outstanding
/// (`mptcp_pm_chk_stale`, net/mptcp/pm.c), then sends on the others.
fn unacked_limit(srtt_micros: u64) -> Duration {
    let pto = srtt_micros.saturating_mul(3);
    Duration::from_micros(pto.saturating_mul(3)).max(Duration::from_secs(1))
}

/// Loss above which a path is kept out of the selection while a path with
/// less loss is usable: the default scheduler sends on the lowest-RTT path
/// whatever it loses, and no rate weighs loss in.
pub(crate) const LOSSY_PATH_LOSS: f64 = 0.10;
/// EasyTier ping loss of a first-hop connection at which it counts as
/// unreachable: every ping of the loss window went unanswered.
pub(crate) const UNREACHABLE_FIRST_HOP_LOSS: f64 = 1.0;

/// ET: how a relay path's physical first hop is doing, from the loss rate of
/// EasyTier's own pings on the connection to it (`PeerConn::loss_rate`). A
/// relay path with little traffic cannot gather the byte-based `recent_loss`
/// (`LOSS_SAMPLE_MIN_BYTES`), but its first hop is pinged all the time.
/// "Unreachable" is a relay whose probes get no answer, which iroh and
/// Tailscale leave out of the ranking (MP_WEAK_NETWORK plan R2); "lossy"
/// reuses [`LOSSY_PATH_LOSS`]. The derive order is the preference order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum FirstHopHealth {
    Clean,
    Lossy,
    Unreachable,
}

impl FirstHopHealth {
    pub(crate) fn from_loss(loss: f64) -> Self {
        if loss >= UNREACHABLE_FIRST_HOP_LOSS {
            Self::Unreachable
        } else if loss > LOSSY_PATH_LOSS {
            Self::Lossy
        } else {
            Self::Clean
        }
    }
}

/// ET: what a relay first hop offers, taken from its best live connection.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct FirstHopQuality {
    /// A connection without a ping answer yet counts as
    /// `UNMEASURED_RTT_MICROS` (RFC 9002 Section 6.2.2), not as the fastest.
    pub(crate) latency_micros: u64,
    pub(crate) loss: f64,
}

impl FirstHopQuality {
    /// The best of a first hop's connections, `(latency_us, loss_rate)` each,
    /// ordered by health, then latency.
    pub(crate) fn best_of(conns: &[(u64, f64)]) -> Option<Self> {
        conns
            .iter()
            .map(|&(latency_us, loss)| Self {
                latency_micros: if latency_us == 0 {
                    super::mp_optimizer::UNMEASURED_RTT_MICROS
                } else {
                    latency_us
                },
                loss,
            })
            .min_by_key(|quality| (quality.health(), quality.latency_micros))
    }

    pub(crate) fn health(&self) -> FirstHopHealth {
        FirstHopHealth::from_loss(self.loss)
    }
}
/// Bytes a sample needs before it moves the loss average.
const LOSS_SAMPLE_MIN_BYTES: u64 = 64 * 1024;

impl PathCandidate {
    pub(crate) fn is_lossy(&self) -> bool {
        self.recent_loss.is_some_and(|loss| loss > LOSSY_PATH_LOSS)
    }

    /// The path was validated and sampled as usable, and nothing has arrived
    /// on it since: the peer never answered over it.
    pub(crate) fn silent_since_validated(&self) -> bool {
        matches!(self.received, Some((_, false)))
    }

    /// Something arrived on the path after it was validated.
    pub(crate) fn heard_since_validated(&self) -> bool {
        matches!(self.received, Some((_, true)))
    }

    /// Bytes sent on the path have gone without any acknowledgement for
    /// longer than `unacked_limit`. Like MPTCP's stale subflow, the path
    /// gives way only to one that is not (see `selection_input`), and any
    /// acknowledgement brings it back.
    pub(crate) fn is_unacked(&self) -> bool {
        self.acks.unacked
    }
}

#[derive(Default)]
pub(crate) struct MpCandidateTable {
    entries: HashMap<PathKey, PathCandidate>,
}

impl MpCandidateTable {
    pub(crate) fn upsert(&mut self, spec: MpPathSpec, now: Instant) -> &mut PathCandidate {
        let key = spec.key;
        match self.entries.entry(key) {
            Entry::Occupied(entry) => {
                let candidate = entry.into_mut();
                candidate.spec = spec;
                candidate.last_seen = now;
                candidate
            }
            Entry::Vacant(entry) => entry.insert(PathCandidate {
                spec,
                state: PathLifecycleState::Validating,
                measurements: PathMeasurements::default(),
                last_seen: now,
                traffic_counters: (0, 0),
                recent_loss: None,
                received: None,
                acks: AckProgress::default(),
            }),
        }
    }

    /// Feeds TQUIC's cumulative sent and acked byte counters of an
    /// established path (see `PathCandidate::is_unacked`). The clock starts
    /// at the first sample that shows bytes sent since the acked count last
    /// moved, not at that acknowledgement: a path that was simply idle is
    /// not unacked the moment it sends again.
    pub(crate) fn record_acks(
        &mut self,
        key: &PathKey,
        sent_bytes: u64,
        acked_bytes: u64,
        srtt_micros: u64,
        now: Instant,
    ) {
        let Some(candidate) = self.entries.get_mut(key) else {
            return;
        };
        let acks = &mut candidate.acks;
        let restarted = sent_bytes < acks.sent || acked_bytes < acks.acked;
        if !candidate.state.is_established() || restarted || acked_bytes > acks.acked {
            // (A restart is a new TQUIC path behind the same key.)
            *acks = AckProgress {
                sent: sent_bytes,
                acked: acked_bytes,
                unacked_since: None,
                unacked: false,
            };
            return;
        }
        if sent_bytes > acks.sent {
            let since = *acks.unacked_since.get_or_insert(now);
            acks.unacked = now.saturating_duration_since(since) >= unacked_limit(srtt_micros);
        }
    }

    /// Feeds TQUIC's cumulative sent/lost byte counters into the path's loss
    /// average: once at least `LOSS_SAMPLE_MIN_BYTES` were sent since the
    /// last sample, its loss share moves the average by a third.
    pub(crate) fn record_traffic(&mut self, key: &PathKey, sent_bytes: u64, lost_bytes: u64) {
        let Some(candidate) = self.entries.get_mut(key) else {
            return;
        };
        let (last_sent, last_lost) = candidate.traffic_counters;
        // Challenges lost while a punched path is still opening are not
        // what the path loses once it carries data: sample from then on.
        if !candidate.state.is_established() || sent_bytes < last_sent || lost_bytes < last_lost {
            // (Or a new TQUIC path behind the same key: start over.)
            candidate.traffic_counters = (sent_bytes, lost_bytes);
            return;
        }
        let sent = sent_bytes - last_sent;
        if sent < LOSS_SAMPLE_MIN_BYTES {
            return;
        }
        let sample = ((lost_bytes - last_lost) as f64 / sent as f64).min(1.0);
        candidate.recent_loss = Some(match candidate.recent_loss {
            Some(loss) => loss + (sample - loss) / 3.0,
            None => sample,
        });
        candidate.traffic_counters = (sent_bytes, lost_bytes);
    }

    /// Feeds TQUIC's cumulative received-byte counter. The first sample of a
    /// path that can carry traffic is the baseline: the challenge answers that
    /// validated it are already in it.
    pub(crate) fn record_received(&mut self, key: &PathKey, recv_bytes: u64) {
        let Some(candidate) = self.entries.get_mut(key) else {
            return;
        };
        if !candidate.state.is_established() {
            candidate.received = None;
            return;
        }
        candidate.received = match candidate.received {
            None => Some((recv_bytes, false)),
            // (A new TQUIC path behind the same key: start over.)
            Some((baseline, _)) if recv_bytes < baseline => Some((recv_bytes, false)),
            Some((baseline, heard)) => Some((baseline, heard || recv_bytes > baseline)),
        };
    }

    pub(crate) fn get_mut(&mut self, key: &PathKey) -> Option<&mut PathCandidate> {
        self.entries.get_mut(key)
    }

    pub(crate) fn get(&self, key: &PathKey) -> Option<&PathCandidate> {
        self.entries.get(key)
    }

    pub(crate) fn key_for_addresses(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Option<PathKey> {
        self.entries
            .keys()
            .find(|key| key.local_addr == local_addr && key.remote_addr == remote_addr)
            .copied()
    }

    /// A server-side symmetric-NAT carrier is registered with `0.0.0.0:0`
    /// before the first TQUIC Initial reveals the real endpoint.  Promote that
    /// provisional entry immediately so telemetry and target-rate operations
    /// use the actual path key thereafter.
    pub(crate) fn resolve_wildcard_remote(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Option<PathKey> {
        let resolved_key = self.key_for_addresses(local_addr, remote_addr);
        if resolved_key.is_some() {
            return resolved_key;
        }
        let wildcard_key = self
            .entries
            .keys()
            .find(|key| {
                key.local_addr == local_addr
                    && key.remote_addr.ip().is_unspecified()
                    && key.remote_addr.port() == 0
            })
            .copied()?;
        let resolved_key = PathKey {
            carrier_id: wildcard_key.carrier_id,
            local_addr,
            remote_addr,
        };
        let mut candidate = self.entries.remove(&wildcard_key)?;
        candidate.spec.key = resolved_key;
        let remote_resource = ResourceGroupId::remote_endpoint(remote_addr);
        candidate.spec.base_remote_resource = remote_resource.clone();
        candidate.spec.remote_resource = remote_resource;
        self.entries.insert(resolved_key, candidate);
        Some(resolved_key)
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&PathKey, &PathCandidate)> {
        self.entries.iter()
    }

    /// Candidates of one carrier kind that are not dead.
    /// Live candidates that are not relayed: whatever carrier they use, they
    /// are a direct path to the peer.
    pub(crate) fn live_direct(&self) -> impl Iterator<Item = &PathCandidate> {
        self.entries.values().filter(|candidate| {
            candidate.spec.carrier_kind != CarrierKind::RelayNextHop
                && candidate.state != PathLifecycleState::Dead
        })
    }

    pub(crate) fn live_of_kind(
        &self,
        kind: CarrierKind,
    ) -> impl Iterator<Item = &PathCandidate> {
        self.entries.values().filter(move |candidate| {
            candidate.spec.carrier_kind == kind && candidate.state != PathLifecycleState::Dead
        })
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = (&PathKey, &mut PathCandidate)> {
        self.entries.iter_mut()
    }

    pub(crate) fn set_state(&mut self, key: &PathKey, state: PathLifecycleState) -> bool {
        let Some(candidate) = self.entries.get_mut(key) else {
            return false;
        };
        candidate.state = state;
        true
    }

    pub(crate) fn begin_validation(&mut self, key: &PathKey) -> bool {
        let Some(candidate) = self.entries.get_mut(key) else {
            return false;
        };
        candidate.state = PathLifecycleState::Validating;
        true
    }

    /// A validated path is established and available at once: it needs no
    /// bandwidth sample to carry data (draft-ietf-quic-multipath Section 5.5;
    /// noq, picoquic, iroh and Linux MPTCP all work this way), and its
    /// congestion control decides how much. A path that is already
    /// established keeps its standby flag.
    pub(crate) fn record_validation(&mut self, key: &PathKey, succeeded: bool) -> bool {
        let Some(candidate) = self.entries.get_mut(key) else {
            return false;
        };
        candidate.state = match (succeeded, candidate.state) {
            (true, state @ PathLifecycleState::Established { .. }) => state,
            (true, _) => PathLifecycleState::AVAILABLE,
            (false, _) => PathLifecycleState::Dead,
        };
        true
    }

    pub(crate) fn observe_measurements(
        &mut self,
        key: &PathKey,
        measurements: PathMeasurements,
    ) -> bool {
        let Some(candidate) = self.entries.get_mut(key) else {
            return false;
        };
        // A relay path's observed address is its virtual overlay address,
        // not a public IP: it names no WAN.
        if let Some(observed) = measurements.observed_local_addr
            && candidate.spec.carrier_kind != CarrierKind::RelayNextHop
        {
            // MP_SQM_PLAN.md S2.14: once the peer reports which public IP it
            // sees, the path belongs to that WAN. A user resource-group
            // override of the local resource stays in effect.
            let wan = ResourceGroupId::wan(observed.ip());
            if candidate.spec.base_local_resource != wan {
                let overridden =
                    candidate.spec.local_resource != candidate.spec.base_local_resource;
                candidate.spec.base_local_resource = wan.clone();
                if !overridden {
                    candidate.spec.local_resource = wan;
                }
            }
        }
        candidate.measurements = measurements;
        true
    }

    pub(crate) fn mark_dead(&mut self, key: &PathKey) -> bool {
        let Some(candidate) = self.entries.get_mut(key) else {
            return false;
        };
        candidate.state = PathLifecycleState::Dead;
        true
    }

    pub(crate) fn mark_all_dead(&mut self) -> usize {
        for candidate in self.entries.values_mut() {
            candidate.state = PathLifecycleState::Dead;
        }
        self.entries.len()
    }

    pub(crate) fn prune_failed_and_stale_validations(
        &mut self,
        now: Instant,
        validation_timeout: std::time::Duration,
    ) -> Vec<PathKey> {
        let removed = self
            .entries
            .iter()
            .filter_map(|(key, candidate)| {
                let validation_expired = candidate.state == PathLifecycleState::Validating
                    && now.saturating_duration_since(candidate.last_seen) >= validation_timeout;
                (candidate.state == PathLifecycleState::Dead || validation_expired).then_some(*key)
            })
            .collect::<Vec<_>>();
        for key in &removed {
            self.entries.remove(key);
        }
        removed
    }
}

#[async_trait::async_trait]
pub(crate) trait MpPathProvider: Send + Sync {
    fn kind(&self) -> CarrierKind;

    async fn discover(&self) -> anyhow::Result<Vec<MpPathSpec>>;
}

pub(crate) struct StaticMpPathProvider {
    kind: CarrierKind,
    paths: Vec<MpPathSpec>,
}

pub(crate) struct UdpMpPathProvider {
    kind: CarrierKind,
    socket: Arc<tokio::net::UdpSocket>,
    remote_addr: SocketAddr,
    egress_device: Option<String>,
    egress_binding: Option<EgressSocketBinding>,
    lifetime_guard: Option<Arc<dyn Send + Sync>>,
}

impl UdpMpPathProvider {
    pub(crate) fn new(
        kind: CarrierKind,
        socket: Arc<tokio::net::UdpSocket>,
        remote_addr: SocketAddr,
        egress_device: Option<String>,
    ) -> Result<Self, String> {
        if !matches!(
            kind,
            CarrierKind::UdpDirect | CarrierKind::UdpPunch | CarrierKind::Manual
        ) {
            return Err(format!("{kind:?} is not a UDP carrier kind"));
        }
        if let Some(device) = egress_device.as_deref() {
            ResourceGroupId::egress_device(device)?;
        }
        Ok(Self {
            kind,
            socket,
            remote_addr,
            egress_device,
            egress_binding: None,
            lifetime_guard: None,
        })
    }

    /// Punching no longer binds per NIC (MP_SQM_PLAN.md S2.14); an explicit
    /// binding is only built by tests of the binding-aware reconcile path.
    #[cfg(test)]
    pub(crate) fn new_on_egress(
        kind: CarrierKind,
        socket: Arc<tokio::net::UdpSocket>,
        remote_addr: SocketAddr,
        binding: EgressSocketBinding,
    ) -> Result<Self, String> {
        let socket_addr = socket
            .local_addr()
            .map_err(|error| format!("failed to inspect egress-bound UDP socket: {error}"))?;
        if socket_addr != binding.local_addr {
            return Err(format!(
                "egress binding local address {} does not match UDP socket {socket_addr}",
                binding.local_addr
            ));
        }
        let mut provider = Self::new(
            kind,
            socket,
            remote_addr,
            Some(binding.platform_name.clone()),
        )?;
        provider.egress_binding = Some(binding);
        Ok(provider)
    }

    pub(crate) fn with_lifetime_guard(mut self, guard: Arc<dyn Send + Sync>) -> Self {
        self.lifetime_guard = Some(guard);
        self
    }
}

#[async_trait::async_trait]
impl MpPathProvider for UdpMpPathProvider {
    fn kind(&self) -> CarrierKind {
        self.kind
    }

    async fn discover(&self) -> anyhow::Result<Vec<MpPathSpec>> {
        let wildcard_remote =
            self.remote_addr.ip().is_unspecified() && self.remote_addr.port() == 0;
        let carrier: Arc<dyn MpDatagramPath> = if wildcard_remote {
            Arc::new(SharedUnconnectedUdpDatagramPath::new_with_guard(
                self.socket.clone(),
                self.lifetime_guard.clone(),
            )?)
        } else {
            Arc::new(
                SharedUdpDatagramPath::connect_with_guard(
                    self.socket.clone(),
                    self.remote_addr,
                    self.lifetime_guard.clone(),
                )
                .await?,
            )
        };
        let discovered_device = self.egress_device.clone().or_else(|| {
            crate::tunnel::common::get_interface_name_by_ip(&carrier.local_addr().ip())
        });
        let mut spec = if let Some(device) = discovered_device.as_deref() {
            match MpPathSpec::with_egress_device(
                carrier.clone(),
                self.remote_addr,
                device,
                self.kind,
            ) {
                Ok(spec) => spec,
                Err(error) if self.egress_device.is_none() => {
                    tracing::debug!(
                        ?device,
                        ?error,
                        "auto-detected UDP MP interface is not an SQM egress; using address fallback"
                    );
                    MpPathSpec::with_default_resources(carrier, self.remote_addr, self.kind)
                }
                Err(error) => return Err(anyhow::Error::msg(error)),
            }
        } else {
            MpPathSpec::with_default_resources(carrier, self.remote_addr, self.kind)
        };
        spec.egress_binding = self.egress_binding.clone();
        Ok(vec![spec])
    }
}

impl StaticMpPathProvider {
    pub(crate) fn new(kind: CarrierKind, paths: Vec<MpPathSpec>) -> Self {
        Self { kind, paths }
    }
}

#[async_trait::async_trait]
impl MpPathProvider for StaticMpPathProvider {
    fn kind(&self) -> CarrierKind {
        self.kind
    }

    async fn discover(&self) -> anyhow::Result<Vec<MpPathSpec>> {
        Ok(self.paths.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    struct MockDatagramPath {
        local: SocketAddr,
    }

    #[async_trait::async_trait]
    impl MpDatagramPath for MockDatagramPath {
        fn local_addr(&self) -> SocketAddr {
            self.local
        }

        fn try_send_to(&self, payload: &[u8], _remote: SocketAddr) -> std::io::Result<usize> {
            Ok(payload.len())
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
    }

    fn spec() -> MpPathSpec {
        let carrier: Arc<dyn MpDatagramPath> = Arc::new(MockDatagramPath {
            local: "127.0.0.1:33001".parse().unwrap(),
        });
        MpPathSpec::new(
            carrier,
            "127.0.0.1:34001".parse().unwrap(),
            ResourceGroupId::new("local-wan"),
            ResourceGroupId::new("remote-wan"),
            CarrierKind::UdpPunch,
        )
    }

    fn egress_binding(
        egress: crate::common::egress_inventory::EgressStableId,
        local_addr: SocketAddr,
        target: std::net::IpAddr,
        generation: u64,
        inventory_revision: u64,
    ) -> EgressSocketBinding {
        let runtime_ifindex = match &egress {
            crate::common::egress_inventory::EgressStableId::Linux { ifindex, .. } => *ifindex,
            _ => 0,
        };
        EgressSocketBinding {
            egress: egress.clone(),
            generation,
            inventory_revision,
            runtime_ifindex,
            platform_name: "wan-test".into(),
            local_addr,
            route: crate::common::egress_inventory::RouteResolution {
                target,
                requested_egress: Some(egress.clone()),
                selected_egress: Some(egress),
                output_ifindex: runtime_ifindex,
                source: Some(local_addr.ip()),
                gateway: None,
                metric: None,
                table: None,
                inventory_revision,
            },
        }
    }

    #[test]
    fn refreshing_the_same_path_preserves_lifecycle_and_measurements() {
        let mut table = MpCandidateTable::default();
        let first = spec();
        let now = Instant::now();
        let candidate = table.upsert(first.clone(), now);
        candidate.state = PathLifecycleState::AVAILABLE;
        candidate.measurements.btlbw = 123_000_000;

        let refreshed = table.upsert(first, now + std::time::Duration::from_secs(1));

        assert_eq!(refreshed.state, PathLifecycleState::AVAILABLE);
        assert_eq!(refreshed.measurements.btlbw, 123_000_000);
        assert_eq!(refreshed.last_seen, now + std::time::Duration::from_secs(1));
    }

    #[tokio::test]
    async fn all_provider_kinds_return_the_same_path_spec_contract() {
        for kind in [
            CarrierKind::UdpDirect,
            CarrierKind::UdpPunch,
            CarrierKind::FakeTcpPunch,
            CarrierKind::RelayNextHop,
            CarrierKind::Manual,
        ] {
            let mut path = spec();
            path.carrier_kind = kind;
            let expected_key = path.key;
            let provider = StaticMpPathProvider::new(kind, vec![path]);

            assert_eq!(provider.kind(), kind);
            let discovered = provider.discover().await.unwrap();
            assert_eq!(discovered.len(), 1);
            assert_eq!(discovered[0].key, expected_key);
            assert_eq!(discovered[0].carrier_kind, kind);
        }
    }

    #[tokio::test]
    async fn udp_provider_delivers_the_punched_socket_as_a_real_mp_carrier() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let remote = "127.0.0.1:34009".parse().unwrap();
        let provider = UdpMpPathProvider::new(
            CarrierKind::UdpPunch,
            socket.clone(),
            remote,
            Some("Ethernet 2".into()),
        )
        .unwrap();

        let paths = provider.discover().await.unwrap();

        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].key.local_addr, socket.local_addr().unwrap());
        assert_eq!(paths[0].key.remote_addr, remote);
        assert_eq!(paths[0].carrier_kind, CarrierKind::UdpPunch);
        assert_eq!(
            paths[0].egress_resource.as_ref().unwrap().as_str(),
            "egress-device:Ethernet 2"
        );
    }

    #[tokio::test]
    async fn egress_bound_udp_provider_preserves_stable_inventory_identity() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = socket.local_addr().unwrap();
        let remote = "127.0.0.1:34010".parse().unwrap();
        let egress = crate::common::egress_inventory::EgressStableId::Linux {
            netns_inode: 7,
            ifindex: 11,
        };
        let provider = UdpMpPathProvider::new_on_egress(
            CarrierKind::UdpPunch,
            socket,
            remote,
            egress_binding(egress.clone(), local_addr, remote.ip(), 3, 9),
        )
        .unwrap();

        let paths = provider.discover().await.unwrap();

        assert_eq!(paths.len(), 1);
        let binding = paths[0].egress_binding.as_ref().unwrap();
        assert_eq!(binding.egress, egress);
        assert_eq!(binding.generation, 3);
        assert_eq!(binding.inventory_revision, 9);
        assert_eq!(binding.runtime_ifindex, 11);
        assert_eq!(
            paths[0].egress_resource.as_ref().unwrap().as_str(),
            "egress-device:wan-test"
        );
    }

    #[tokio::test]
    async fn egress_bound_udp_provider_rejects_mismatched_socket_metadata() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let other_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = "127.0.0.1:34011".parse().unwrap();
        let egress = crate::common::egress_inventory::EgressStableId::Linux {
            netns_inode: 7,
            ifindex: 12,
        };
        let mismatched_local_addr = other_socket.local_addr().unwrap();

        let error = match UdpMpPathProvider::new_on_egress(
            CarrierKind::UdpPunch,
            socket,
            remote,
            egress_binding(egress, mismatched_local_addr, remote.ip(), 1, 1),
        ) {
            Ok(_) => panic!("mismatched egress binding was accepted"),
            Err(error) => error,
        };

        assert!(error.contains("does not match UDP socket"));
    }

    #[tokio::test]
    async fn wildcard_udp_provider_keeps_the_server_socket_unconnected() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wildcard = "0.0.0.0:0".parse().unwrap();
        let provider =
            UdpMpPathProvider::new(CarrierKind::UdpPunch, socket.clone(), wildcard, None).unwrap();
        let paths = provider.discover().await.unwrap();

        loop {
            match paths[0]
                .carrier
                .try_send_to(b"reply-after-learn", receiver.local_addr().unwrap())
            {
                Ok(_) => break,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    socket.writable().await.unwrap();
                }
                Err(error) => panic!("unconnected MP carrier send failed: {error}"),
            }
        }
        let mut received = [0u8; 64];
        let (n, source) = receiver.recv_from(&mut received).await.unwrap();
        assert_eq!(&received[..n], b"reply-after-learn");
        assert_eq!(source, socket.local_addr().unwrap());

        receiver
            .send_to(b"first-initial", socket.local_addr().unwrap())
            .await
            .unwrap();
        let mut inbound = [0u8; 64];
        let (n, remote) = paths[0].carrier.recv_from(&mut inbound).await.unwrap();
        assert_eq!(&inbound[..n], b"first-initial");
        assert_eq!(remote, receiver.local_addr().unwrap());
    }

    #[test]
    fn wildcard_candidate_is_promoted_when_the_server_learns_the_peer_endpoint() {
        let mut table = MpCandidateTable::default();
        let mut wildcard = spec();
        wildcard.key.remote_addr = "0.0.0.0:0".parse().unwrap();
        wildcard.remote_resource = ResourceGroupId::remote_endpoint(wildcard.key.remote_addr);
        let wildcard_key = wildcard.key;
        table.upsert(wildcard, Instant::now());

        let remote: SocketAddr = "198.51.100.42:45678".parse().unwrap();
        let resolved = table
            .resolve_wildcard_remote(wildcard_key.local_addr, remote)
            .expect("wildcard path should be promoted");

        assert_eq!(resolved.remote_addr, remote);
        assert!(table.get(&wildcard_key).is_none());
        let candidate = table.get(&resolved).unwrap();
        assert_eq!(candidate.spec.key, resolved);
        assert_eq!(
            candidate.spec.remote_resource.as_str(),
            "remote-endpoint:198.51.100.42"
        );
    }

    #[test]
    fn default_resource_groups_ignore_ephemeral_ports() {
        let first_carrier: Arc<dyn MpDatagramPath> = Arc::new(MockDatagramPath {
            local: "192.0.2.10:33001".parse().unwrap(),
        });
        let second_carrier: Arc<dyn MpDatagramPath> = Arc::new(MockDatagramPath {
            local: "192.0.2.10:33002".parse().unwrap(),
        });
        let first = MpPathSpec::with_default_resources(
            first_carrier,
            "198.51.100.20:34001".parse().unwrap(),
            CarrierKind::UdpPunch,
        );
        let second = MpPathSpec::with_default_resources(
            second_carrier,
            "198.51.100.20:34002".parse().unwrap(),
            CarrierKind::FakeTcpPunch,
        );

        assert_eq!(first.local_resource, second.local_resource);
        assert_eq!(first.remote_resource, second.remote_resource);
        assert_eq!(
            first.local_resource.kind(),
            ResourceGroupKind::AddressFallback
        );
        assert_eq!(
            first.remote_resource.kind(),
            ResourceGroupKind::RemoteEndpoint
        );
    }

    #[test]
    fn sqm_egress_resource_rejects_tun_and_accepts_physical_device() {
        for name in ["tun0", "utun5", "Wintun", "EasyTier", "lo"] {
            assert!(
                ResourceGroupId::egress_device(name).is_err(),
                "{name} must never become an SQM egress resource"
            );
        }

        let ethernet = ResourceGroupId::egress_device("Ethernet 2").unwrap();
        assert_eq!(ethernet.kind(), ResourceGroupKind::EgressDevice);
        assert_eq!(ethernet.as_str(), "egress-device:Ethernet 2");
    }

    #[test]
    fn failed_path_validation_never_enters_eligible() {
        let mut table = MpCandidateTable::default();
        let path = spec();
        let key = path.key;
        table.upsert(path, Instant::now());

        assert!(table.begin_validation(&key));
        assert_eq!(
            table.get_mut(&key).unwrap().state,
            PathLifecycleState::Validating
        );
        assert!(table.record_validation(&key, false));
        assert_eq!(table.get_mut(&key).unwrap().state, PathLifecycleState::Dead);
    }

    #[test]
    fn failed_and_stale_validating_candidates_are_pruned() {
        let mut table = MpCandidateTable::default();
        let now = Instant::now();

        let failed = spec();
        let failed_key = failed.key;
        table.upsert(failed, now - std::time::Duration::from_secs(20));
        table.begin_validation(&failed_key);
        table.record_validation(&failed_key, false);

        let stale = spec();
        let stale_key = stale.key;
        table.upsert(stale, now - std::time::Duration::from_secs(11));
        table.begin_validation(&stale_key);

        let fresh = spec();
        let fresh_key = fresh.key;
        table.upsert(fresh, now - std::time::Duration::from_secs(5));
        table.begin_validation(&fresh_key);

        let active = spec();
        let active_key = active.key;
        table.upsert(active, now - std::time::Duration::from_secs(20));
        table.set_state(&active_key, PathLifecycleState::AVAILABLE);

        let removed =
            table.prune_failed_and_stale_validations(now, std::time::Duration::from_secs(10));

        assert_eq!(removed.len(), 2);
        assert!(removed.contains(&failed_key));
        assert!(removed.contains(&stale_key));
        assert!(table.get(&failed_key).is_none());
        assert!(table.get(&stale_key).is_none());
        assert_eq!(
            table.get(&fresh_key).unwrap().state,
            PathLifecycleState::Validating
        );
        assert_eq!(
            table.get(&active_key).unwrap().state,
            PathLifecycleState::AVAILABLE
        );
    }

    #[test]
    fn peer_observed_address_moves_the_path_into_its_wan_group() {
        let mut table = MpCandidateTable::default();
        let path = spec();
        let key = path.key;
        table.upsert(path, Instant::now());
        let observed: SocketAddr = "198.51.100.7:40000".parse().unwrap();

        table.observe_measurements(
            &key,
            PathMeasurements {
                observed_local_addr: Some(observed),
                ..PathMeasurements::default()
            },
        );

        let candidate = table.get(&key).unwrap();
        assert_eq!(candidate.spec.local_resource, ResourceGroupId::wan(observed.ip()));
        assert_eq!(candidate.spec.local_resource.kind(), ResourceGroupKind::Wan);
        assert_eq!(candidate.spec.local_resource.wan_ip(), Some(observed.ip()));

        // A user override of the local resource survives a later report.
        let group = ResourceGroupId::shared_bottleneck("office");
        table.get_mut(&key).unwrap().spec.local_resource = group.clone();
        let moved: SocketAddr = "203.0.113.9:40000".parse().unwrap();
        table.observe_measurements(
            &key,
            PathMeasurements {
                observed_local_addr: Some(moved),
                ..PathMeasurements::default()
            },
        );
        let candidate = table.get(&key).unwrap();
        assert_eq!(candidate.spec.local_resource, group);
        assert_eq!(candidate.spec.base_local_resource, ResourceGroupId::wan(moved.ip()));
    }

    /// The NIC stays reported (and matchable by path policies) after the
    /// path's resource moves to its WAN; without a NIC it is empty.
    #[test]
    fn egress_device_name_survives_the_move_into_the_wan_group() {
        let carrier: Arc<dyn MpDatagramPath> = Arc::new(MockDatagramPath {
            local: "198.19.2.2:33001".parse().unwrap(),
        });
        let remote: SocketAddr = "198.18.0.21:34001".parse().unwrap();
        let mut table = MpCandidateTable::default();
        let path =
            MpPathSpec::with_egress_device(carrier.clone(), remote, "a2", CarrierKind::UdpDirect)
                .unwrap();
        let key = path.key;
        table.upsert(path, Instant::now());
        table.observe_measurements(
            &key,
            PathMeasurements {
                observed_local_addr: Some("198.19.2.2:33001".parse().unwrap()),
                ..PathMeasurements::default()
            },
        );
        let candidate = table.get(&key).unwrap();
        assert_eq!(candidate.spec.local_resource.kind(), ResourceGroupKind::Wan);
        assert_eq!(candidate.spec.egress_device_name(), "a2");

        let plain = MpPathSpec::with_default_resources(carrier, remote, CarrierKind::UdpDirect);
        assert_eq!(plain.egress_device_name(), "");
    }

    /// P4-B: a path that answered its challenge is available at once, with no
    /// bandwidth sample at all. Red on the 9-state machine: `record_validation`
    /// left it in `ProbingBw`, out of use until a fresh sample promoted it.
    #[test]
    fn validated_path_is_available_without_any_bandwidth_sample() {
        let mut table = MpCandidateTable::default();
        let path = spec();
        let key = path.key;
        table.upsert(path, Instant::now());
        table.begin_validation(&key);
        assert_eq!(table.get(&key).unwrap().state, PathLifecycleState::Validating);

        table.record_validation(&key, true);
        assert_eq!(table.get(&key).unwrap().state, PathLifecycleState::AVAILABLE);
        assert!(table.get(&key).unwrap().state.is_established());

        // A sample of any kind -- stale, empty, app-limited -- changes nothing
        // about whether the path may carry data.
        for sample in [
            PathMeasurements::default(),
            PathMeasurements {
                btlbw: 1_000,
                delivery_rate: 900,
                app_limited: true,
                sample_age_micros: Some(60_000_000),
                ..PathMeasurements::default()
            },
        ] {
            table.observe_measurements(&key, sample);
            assert_eq!(table.get(&key).unwrap().state, PathLifecycleState::AVAILABLE);
        }
    }

    /// Validating a path again (the offer that built the session confirms its
    /// own path) must not take a path off standby.
    #[test]
    fn revalidating_an_established_path_keeps_its_standby_flag() {
        let mut table = MpCandidateTable::default();
        let path = spec();
        let key = path.key;
        table.upsert(path, Instant::now());
        table.record_validation(&key, true);
        table.set_state(&key, PathLifecycleState::STANDBY);
        table.record_validation(&key, true);
        assert_eq!(table.get(&key).unwrap().state, PathLifecycleState::STANDBY);
    }

    #[tokio::test]
    async fn udp_provider_keeps_the_nat_mapping_lease_for_the_path_lifetime() {
        struct DropGuard(Arc<AtomicBool>);
        impl Drop for DropGuard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let remote: SocketAddr = "127.0.0.1:39091".parse().unwrap();
        let provider = UdpMpPathProvider::new(
            CarrierKind::UdpPunch,
            socket,
            remote,
            Some("Ethernet 2".into()),
        )
        .unwrap()
        .with_lifetime_guard(Arc::new(DropGuard(dropped.clone())));

        let paths = provider.discover().await.unwrap();
        drop(provider);
        assert!(!dropped.load(Ordering::Relaxed));
        drop(paths);
        assert!(dropped.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn auto_detected_loopback_never_becomes_an_sqm_egress_resource() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let remote: SocketAddr = "127.0.0.1:39092".parse().unwrap();
        let provider = UdpMpPathProvider::new(CarrierKind::UdpPunch, socket, remote, None).unwrap();

        let paths = provider.discover().await.unwrap();
        assert_eq!(paths.len(), 1);
        assert!(paths[0].egress_resource.is_none());
        assert_eq!(
            paths[0].local_resource.kind(),
            ResourceGroupKind::AddressFallback
        );
    }

    /// White-box: the three-state lifecycle through every state that
    /// `MpCandidateTable` can enter via public mutators.
    ///
    /// ```text
    /// Validating --record_validation(ok)--> Established{available}
    ///            --set_state(standby)--> Established{standby}
    ///            --mark_dead--> Dead --prune--> removed
    /// ```
    #[test]
    fn path_lifecycle_automaton_happy_path_and_prune() {
        let sp = spec();
        let key = sp.key;
        let mut table = MpCandidateTable::default();
        table.upsert(sp, Instant::now());
        assert_eq!(
            table.get(&key).unwrap().state,
            PathLifecycleState::Validating
        );

        assert!(table.begin_validation(&key));
        assert_eq!(
            table.get(&key).unwrap().state,
            PathLifecycleState::Validating
        );

        assert!(table.record_validation(&key, true));
        assert_eq!(
            table.get(&key).unwrap().state,
            PathLifecycleState::AVAILABLE
        );

        // Measurements are reported as they come; a standby path's decayed
        // bandwidth estimate is simply what it is now (nothing weighs it).
        let sample = PathMeasurements {
            btlbw: 1_000_000,
            delivery_rate: 900_000,
            propagation_rtt_micros: 20_000,
            ..PathMeasurements::default()
        };
        assert!(table.observe_measurements(&key, sample.clone()));
        assert!(table.set_state(&key, PathLifecycleState::STANDBY));
        let idle = PathMeasurements {
            btlbw: 10_000,
            delivery_rate: 8_000,
            ..sample
        };
        assert!(table.observe_measurements(&key, idle));
        assert_eq!(table.get(&key).unwrap().measurements.btlbw, 10_000);

        for (state, name) in [
            (PathLifecycleState::AVAILABLE, "available"),
            (PathLifecycleState::STANDBY, "standby"),
            (PathLifecycleState::Validating, "validating"),
        ] {
            assert!(table.set_state(&key, state));
            assert_eq!(table.get(&key).unwrap().state, state);
            assert_eq!(state.as_str(), name);
        }

        assert!(table.mark_dead(&key));
        assert_eq!(table.get(&key).unwrap().state, PathLifecycleState::Dead);
        assert_eq!(PathLifecycleState::Dead.as_str(), "dead");
        let pruned = table
            .prune_failed_and_stale_validations(Instant::now(), std::time::Duration::from_secs(1));
        assert!(pruned.contains(&key));
        assert!(table.get(&key).is_none());
    }

    #[test]
    fn path_lifecycle_failed_validation_goes_dead_without_becoming_available() {
        let sp = spec();
        let key = sp.key;
        let mut table = MpCandidateTable::default();
        table.upsert(sp, Instant::now());
        table.begin_validation(&key);
        assert!(table.record_validation(&key, false));
        assert_eq!(table.get(&key).unwrap().state, PathLifecycleState::Dead);
    }

    #[test]
    fn mark_all_dead_and_missing_key_mutators_are_safe() {
        let sp = spec();
        let key = sp.key;
        let missing = PathKey {
            carrier_id: crate::tunnel::mpquic::CarrierId(999),
            local_addr: "127.0.0.1:1".parse().unwrap(),
            remote_addr: "127.0.0.1:2".parse().unwrap(),
        };
        let mut table = MpCandidateTable::default();
        table.upsert(sp, Instant::now());
        assert!(!table.begin_validation(&missing));
        assert!(!table.record_validation(&missing, true));
        assert!(!table.set_state(&missing, PathLifecycleState::AVAILABLE));
        assert!(!table.mark_dead(&missing));
        assert!(!table.observe_measurements(&missing, PathMeasurements::default()));
        assert_eq!(table.mark_all_dead(), 1);
        assert_eq!(table.get(&key).unwrap().state, PathLifecycleState::Dead);
    }

    /// The loss average moves only on samples of enough bytes, and a reset
    /// counter (a new TQUIC path) starts it over.
    #[test]
    fn loss_average_tracks_sampled_traffic() {
        let sp = spec();
        let key = sp.key;
        let mut table = MpCandidateTable::default();
        table.upsert(sp, Instant::now());
        let loss = |table: &MpCandidateTable| table.get(&key).unwrap().recent_loss;

        table.set_state(&key, PathLifecycleState::AVAILABLE);
        table.record_traffic(&key, 1_000, 500);
        assert_eq!(loss(&table), None, "too few bytes for a sample");
        table.record_traffic(&key, 100_000, 40_000);
        assert!((loss(&table).unwrap() - 0.4).abs() < 1e-9, "first sample sets it");
        assert!(table.get(&key).unwrap().is_lossy());
        table.record_traffic(&key, 200_000, 40_000);
        assert!((loss(&table).unwrap() - 0.4 * 2.0 / 3.0).abs() < 1e-9, "a clean sample pulls it down a third");
        for sent in [300_000, 400_000, 500_000] {
            table.record_traffic(&key, sent, 40_000);
        }
        assert!(!table.get(&key).unwrap().is_lossy(), "three more clean samples clear it");
        table.record_traffic(&key, 10, 0);
        assert!(!table.get(&key).unwrap().is_lossy(), "a counter reset keeps the average");
    }

    /// Challenges lost while a punched path is opening are not path loss.
    #[test]
    fn loss_sampling_starts_once_the_path_can_carry_data() {
        let sp = spec();
        let key = sp.key;
        let mut table = MpCandidateTable::default();
        table.upsert(sp, Instant::now());
        table.record_traffic(&key, 90_000, 60_000);
        assert_eq!(table.get(&key).unwrap().recent_loss, None);
        table.set_state(&key, PathLifecycleState::AVAILABLE);
        table.record_traffic(&key, 190_000, 61_000);
        assert!((table.get(&key).unwrap().recent_loss.unwrap() - 0.01).abs() < 1e-9);
    }

}

//! TQUIC datagram carriers whose first EasyTier hop is a selected direct peer.
//!
//! A relay candidate is not a claimed immutable end-to-end route.  It pins only
//! the locally controlled first hop until the next route-table generation.  The
//! stock EasyTier relay data plane forwards the opaque TQUIC datagram afterwards.

use std::{
    io,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use dashmap::{DashMap, mapref::entry::Entry};
use tokio::sync::{Mutex, mpsc};

use crate::{
    common::PeerId,
    connector::mp_path::{CarrierKind, MpPathSpec, ResourceGroupId},
    tunnel::mpquic::MpDatagramPath,
};

const RELAY_DATAGRAM_MAGIC: [u8; 4] = *b"ETMR";
const RELAY_DATAGRAM_VERSION: u8 = 2;
const VIRTUAL_ADDR_WIRE_LEN: usize = 18;
const RELAY_DATAGRAM_HEADER_LEN: usize = 4 + 1 + 4 + 4 + 4 + 4 + 8 + VIRTUAL_ADDR_WIRE_LEN * 2;
/// One warning per this many datagrams dropped into full inbound queues.
const INBOUND_FULL_DROPS_PER_WARNING: u64 = 256;

/// A stable TQUIC path identity for a source-selected relay first hop.
///
/// The socket addresses are virtual: they are never passed to the operating
/// system.  TQUIC still needs stable, distinct `(local, remote)` addresses to
/// distinguish its paths while `RelayNextHopDatagramPath` carries the payload
/// through EasyTier's relay plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RelayPathIdentity {
    pub(crate) source_peer_id: PeerId,
    pub(crate) destination_peer_id: PeerId,
    /// The source-selected hop encoded into the TQUIC virtual path identity.
    pub(crate) first_hop_peer_id: PeerId,
    pub(crate) route_generation: u64,
    pub(crate) local_addr: SocketAddr,
    pub(crate) remote_addr: SocketAddr,
}

impl RelayPathIdentity {
    pub(crate) fn from_origin(
        source_peer_id: PeerId,
        destination_peer_id: PeerId,
        first_hop_peer_id: PeerId,
        route_generation: u64,
    ) -> Self {
        Self {
            source_peer_id,
            destination_peer_id,
            first_hop_peer_id,
            route_generation,
            local_addr: relay_virtual_addr(source_peer_id, destination_peer_id, first_hop_peer_id),
            remote_addr: relay_virtual_addr(destination_peer_id, source_peer_id, first_hop_peer_id),
        }
    }
}

/// Whether `ip` is a relay path's virtual identity (see `relay_virtual_addr`):
/// what a peer reports as our address on such a path names no WAN.
pub(crate) fn is_relay_virtual_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V6(ip) => ip.segments()[..2] == [0xfd4d, 0x5000],
        std::net::IpAddr::V4(_) => false,
    }
}

fn relay_virtual_addr(
    owner_peer_id: PeerId,
    peer_id: PeerId,
    first_hop_peer_id: PeerId,
) -> SocketAddr {
    // fd4d:5000/32 is an internal ULA-only identity namespace.  It embeds the
    // local owner, final peer, and pinned first hop, so distinct relay choices
    // can coexist in one TQUIC session without aliases.
    let ip = Ipv6Addr::new(
        0xfd4d,
        0x5000,
        (owner_peer_id >> 16) as u16,
        owner_peer_id as u16,
        (peer_id >> 16) as u16,
        peer_id as u16,
        (first_hop_peer_id >> 16) as u16,
        first_hop_peer_id as u16,
    );
    SocketAddr::V6(SocketAddrV6::new(ip, 44_443, 0, 0))
}

/// An opaque TQUIC packet transported through an EasyTier relay route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayDatagram {
    pub(crate) source_peer_id: PeerId,
    pub(crate) destination_peer_id: PeerId,
    pub(crate) first_hop_peer_id: PeerId,
    /// The sender's own direct EasyTier hop. It may differ from the hop
    /// encoded by `first_hop_peer_id` on the reverse direction of an
    /// asymmetric overlay while the virtual TQUIC address pair stays stable.
    pub(crate) egress_first_hop_peer_id: PeerId,
    pub(crate) route_generation: u64,
    pub(crate) source_addr: SocketAddr,
    pub(crate) destination_addr: SocketAddr,
    pub(crate) payload: Vec<u8>,
}

impl RelayDatagram {
    pub(crate) fn from_identity(identity: RelayPathIdentity, payload: Vec<u8>) -> Self {
        Self::from_identity_with_egress(identity, identity.first_hop_peer_id, payload)
    }

    pub(crate) fn from_identity_with_egress(
        identity: RelayPathIdentity,
        egress_first_hop_peer_id: PeerId,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            source_peer_id: identity.source_peer_id,
            destination_peer_id: identity.destination_peer_id,
            first_hop_peer_id: identity.first_hop_peer_id,
            egress_first_hop_peer_id,
            route_generation: identity.route_generation,
            source_addr: identity.local_addr,
            destination_addr: identity.remote_addr,
            payload,
        }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        // The envelope deliberately contains no mutable routing state beyond
        // the chosen first hop.  A relay only reads the normal EasyTier header;
        // the TQUIC payload below remains end-to-end opaque.
        let mut raw = Vec::with_capacity(RELAY_DATAGRAM_HEADER_LEN + self.payload.len());
        raw.extend_from_slice(&RELAY_DATAGRAM_MAGIC);
        raw.push(RELAY_DATAGRAM_VERSION);
        raw.extend_from_slice(&self.source_peer_id.to_le_bytes());
        raw.extend_from_slice(&self.destination_peer_id.to_le_bytes());
        raw.extend_from_slice(&self.first_hop_peer_id.to_le_bytes());
        raw.extend_from_slice(&self.egress_first_hop_peer_id.to_le_bytes());
        raw.extend_from_slice(&self.route_generation.to_le_bytes());
        encode_virtual_addr(&mut raw, self.source_addr);
        encode_virtual_addr(&mut raw, self.destination_addr);
        raw.extend_from_slice(&self.payload);
        raw
    }

    pub(crate) fn decode(raw: &[u8]) -> io::Result<Self> {
        if raw.len() < RELAY_DATAGRAM_HEADER_LEN {
            return Err(invalid_datagram("relay MP datagram header is truncated"));
        }

        if raw[..4] != RELAY_DATAGRAM_MAGIC {
            return Err(invalid_datagram("relay MP datagram has an invalid magic"));
        }
        if raw[4] != RELAY_DATAGRAM_VERSION {
            return Err(invalid_datagram(
                "relay MP datagram has an unsupported version",
            ));
        }

        let source_peer_id = read_u32(raw, 5)?;
        let destination_peer_id = read_u32(raw, 9)?;
        let first_hop_peer_id = read_u32(raw, 13)?;
        let egress_first_hop_peer_id = read_u32(raw, 17)?;
        let route_generation = read_u64(raw, 21)?;
        let source_addr = decode_virtual_addr(&raw[29..29 + VIRTUAL_ADDR_WIRE_LEN])?;
        let destination_addr =
            decode_virtual_addr(&raw[29 + VIRTUAL_ADDR_WIRE_LEN..RELAY_DATAGRAM_HEADER_LEN])?;

        let expected = RelayPathIdentity::from_origin(
            source_peer_id,
            destination_peer_id,
            first_hop_peer_id,
            route_generation,
        );
        if source_addr != expected.local_addr || destination_addr != expected.remote_addr {
            return Err(invalid_datagram(
                "relay MP datagram virtual addresses do not match its peer identity",
            ));
        }

        Ok(Self {
            source_peer_id,
            destination_peer_id,
            first_hop_peer_id,
            egress_first_hop_peer_id,
            route_generation,
            source_addr,
            destination_addr,
            payload: raw[RELAY_DATAGRAM_HEADER_LEN..].to_vec(),
        })
    }
}

fn invalid_datagram(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_u32(raw: &[u8], offset: usize) -> io::Result<u32> {
    let bytes: [u8; 4] = raw
        .get(offset..offset + 4)
        .ok_or_else(|| invalid_datagram("relay MP datagram integer is truncated"))?
        .try_into()
        .expect("fixed four-byte slice");
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(raw: &[u8], offset: usize) -> io::Result<u64> {
    let bytes: [u8; 8] = raw
        .get(offset..offset + 8)
        .ok_or_else(|| invalid_datagram("relay MP datagram integer is truncated"))?
        .try_into()
        .expect("fixed eight-byte slice");
    Ok(u64::from_le_bytes(bytes))
}

fn encode_virtual_addr(raw: &mut Vec<u8>, addr: SocketAddr) {
    let SocketAddr::V6(addr) = addr else {
        panic!("RelayDatagram only accepts virtual IPv6 addresses");
    };

    raw.extend_from_slice(&addr.ip().octets());
    raw.extend_from_slice(&addr.port().to_be_bytes());
}

fn decode_virtual_addr(raw: &[u8]) -> io::Result<SocketAddr> {
    let octets: [u8; 16] = raw
        .get(..16)
        .ok_or_else(|| invalid_datagram("relay MP datagram address is truncated"))?
        .try_into()
        .expect("fixed sixteen-byte slice");
    let port: [u8; 2] = raw
        .get(16..18)
        .ok_or_else(|| invalid_datagram("relay MP datagram port is truncated"))?
        .try_into()
        .expect("fixed two-byte slice");

    let addr = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(octets),
        u16::from_be_bytes(port),
        0,
        0,
    ));
    let SocketAddr::V6(addr_v6) = addr else {
        unreachable!("constructed address is IPv6")
    };
    let segments = addr_v6.ip().segments();
    if segments[0] != 0xfd4d || (segments[1] != 0x5000 && segments[1] != 0x5001) {
        return Err(invalid_datagram(
            "relay MP datagram address is outside the virtual path namespace",
        ));
    }

    Ok(addr)
}

#[derive(Debug)]
struct RelayInbound {
    source_addr: SocketAddr,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct RelayReceiveState {
    inbound_rx: mpsc::Receiver<RelayInbound>,
    pending: Option<RelayInbound>,
}

/// A TQUIC carrier backed by the EasyTier relay data plane.
///
/// The path itself is transport-agnostic: its outbound receiver is owned by
/// `PeerManager`, which serializes a `RelayDatagram` into an EasyTier packet
/// and sends that packet directly to its selected local egress peer.
struct RelayNextHopDatagramPath {
    identity: RelayPathIdentity,
    egress_first_hop_peer_id: PeerId,
    outbound_tx: mpsc::Sender<RelayDatagram>,
    inbound: Mutex<RelayReceiveState>,
}

#[derive(Clone)]
struct RelayInboundPath {
    carrier: Arc<RelayNextHopDatagramPath>,
    inbound_tx: mpsc::Sender<RelayInbound>,
    egress_first_hop_peer_id: PeerId,
}

/// Admission result for a relay packet that reached its final EasyTier peer.
/// `created` tells `PeerManager` whether it must attach this carrier to a new
/// or existing TQUIC session before the queued packet can be consumed.
#[derive(Clone)]
pub(crate) struct RelayInboundAdmission {
    pub(crate) identity: RelayPathIdentity,
    pub(crate) source_peer_id: PeerId,
    pub(crate) egress_first_hop_peer_id: PeerId,
    pub(crate) carrier: Arc<dyn MpDatagramPath>,
    pub(crate) created: bool,
}

/// Shared bridge between TQUIC paths and the EasyTier packet data plane.
pub(crate) struct RelayNextHopTransport {
    outbound_tx: mpsc::Sender<RelayDatagram>,
    inbound_paths: DashMap<RelayPathIdentity, RelayInboundPath>,
    /// Datagrams `deliver_inbound` dropped into full queues so far.
    inbound_full_drops: AtomicU64,
}

impl RelayNextHopTransport {
    pub(crate) fn new() -> (Arc<Self>, mpsc::Receiver<RelayDatagram>) {
        let (outbound_tx, outbound_rx) = mpsc::channel(256);
        (
            Arc::new(Self {
                outbound_tx,
                inbound_paths: DashMap::new(),
                inbound_full_drops: AtomicU64::new(0),
            }),
            outbound_rx,
        )
    }

    pub(crate) fn open_source_path(&self, identity: RelayPathIdentity) -> Arc<dyn MpDatagramPath> {
        self.get_or_create_path(identity, identity.first_hop_peer_id)
            .0
            .carrier
    }

    pub(crate) async fn prepare_inbound(
        &self,
        datagram: &RelayDatagram,
        egress_first_hop_peer_id: PeerId,
    ) -> io::Result<RelayInboundAdmission> {
        let identity = RelayPathIdentity::from_origin(
            datagram.destination_peer_id,
            datagram.source_peer_id,
            datagram.first_hop_peer_id,
            datagram.route_generation,
        );
        if identity.local_addr != datagram.destination_addr
            || identity.remote_addr != datagram.source_addr
        {
            return Err(invalid_datagram(
                "relay MP datagram does not match its destination-side path identity",
            ));
        }
        let (path, created) = self.get_or_create_path(identity, egress_first_hop_peer_id);
        tracing::debug!(?identity, created, egress_first_hop_peer_id, "relay MP inbound admission");
        Ok(RelayInboundAdmission {
            identity,
            source_peer_id: datagram.source_peer_id,
            egress_first_hop_peer_id,
            carrier: path.carrier,
            created,
        })
    }

    /// Called from the node's single peer-receive loop, so it never waits: a
    /// full queue drops the datagram like a full UDP socket buffer would
    /// (`try_send_to` does the same outbound). Waiting here stalls every
    /// packet the node receives until the carrier's reader starts.
    pub(crate) async fn deliver_inbound(&self, datagram: RelayDatagram) -> io::Result<()> {
        let identity = RelayPathIdentity::from_origin(
            datagram.destination_peer_id,
            datagram.source_peer_id,
            datagram.first_hop_peer_id,
            datagram.route_generation,
        );
        let inbound_tx = self
            .inbound_paths
            .get(&identity)
            .map(|entry| entry.inbound_tx.clone())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "relay MP inbound path was retired before delivery",
                )
            })?;
        match inbound_tx.try_send(RelayInbound {
            source_addr: datagram.source_addr,
            payload: datagram.payload,
        }) {
            Ok(()) => {
                // Backlog that only grows means no carrier reads this queue.
                tracing::debug!(
                    ?identity,
                    backlog = inbound_tx.max_capacity() - inbound_tx.capacity(),
                    "relay MP datagram queued"
                );
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                // A full queue is normal under a burst, but one nobody reads
                // drops everything for its path: say so (rate-limited), so a
                // one-way black hole shows up in the log.
                let drops = self.inbound_full_drops.fetch_add(1, Ordering::Relaxed);
                if drops % INBOUND_FULL_DROPS_PER_WARNING == 0 {
                    tracing::warn!(
                        ?identity,
                        drops = drops + 1,
                        "relay MP inbound queue full; datagrams dropped"
                    );
                }
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "relay MP inbound carrier has stopped",
            )),
        }
    }

    pub(crate) fn retire_path(&self, identity: &RelayPathIdentity) {
        self.inbound_paths.remove(identity);
    }

    /// Drop every local bridge entry when relay-next-hop is disabled at
    /// runtime. The corresponding TQUIC candidates are retired by
    /// `MpSessionManager`; this side owns the queued inbound/outbound bridge.
    pub(crate) fn retire_all_paths(&self) -> Vec<RelayPathIdentity> {
        let identities = self
            .inbound_paths
            .iter()
            .map(|entry| *entry.key())
            .collect::<Vec<_>>();
        for identity in &identities {
            self.inbound_paths.remove(identity);
        }
        identities
    }

    /// The paths whose carrier leaves through `first_hop_peer_id`. Read-only:
    /// whether a carrier goes is the session's say (see
    /// `MpSessionManager::retire_path_by_addresses`), not this table's.
    pub(crate) fn paths_for_egress_first_hop(
        &self,
        first_hop_peer_id: PeerId,
    ) -> Vec<RelayPathIdentity> {
        self.inbound_paths
            .iter()
            .filter_map(|entry| {
                (entry.value().egress_first_hop_peer_id == first_hop_peer_id)
                    .then_some(*entry.key())
            })
            .collect()
    }

    fn get_or_create_path(
        &self,
        identity: RelayPathIdentity,
        egress_first_hop_peer_id: PeerId,
    ) -> (RelayInboundPath, bool) {
        match self.inbound_paths.entry(identity) {
            Entry::Occupied(entry) => (entry.get().clone(), false),
            Entry::Vacant(entry) => {
                let (carrier, inbound_tx) = RelayNextHopDatagramPath::new_with_outbound(
                    identity,
                    egress_first_hop_peer_id,
                    self.outbound_tx.clone(),
                );
                let path = RelayInboundPath {
                    carrier: Arc::new(carrier),
                    inbound_tx,
                    egress_first_hop_peer_id,
                };
                entry.insert(path.clone());
                (path, true)
            }
        }
    }
}

/// `egress_device` is the NIC carrying the EasyTier connection to the first
/// hop (`first_hop_egress_device`): the relay path's packets physically leave
/// through it, so its SQM, autorate and send limit apply to them too.
pub(crate) fn relay_path_spec(
    identity: RelayPathIdentity,
    carrier: Arc<dyn MpDatagramPath>,
    egress_first_hop_peer_id: PeerId,
    egress_device: Option<&str>,
) -> MpPathSpec {
    let mut spec = MpPathSpec::new(
        carrier,
        identity.remote_addr,
        ResourceGroupId::new(format!(
            "relay-next-hop:{}:{}",
            identity.first_hop_peer_id, identity.route_generation
        )),
        ResourceGroupId::new(format!("relay-peer:{}", identity.destination_peer_id)),
        CarrierKind::RelayNextHop,
    )
    .with_relay_metadata(
        identity.first_hop_peer_id,
        egress_first_hop_peer_id,
        identity.route_generation,
    );
    spec.egress_resource =
        egress_device.and_then(|device| ResourceGroupId::egress_device(device).ok());
    spec
}

/// The NIC an EasyTier connection with socket addresses `local`/`remote`
/// leaves through. A connection accepted by a listener reports the
/// listener's unspecified address, so the OS route to `remote` decides.
pub(crate) fn first_hop_egress_device(
    local: Option<SocketAddr>,
    remote: SocketAddr,
) -> Option<String> {
    let local_ip = match local {
        Some(local) if !local.ip().is_unspecified() => local.ip(),
        _ => {
            let unspecified: std::net::IpAddr = if remote.is_ipv4() {
                std::net::Ipv4Addr::UNSPECIFIED.into()
            } else {
                Ipv6Addr::UNSPECIFIED.into()
            };
            // Connecting a UDP socket sends nothing; it only asks the OS
            // which source address (hence NIC) it would use for `remote`.
            let socket = std::net::UdpSocket::bind((unspecified, 0)).ok()?;
            socket.connect(remote).ok()?;
            socket.local_addr().ok()?.ip()
        }
    };
    crate::tunnel::common::get_interface_name_by_ip(&local_ip)
}

impl RelayNextHopDatagramPath {
    fn new(
        identity: RelayPathIdentity,
    ) -> (
        Self,
        mpsc::Receiver<RelayDatagram>,
        mpsc::Sender<RelayInbound>,
    ) {
        let (outbound_tx, outbound_rx) = mpsc::channel(64);
        let (path, inbound_tx) =
            Self::new_with_outbound(identity, identity.first_hop_peer_id, outbound_tx);
        (path, outbound_rx, inbound_tx)
    }

    fn new_with_outbound(
        identity: RelayPathIdentity,
        egress_first_hop_peer_id: PeerId,
        outbound_tx: mpsc::Sender<RelayDatagram>,
    ) -> (Self, mpsc::Sender<RelayInbound>) {
        let (inbound_tx, inbound_rx) = mpsc::channel(64);
        (
            Self {
                identity,
                egress_first_hop_peer_id,
                outbound_tx,
                inbound: Mutex::new(RelayReceiveState {
                    inbound_rx,
                    pending: None,
                }),
            },
            inbound_tx,
        )
    }
}

#[async_trait::async_trait]
impl MpDatagramPath for RelayNextHopDatagramPath {
    fn local_addr(&self) -> SocketAddr {
        self.identity.local_addr
    }

    fn try_send_to(&self, payload: &[u8], remote: SocketAddr) -> io::Result<usize> {
        if remote != self.identity.remote_addr {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "relay next-hop carrier targets {}, not {remote}",
                    self.identity.remote_addr
                ),
            ));
        }

        let len = payload.len();
        match self
            .outbound_tx
            .try_send(RelayDatagram::from_identity_with_egress(
                self.identity,
                self.egress_first_hop_peer_id,
                payload.to_vec(),
            )) {
            Ok(()) => Ok(len),
            Err(mpsc::error::TrySendError::Full(_)) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "relay next-hop outbound queue is full",
            )),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "relay next-hop outbound worker has stopped",
            )),
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut inbound = self.inbound.lock().await;
        if inbound.pending.is_none() {
            inbound.pending = inbound.inbound_rx.recv().await;
        }
        let Some(datagram) = inbound.pending.as_ref() else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "relay next-hop inbound worker has stopped",
            ));
        };
        if buf.len() < datagram.payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "relay next-hop receive buffer is {} bytes, need {}",
                    buf.len(),
                    datagram.payload.len()
                ),
            ));
        }

        let datagram = inbound
            .pending
            .take()
            .expect("checked pending relay datagram");
        let len = datagram.payload.len();
        buf[..len].copy_from_slice(&datagram.payload);
        Ok((len, datagram.source_addr))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RelayDatagram, RelayNextHopDatagramPath, RelayNextHopTransport, RelayPathIdentity,
    };
    use crate::tunnel::mpquic::MpDatagramPath;

    #[test]
    fn paths_for_egress_first_hop_lists_only_that_hops_carriers() {
        let (transport, _outbound) = RelayNextHopTransport::new();
        let via = RelayPathIdentity::from_origin(101, 202, 303, 7);
        let also_via = RelayPathIdentity::from_origin(101, 505, 303, 7);
        let other_hop = RelayPathIdentity::from_origin(101, 202, 404, 7);
        for identity in [via, also_via, other_hop] {
            let _ = transport.open_source_path(identity);
        }

        let mut listed = transport.paths_for_egress_first_hop(303);
        listed.sort_by_key(|identity| identity.destination_peer_id);

        assert_eq!(listed, vec![via, also_via]);
        // Listing retires nothing.
        assert_eq!(transport.paths_for_egress_first_hop(303).len(), 2);
        assert_eq!(transport.paths_for_egress_first_hop(404), vec![other_hop]);
    }

    #[test]
    fn relay_virtual_identities_are_never_mistaken_for_wans() {
        let relay = super::relay_virtual_addr(101, 202, 303);
        assert!(super::is_relay_virtual_ip(relay.ip()));
        assert!(!super::is_relay_virtual_ip("198.51.100.39".parse().unwrap()));
        assert!(!super::is_relay_virtual_ip("fd4d:1::1".parse().unwrap()));
        assert!(!super::is_relay_virtual_ip("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn relay_path_spec_takes_the_first_hop_nic_as_its_egress() {
        let identity = RelayPathIdentity::from_origin(101, 202, 303, 7);
        let spec = |device: Option<&str>| {
            let (carrier, _, _) = RelayNextHopDatagramPath::new(identity);
            super::relay_path_spec(identity, std::sync::Arc::new(carrier), 303, device)
        };

        let on_nic = spec(Some("eth0"));
        assert_eq!(
            on_nic.egress_resource.as_ref().map(|r| r.as_str()),
            Some("egress-device:eth0")
        );
        assert_eq!(on_nic.egress_device_name(), "eth0");
        // Its optimizer resource stays per first hop.
        assert!(on_nic.local_resource.as_str().starts_with("relay-next-hop:303:"));
        assert!(spec(None).egress_resource.is_none());
        assert!(spec(Some("lo")).egress_resource.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn first_hop_egress_device_resolves_a_listener_side_connection_by_route() {
        // A listener's unspecified local address is resolved through the OS
        // route to the remote.
        let remote = "127.0.0.1:11010".parse().unwrap();
        assert_eq!(
            super::first_hop_egress_device(Some("0.0.0.0:11010".parse().unwrap()), remote)
                .as_deref(),
            Some("lo")
        );
        assert_eq!(
            super::first_hop_egress_device(Some("127.0.0.1:5000".parse().unwrap()), remote)
                .as_deref(),
            Some("lo")
        );
    }

    #[test]
    fn first_hop_changes_virtual_path_identity() {
        let via_first_relay = RelayPathIdentity::from_origin(101, 202, 303, 7);
        let via_second_relay = RelayPathIdentity::from_origin(101, 202, 404, 7);

        assert_ne!(via_first_relay.local_addr, via_second_relay.local_addr);
        assert_ne!(via_first_relay.remote_addr, via_second_relay.remote_addr);
    }

    #[test]
    fn relay_path_identity_is_bidirectional() {
        let forward = RelayPathIdentity::from_origin(101, 202, 303, 7);
        let reverse = RelayPathIdentity::from_origin(202, 101, 303, 7);

        assert_eq!(forward.local_addr, reverse.remote_addr);
        assert_eq!(forward.remote_addr, reverse.local_addr);
    }

    #[test]
    fn relay_datagram_round_trips_identity_and_payload() {
        let identity = RelayPathIdentity::from_origin(101, 202, 303, 0x0102_0304_0506_0708);
        let original = RelayDatagram::from_identity(identity, vec![1, 3, 3, 7]);

        let decoded = RelayDatagram::decode(&original.encode()).unwrap();

        assert_eq!(decoded, original);
    }

    #[test]
    fn relay_datagram_keeps_path_identity_when_reverse_egress_differs() {
        let identity = RelayPathIdentity::from_origin(202, 101, 303, 7);
        let original = RelayDatagram::from_identity_with_egress(identity, 404, vec![9, 8, 7]);

        let decoded = RelayDatagram::decode(&original.encode()).unwrap();

        assert_eq!(decoded.first_hop_peer_id, 303);
        assert_eq!(decoded.egress_first_hop_peer_id, 404);
        assert_eq!(decoded.source_addr, identity.local_addr);
        assert_eq!(decoded.destination_addr, identity.remote_addr);
        assert_eq!(decoded.payload, [9, 8, 7]);
    }

    #[tokio::test]
    async fn relay_next_hop_path_enqueues_outbound_and_delivers_inbound() {
        let identity = RelayPathIdentity::from_origin(101, 202, 303, 7);
        let (path, mut outbound_rx, inbound_tx) = RelayNextHopDatagramPath::new(identity);

        assert_eq!(
            path.try_send_to(&[1, 2, 3], identity.remote_addr).unwrap(),
            3
        );
        let outbound = outbound_rx.recv().await.unwrap();
        assert_eq!(
            outbound,
            RelayDatagram::from_identity(identity, vec![1, 2, 3])
        );

        inbound_tx
            .send(super::RelayInbound {
                source_addr: identity.remote_addr,
                payload: vec![4, 5, 6],
            })
            .await
            .unwrap();
        let mut buf = [0; 8];
        let (len, source_addr) = path.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, 3);
        assert_eq!(source_addr, identity.remote_addr);
        assert_eq!(&buf[..len], &[4, 5, 6]);
    }

    #[tokio::test]
    async fn relay_next_hop_path_preserves_datagram_after_short_receive_buffer() {
        let identity = RelayPathIdentity::from_origin(101, 202, 303, 7);
        let (path, _outbound_rx, inbound_tx) = RelayNextHopDatagramPath::new(identity);
        inbound_tx
            .send(super::RelayInbound {
                source_addr: identity.remote_addr,
                payload: vec![4, 5, 6],
            })
            .await
            .unwrap();

        let mut too_small = [0; 2];
        assert_eq!(
            path.recv_from(&mut too_small).await.unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );

        let mut adequate = [0; 3];
        let (len, source_addr) = path.recv_from(&mut adequate).await.unwrap();
        assert_eq!(len, 3);
        assert_eq!(source_addr, identity.remote_addr);
        assert_eq!(adequate, [4, 5, 6]);
    }

    #[tokio::test]
    async fn relay_transport_binds_a_source_path_to_its_reverse_inbound_path() {
        let forward_identity = RelayPathIdentity::from_origin(101, 202, 303, 7);
        let (transport, mut outbound_rx) = RelayNextHopTransport::new();
        let source = transport.open_source_path(forward_identity);

        assert_eq!(
            source
                .try_send_to(&[1, 2, 3], forward_identity.remote_addr)
                .unwrap(),
            3
        );
        let sent = outbound_rx.recv().await.unwrap();
        assert_eq!(
            sent,
            RelayDatagram::from_identity(forward_identity, vec![1, 2, 3])
        );

        let reverse = RelayDatagram::from_identity(
            RelayPathIdentity::from_origin(202, 101, 303, 7),
            vec![4, 5, 6],
        );
        let inbound = transport.prepare_inbound(&reverse, 303).await.unwrap();
        assert!(
            !inbound.created,
            "the source registration owns the reverse path"
        );
        transport.deliver_inbound(reverse).await.unwrap();

        let mut buf = [0; 3];
        let (len, source_addr) = source.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, 3);
        assert_eq!(source_addr, forward_identity.remote_addr);
        assert_eq!(buf, [4, 5, 6]);
    }

    #[tokio::test]
    async fn relay_transport_retires_all_bridge_entries_when_provider_is_disabled() {
        let first = RelayPathIdentity::from_origin(101, 202, 303, 7);
        let second = RelayPathIdentity::from_origin(101, 204, 305, 8);
        let (transport, _outbound_rx) = RelayNextHopTransport::new();
        transport.open_source_path(first);
        transport.open_source_path(second);

        let retired = transport.retire_all_paths();

        assert_eq!(retired.len(), 2);
        assert!(retired.contains(&first));
        assert!(retired.contains(&second));
        assert!(transport.retire_all_paths().is_empty());
        let reverse_first = RelayDatagram::from_identity(
            RelayPathIdentity::from_origin(202, 101, 303, 7),
            vec![1, 2, 3],
        );
        assert_eq!(
            transport
                .deliver_inbound(reverse_first)
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotConnected,
            "a disabled relay provider must not keep accepting bridge traffic"
        );
    }

    #[tokio::test]
    async fn relay_transport_buffers_initial_before_server_path_is_polled() {
        let client_identity = RelayPathIdentity::from_origin(101, 202, 303, 7);
        let (transport, _outbound_rx) = RelayNextHopTransport::new();
        let initial = RelayDatagram::from_identity(client_identity, vec![1, 2, 3]);

        let admission = transport.prepare_inbound(&initial, 303).await.unwrap();
        assert!(
            admission.created,
            "the destination must create its server-side relay path for the first Initial"
        );

        // The server's TQUIC task may not be polling `recv_from` yet. The
        // first Initial must still be queued, otherwise waiting for session
        // readiness before delivery deadlocks the handshake.
        transport.deliver_inbound(initial).await.unwrap();

        let mut buf = [0; 3];
        let (len, source_addr) = admission.carrier.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, 3);
        assert_eq!(source_addr, client_identity.local_addr);
        assert_eq!(buf, [1, 2, 3]);
    }

    /// Delivery runs in the node's only peer-receive loop: a carrier nobody
    /// reads yet must cost dropped datagrams, never a stalled loop.
    #[tokio::test]
    async fn delivery_to_an_unread_carrier_drops_instead_of_waiting() {
        let client_identity = RelayPathIdentity::from_origin(101, 202, 303, 7);
        let (transport, _outbound_rx) = RelayNextHopTransport::new();
        let first = RelayDatagram::from_identity(client_identity, vec![0]);
        let admission = transport.prepare_inbound(&first, 303).await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            for i in 0..1_000u32 {
                let datagram = RelayDatagram::from_identity(client_identity, i.to_le_bytes().to_vec());
                transport.deliver_inbound(datagram).await.unwrap();
            }
        })
        .await
        .expect("a full carrier queue must not block delivery");

        // What did fit is still delivered, oldest first.
        let mut buf = [0; 4];
        let (len, _) = admission.carrier.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], 0u32.to_le_bytes());
    }
}

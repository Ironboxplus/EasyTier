//! Datagram data plane for mpquic sessions (MP_SQM_PLAN.md S2.10-S2.11).
//!
//! The mpquic tunnel historically carried every EasyTier packet on one
//! reliable QUIC stream, so one lost packet stalled every flow behind it.
//! With the data plane negotiated, each EasyTier packet is instead sent as a
//! QUIC DATAGRAM (RFC 9221) by default -- never retransmitted, exactly like
//! the `udp://` tunnel -- and a class of traffic can opt into
//! `reliable_stream`: its own QUIC stream per flow (ordered per flow, no
//! blocking across flows).
//!
//! This module is engine-free: policy parsing and validation, the traffic
//! classifier, the datagram header codec, fragmentation, negotiation and
//! counters. `tunnel::mpquic`'s driver wires it to TQUIC.
//!
//! Datagram header (RFC 9221 Section 5.1 recommends an application context
//! identifier): a QUIC varint `context`, then per context:
//! - 0 whole EasyTier frame: `frame`
//! - 1 fragment: `packet_id u32, index u8, count u8, chunk`
//!
//! Other contexts are reserved and dropped on receipt.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::proto::api::instance::{MpClassStatus, MpDataPlaneStatus};
use crate::proto::common::{MpClassPolicy, MpClassRule, MpDataPlaneConfig};
use crate::tunnel::packet_def::{
    PEER_MANAGER_HEADER_SIZE, PacketType, TCP_TUNNEL_HEADER_SIZE, ZCPacket, ZCPacketType,
};

// ---------------------------------------------------------------------------
// Capabilities (RoutePeerInfo.mp_dataplane_caps)
// ---------------------------------------------------------------------------

pub const CAP_DATAGRAM: u32 = 1;
pub const CAP_FRAGMENT: u32 = 2;
/// OWD_AUTORATE_PLAN.md 1.1: the peer answers `OwdProbe` datagrams with
/// `OwdReport`s (one-way delay in the data direction).
pub const CAP_OWD_PROBE: u32 = 4;
pub const LOCAL_DATAPLANE_CAPS: u32 = CAP_DATAGRAM | CAP_FRAGMENT | CAP_OWD_PROBE;

/// `max_datagram_frame_size` advertised when the data plane is enabled.
pub const MAX_DATAGRAM_FRAME_SIZE: u64 = 65535;

pub const DEFAULT_RELIABLE_STREAM_MAX: u32 = 64;
pub const DEFAULT_RELIABLE_STREAM_IDLE: Duration = Duration::from_secs(30);
pub const MAX_FRAGMENTS: usize = 4;
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(1);
/// User rules are tagged `RULE_TAG_BASE + index` in the in-memory tag byte.
const RULE_TAG_BASE: u8 = 16;
pub const MAX_CLASS_RULES: usize = 64;
/// ET encryption adds a nonce and an AEAD tag per packet.
const ET_AEAD_OVERHEAD: usize = 28;

// ---------------------------------------------------------------------------
// Classes and modes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TrafficClass {
    EtControl,
    Tcp,
    Udp,
    Icmp,
    Proxy,
    Other,
    /// Index into `DataPlanePolicy::rules`.
    Rule(u8),
}

pub const BUILTIN_CLASSES: [TrafficClass; 6] = [
    TrafficClass::EtControl,
    TrafficClass::Tcp,
    TrafficClass::Udp,
    TrafficClass::Icmp,
    TrafficClass::Proxy,
    TrafficClass::Other,
];

impl TrafficClass {
    pub fn tag(self) -> u8 {
        match self {
            TrafficClass::EtControl => 1,
            TrafficClass::Tcp => 2,
            TrafficClass::Udp => 3,
            TrafficClass::Icmp => 4,
            TrafficClass::Proxy => 5,
            TrafficClass::Other => 6,
            TrafficClass::Rule(index) => RULE_TAG_BASE + index,
        }
    }

    pub fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            1 => TrafficClass::EtControl,
            2 => TrafficClass::Tcp,
            3 => TrafficClass::Udp,
            4 => TrafficClass::Icmp,
            5 => TrafficClass::Proxy,
            6 => TrafficClass::Other,
            tag if tag >= RULE_TAG_BASE && ((tag - RULE_TAG_BASE) as usize) < MAX_CLASS_RULES => {
                TrafficClass::Rule(tag - RULE_TAG_BASE)
            }
            _ => return None,
        })
    }

    pub fn builtin_name(self) -> Option<&'static str> {
        Some(match self {
            TrafficClass::EtControl => "et_control",
            TrafficClass::Tcp => "tcp",
            TrafficClass::Udp => "udp",
            TrafficClass::Icmp => "icmp",
            TrafficClass::Proxy => "proxy",
            TrafficClass::Other => "other",
            TrafficClass::Rule(_) => return None,
        })
    }

    fn from_builtin_name(name: &str) -> Option<Self> {
        BUILTIN_CLASSES
            .into_iter()
            .find(|class| class.builtin_name() == Some(name))
    }

    /// Class of a frame nobody tagged: from the EasyTier packet type alone.
    /// Data packets are encrypted by now, so their inner protocol is unknown.
    pub fn from_packet_type(packet_type: u8) -> Self {
        const KCP_SRC: u8 = PacketType::KcpSrc as u8;
        const KCP_DST: u8 = PacketType::KcpDst as u8;
        const QUIC_SRC: u8 = PacketType::QuicSrc as u8;
        const QUIC_DST: u8 = PacketType::QuicDst as u8;
        const DATA: u8 = PacketType::Data as u8;
        const DATA_KCP: u8 = PacketType::DataWithKcpSrcModified as u8;
        const DATA_QUIC: u8 = PacketType::DataWithQuicSrcModified as u8;
        match packet_type {
            KCP_SRC | KCP_DST | QUIC_SRC | QUIC_DST => TrafficClass::Proxy,
            DATA | DATA_KCP | DATA_QUIC => TrafficClass::Other,
            _ => TrafficClass::EtControl,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ClassMode {
    Datagram,
    ReliableStream,
}

impl ClassMode {
    pub fn name(&self) -> &'static str {
        match self {
            ClassMode::Datagram => "datagram",
            ClassMode::ReliableStream => "reliable_stream",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OversizePolicy {
    /// Drop it and tell the local host with ICMP Packet Too Big
    /// (RFC 9484 Section 10.1); only for tagged Data packets (default).
    IcmpPtb,
    /// Split into at most `MAX_FRAGMENTS` datagrams.
    Fragment,
}

impl OversizePolicy {
    fn parse(value: &str) -> anyhow::Result<Self> {
        Ok(match value {
            // "stream" (send the packet on a reliable stream) is gone: it
            // pinned the flow to the stream. An old config naming it means
            // the default.
            "" | "stream" | "icmp_ptb" => OversizePolicy::IcmpPtb,
            "fragment" => OversizePolicy::Fragment,
            other => bail!("unknown oversize policy {other:?} (icmp_ptb|fragment)"),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            OversizePolicy::IcmpPtb => "icmp_ptb",
            OversizePolicy::Fragment => "fragment",
        }
    }

    pub fn restricted_to(self, caps: u32) -> Self {
        match self {
            OversizePolicy::Fragment if caps & CAP_FRAGMENT == 0 => OversizePolicy::IcmpPtb,
            policy => policy,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleProtocol {
    Any,
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClassRule {
    pub name: String,
    protocol: RuleProtocol,
    ports: Option<(u16, u16)>,
    dst: Option<cidr::IpCidr>,
}

impl ClassRule {
    fn parse(rule: &MpClassRule) -> anyhow::Result<Self> {
        let name = rule.name.trim().to_string();
        if name.is_empty() {
            bail!("class rule name must not be empty");
        }
        if TrafficClass::from_builtin_name(&name).is_some() {
            bail!("class rule name {name:?} collides with a built-in class");
        }
        let protocol = match rule.protocol.as_str() {
            "" | "any" => RuleProtocol::Any,
            "tcp" => RuleProtocol::Tcp,
            "udp" => RuleProtocol::Udp,
            "icmp" => RuleProtocol::Icmp,
            other => bail!("class rule {name:?}: unknown protocol {other:?}"),
        };
        let ports = parse_port_range(&rule.port_range)
            .with_context(|| format!("class rule {name:?}"))?;
        if ports.is_some() && !matches!(protocol, RuleProtocol::Tcp | RuleProtocol::Udp) {
            bail!("class rule {name:?}: a port range needs protocol tcp or udp");
        }
        let dst = match rule.dst_cidr.trim() {
            "" => None,
            cidr => Some(
                cidr.parse::<cidr::IpCidr>()
                    .map_err(|error| anyhow::anyhow!("class rule {name:?}: dst_cidr: {error}"))?,
            ),
        };
        Ok(Self {
            name,
            protocol,
            ports,
            dst,
        })
    }

    fn matches(&self, packet: &InnerIp) -> bool {
        let protocol_ok = match self.protocol {
            RuleProtocol::Any => true,
            RuleProtocol::Tcp => packet.protocol == IP_PROTO_TCP,
            RuleProtocol::Udp => packet.protocol == IP_PROTO_UDP,
            RuleProtocol::Icmp => {
                packet.protocol == IP_PROTO_ICMP || packet.protocol == IP_PROTO_ICMPV6
            }
        };
        let ports_ok = match (self.ports, packet.ports) {
            (None, _) => true,
            (Some((lo, hi)), Some((src, dst))) => (lo..=hi).contains(&dst) || (lo..=hi).contains(&src),
            (Some(_), None) => false,
        };
        let dst_ok = self
            .dst
            .as_ref()
            .is_none_or(|cidr| cidr.contains(&packet.dst));
        protocol_ok && ports_ok && dst_ok
    }
}

fn parse_port_range(value: &str) -> anyhow::Result<Option<(u16, u16)>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let (lo, hi) = match value.split_once('-') {
        Some((lo, hi)) => (lo.trim(), hi.trim()),
        None => (value, value),
    };
    let lo: u16 = lo.parse().with_context(|| format!("bad port {lo:?}"))?;
    let hi: u16 = hi.parse().with_context(|| format!("bad port {hi:?}"))?;
    if lo == 0 || lo > hi {
        bail!("bad port range {value:?}");
    }
    Ok(Some((lo, hi)))
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct DataPlanePolicy {
    pub enabled: bool,
    pub oversize: OversizePolicy,
    modes: HashMap<TrafficClass, ClassMode>,
    pub rules: Vec<ClassRule>,
    pub reliable_stream_max: u32,
    pub reliable_stream_idle: Duration,
}

impl Default for DataPlanePolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            oversize: OversizePolicy::IcmpPtb,
            modes: HashMap::new(),
            rules: Vec::new(),
            reliable_stream_max: DEFAULT_RELIABLE_STREAM_MAX,
            reliable_stream_idle: DEFAULT_RELIABLE_STREAM_IDLE,
        }
    }
}

impl DataPlanePolicy {
    /// Parse and validate `MpConfig.data_plane`.
    pub fn from_config(config: &MpDataPlaneConfig) -> anyhow::Result<Self> {
        if config.class_rules.len() > MAX_CLASS_RULES {
            bail!("at most {MAX_CLASS_RULES} class rules are supported");
        }
        let mut rules = Vec::with_capacity(config.class_rules.len());
        for rule in config.class_rules.iter().filter(|rule| rule.enabled) {
            let rule = ClassRule::parse(rule)?;
            if rules.iter().any(|existing: &ClassRule| existing.name == rule.name) {
                bail!("duplicate class rule name {:?}", rule.name);
            }
            rules.push(rule);
        }

        let mut modes = HashMap::new();
        for policy in &config.class_policies {
            let class = TrafficClass::from_builtin_name(&policy.class)
                .or_else(|| {
                    rules
                        .iter()
                        .position(|rule| rule.name == policy.class)
                        .map(|index| TrafficClass::Rule(index as u8))
                });
            let Some(class) = class else {
                // A policy for a disabled rule is kept in the config but has
                // nothing to apply to; an unknown name is a typo.
                if config
                    .class_rules
                    .iter()
                    .any(|rule| rule.name.trim() == policy.class)
                {
                    continue;
                }
                bail!("class policy for unknown class {:?}", policy.class);
            };
            if modes.contains_key(&class) {
                bail!("duplicate class policy for {:?}", policy.class);
            }
            modes.insert(
                class,
                parse_mode(policy).with_context(|| format!("class {:?}", policy.class))?,
            );
        }

        Ok(Self {
            enabled: config.enabled,
            oversize: OversizePolicy::parse(&config.oversize)?,
            modes,
            rules,
            reliable_stream_max: match config.reliable_stream_max {
                0 => DEFAULT_RELIABLE_STREAM_MAX,
                n => n.min(1024),
            },
            reliable_stream_idle: match config.reliable_stream_idle_ms {
                0 => DEFAULT_RELIABLE_STREAM_IDLE,
                ms => Duration::from_millis(ms as u64),
            },
        })
    }

    /// The policy of `MpConfig.data_plane`, or the disabled default.
    pub fn from_mp_config(config: &crate::proto::common::MpConfig) -> Self {
        config
            .data_plane
            .as_ref()
            .and_then(|plane| Self::from_config(plane).ok())
            .unwrap_or_default()
    }

    pub fn mode_for(&self, class: TrafficClass) -> ClassMode {
        self.modes
            .get(&class)
            .copied()
            .unwrap_or_else(|| default_mode(class))
    }

    pub fn class_name(&self, class: TrafficClass) -> String {
        match class {
            TrafficClass::Rule(index) => self
                .rules
                .get(index as usize)
                .map(|rule| rule.name.clone())
                .unwrap_or_else(|| format!("rule#{index}")),
            class => class.builtin_name().unwrap_or("other").to_string(),
        }
    }

    /// Every class this policy can produce, built-ins first.
    pub fn classes(&self) -> Vec<TrafficClass> {
        BUILTIN_CLASSES
            .into_iter()
            .chain((0..self.rules.len()).map(|index| TrafficClass::Rule(index as u8)))
            .collect()
    }

    /// Classify a plaintext inner IP packet (a Data packet from the local
    /// NIC). Returns the class and the packet's flow hash (`InnerIp::flow_hash`;
    /// 0 when the packet is not IP): `reliable_stream` maps it to a stream, and
    /// the egress queue below QUIC isolates the flow by it.
    pub fn classify_ip(&self, packet: &[u8]) -> (TrafficClass, u32) {
        let Some(inner) = parse_inner_ip(packet) else {
            return (TrafficClass::Other, 0);
        };
        let bucket = inner.flow_hash();
        if let Some(index) = self.rules.iter().position(|rule| rule.matches(&inner)) {
            return (TrafficClass::Rule(index as u8), bucket);
        }
        let class = match inner.protocol {
            IP_PROTO_TCP => TrafficClass::Tcp,
            IP_PROTO_UDP => TrafficClass::Udp,
            IP_PROTO_ICMP | IP_PROTO_ICMPV6 => TrafficClass::Icmp,
            _ => TrafficClass::Other,
        };
        (class, bucket)
    }
}

/// The mode of a class without a policy. Inner TCP gets its own reliable
/// streams: as a datagram it saw every loss of the outer path, including
/// those QUIC's congestion control causes while probing, and backed off on
/// each (S3: 323 vs 540 Mbit/s without netem loss, 0.9 vs 23 with). QUIC
/// recovers them on a stream, and a stream per flow keeps flows from
/// blocking each other. The quic/kcp proxy carries TCP connections too, and
/// measured the same way (S3 `diag_dp`: 425 vs 479 Mbit/s without loss, 22.6
/// vs 30.4 with 10%). Making it a datagram by default (item 18) was measured
/// again on the current tree and reverted: `s32_split_proxy` at 10% loss got
/// 0.74-0.84 of the stream's goodput, `diag_i15` without loss 0.62-0.87
/// (_phase3/s3_regression.md). Everything else keeps the datagram: UDP and
/// ICMP bring their own recovery or need none, and gain latency from it.
fn default_mode(class: TrafficClass) -> ClassMode {
    match class {
        TrafficClass::Tcp | TrafficClass::Proxy => ClassMode::ReliableStream,
        _ => ClassMode::Datagram,
    }
}

fn parse_mode(policy: &MpClassPolicy) -> anyhow::Result<ClassMode> {
    Ok(match policy.mode.as_str() {
        "" | "datagram" => ClassMode::Datagram,
        "reliable_stream" => ClassMode::ReliableStream,
        other => bail!("unknown mode {other:?} (datagram|reliable_stream)"),
    })
}

// ---------------------------------------------------------------------------
// Inner IP parsing
// ---------------------------------------------------------------------------

pub(crate) const IP_PROTO_ICMP: u8 = 1;
pub(crate) const IP_PROTO_TCP: u8 = 6;
pub(crate) const IP_PROTO_UDP: u8 = 17;
pub(crate) const IP_PROTO_ICMPV6: u8 = 58;

/// Header fields of a plaintext inner IP packet (a TUN packet), parsed with
/// pnet. Shared by the data-plane classifier and
/// `PeerManager::packet_flow_hash`, so the send path parses each packet one
/// way only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InnerIp {
    pub(crate) src: IpAddr,
    pub(crate) dst: IpAddr,
    pub(crate) protocol: u8,
    /// TCP/UDP ports; `None` for other protocols and for IPv4 fragments
    /// after the first (only the first carries the L4 header).
    pub(crate) ports: Option<(u16, u16)>,
    /// IPv4 identification when the packet is a fragment.
    pub(crate) fragment_id: Option<u16>,
}

/// `InnerIp::flow_hash` of an inner IP packet; 0 when it is not one.
pub(crate) fn inner_flow_hash(packet: &[u8]) -> u32 {
    parse_inner_ip(packet).map_or(0, |inner| inner.flow_hash())
}

fn l4_ports(protocol: u8, l4: &[u8]) -> Option<(u16, u16)> {
    use pnet::packet::{tcp::TcpPacket, udp::UdpPacket};
    match protocol {
        IP_PROTO_TCP => TcpPacket::new(l4).map(|p| (p.get_source(), p.get_destination())),
        IP_PROTO_UDP => UdpPacket::new(l4).map(|p| (p.get_source(), p.get_destination())),
        _ => None,
    }
}

pub(crate) fn parse_inner_ip(packet: &[u8]) -> Option<InnerIp> {
    use pnet::packet::{Packet as _, ipv4::Ipv4Packet, ipv6::Ipv6Packet};
    match packet.first()? >> 4 {
        4 => {
            let ip = Ipv4Packet::new(packet)?;
            let protocol = ip.get_next_level_protocol().0;
            let first = ip.get_fragment_offset() == 0;
            let fragmented = ip.get_flags() & 0b001 != 0 || !first;
            Some(InnerIp {
                src: ip.get_source().into(),
                dst: ip.get_destination().into(),
                protocol,
                ports: first.then(|| l4_ports(protocol, ip.payload())).flatten(),
                fragment_id: fragmented.then(|| ip.get_identification()),
            })
        }
        6 => {
            let ip = Ipv6Packet::new(packet)?;
            let protocol = ip.get_next_header().0;
            Some(InnerIp {
                src: ip.get_source().into(),
                dst: ip.get_destination().into(),
                protocol,
                ports: l4_ports(protocol, ip.payload()),
                fragment_id: None,
            })
        }
        _ => None,
    }
}

impl InnerIp {
    /// A direction-independent hash of the flow, so both directions of a TCP
    /// flow map to one reliable stream (its low byte is the stream bucket).
    /// Never 0, which stands for "no flow" on the pipe.
    pub(crate) fn flow_hash(&self) -> u32 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        let (a, b) = if self.src <= self.dst {
            ((self.src, self.ports.map(|p| p.0)), (self.dst, self.ports.map(|p| p.1)))
        } else {
            ((self.dst, self.ports.map(|p| p.1)), (self.src, self.ports.map(|p| p.0)))
        };
        a.hash(&mut hasher);
        b.hash(&mut hasher);
        self.protocol.hash(&mut hasher);
        match hasher.finish() as u32 {
            0 => 1,
            hash => hash,
        }
    }
}

// ---------------------------------------------------------------------------
// Pipe framing between the ET tunnel and the mpquic driver (local only)
// ---------------------------------------------------------------------------

/// Body lengths fit in 16 bits; the upper byte of the 32-bit length of the
/// local pipe framing carries the class tag. The driver clears it before any
/// byte reaches the wire.
pub fn encode_pipe_len(body_len: usize, class: u8) -> u32 {
    debug_assert!(body_len <= u16::MAX as usize);
    (body_len as u32 & 0xffff) | (class as u32) << 24
}

pub fn decode_pipe_len(len: u32) -> (usize, u8) {
    ((len & 0xffff) as usize, (len >> 24) as u8)
}

/// Bytes the local pipe adds behind each frame: the inner flow hash
/// (little endian, 0 = none). The driver strips them before the frame is
/// sent, so streams and datagrams carry the same bytes as without the data
/// plane.
pub const PIPE_TRAILER_SIZE: usize = 4;

/// `ZCPacketToBytes` for the ET end of a data-plane mpquic pipe: TCP framing
/// plus the in-memory class tag in the length's upper byte, and the inner
/// flow hash as a trailer ([`PIPE_TRAILER_SIZE`]).
pub struct MpPipeZCPacketToBytes;

impl crate::tunnel::common::ZCPacketToBytes for MpPipeZCPacketToBytes {
    fn zcpacket_into_bytes(
        &self,
        item: ZCPacket,
    ) -> Result<Bytes, crate::tunnel::TunnelError> {
        let (class, flow_hash) = item.mp_dataplane_tag().unwrap_or((0, 0));
        let mut item = item.convert_type(ZCPacketType::TCP);
        let body_len = PEER_MANAGER_HEADER_SIZE + item.payload_len();
        if body_len > u16::MAX as usize {
            return Err(crate::tunnel::TunnelError::InvalidPacket(
                "packet too long for the mpquic pipe".to_string(),
            ));
        }
        let Some(header) = item.mut_tcp_tunnel_header() else {
            return Err(crate::tunnel::TunnelError::InvalidPacket(
                "packet too short".to_string(),
            ));
        };
        header.len.set(encode_pipe_len(body_len, class));
        let mut framed = item.inner();
        framed.extend_from_slice(&flow_hash.to_le_bytes());
        Ok(framed.freeze())
    }
}

/// One EasyTier frame taken from a byte stream, with a clean length header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeFrame {
    pub frame: Bytes,
    pub tag: u8,
    /// `InnerIp::flow_hash` of the packet; 0 = none (not from the pipe, or
    /// not an IP packet).
    pub flow_hash: u32,
}

impl PipeFrame {
    /// The reliable stream bucket of the flow.
    pub fn bucket(&self) -> u8 {
        self.flow_hash as u8
    }

    /// The flow for the egress queue, when the packet has one.
    pub fn flow(&self) -> Option<u32> {
        (self.flow_hash != 0).then_some(self.flow_hash)
    }

    pub fn packet_type(&self) -> u8 {
        self.frame
            .get(TCP_TUNNEL_HEADER_SIZE + 8)
            .copied()
            .unwrap_or(0)
    }

    /// Class from the tag, else from the EasyTier packet type.
    pub fn class(&self) -> TrafficClass {
        TrafficClass::from_tag(self.tag)
            .unwrap_or_else(|| TrafficClass::from_packet_type(self.packet_type()))
    }
}

/// Whether `frame` is one whole EasyTier frame with a clean length header,
/// i.e. safe to write to the ET pipe. A datagram from the network is checked
/// with this first: a bad length would desync every later frame in the pipe.
pub fn is_whole_frame(frame: &[u8]) -> bool {
    frame.len() >= TCP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE
        && frame.len() - TCP_TUNNEL_HEADER_SIZE <= u16::MAX as usize
        && frame[..4] == ((frame.len() - TCP_TUNNEL_HEADER_SIZE) as u32).to_le_bytes()
}

/// Splits a byte stream of framed EasyTier packets (ET pipe or a QUIC
/// stream) into whole frames.
#[derive(Default)]
pub struct FrameSplitter {
    buf: BytesMut,
    /// Every frame is followed by [`PIPE_TRAILER_SIZE`] bytes of flow hash:
    /// the splitter of the local ET pipe, not of a stream from the network.
    trailer: bool,
}

impl FrameSplitter {
    /// The splitter of the local ET pipe (see [`MpPipeZCPacketToBytes`]).
    pub fn pipe() -> Self {
        Self {
            buf: BytesMut::new(),
            trailer: true,
        }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    pub fn next_frame(&mut self) -> Option<Result<PipeFrame, String>> {
        if self.buf.len() < TCP_TUNNEL_HEADER_SIZE {
            return None;
        }
        let raw = u32::from_le_bytes(self.buf[..4].try_into().ok()?);
        let (body_len, tag) = decode_pipe_len(raw);
        if body_len < PEER_MANAGER_HEADER_SIZE {
            return Some(Err(format!("frame body too short: {body_len}")));
        }
        let trailer = if self.trailer { PIPE_TRAILER_SIZE } else { 0 };
        let frame_len = TCP_TUNNEL_HEADER_SIZE + body_len;
        if self.buf.len() < frame_len + trailer {
            return None;
        }
        let mut frame = self.buf.split_to(frame_len);
        frame[..4].copy_from_slice(&(body_len as u32).to_le_bytes());
        let flow_hash = if self.trailer {
            let bytes = self.buf.split_to(PIPE_TRAILER_SIZE);
            u32::from_le_bytes(bytes[..].try_into().ok()?)
        } else {
            0
        };
        Some(Ok(PipeFrame {
            frame: frame.freeze(),
            tag,
            flow_hash,
        }))
    }
}

// ---------------------------------------------------------------------------
// Datagram header codec
// ---------------------------------------------------------------------------

pub const CTX_WHOLE: u64 = 0;
pub const CTX_FRAGMENT: u64 = 1;
/// OWD_AUTORATE_PLAN.md 1.1: a one-way delay probe and the receiver's report
/// of when probes arrived. A peer without `CAP_OWD_PROBE` drops both as
/// reserved contexts (`DataPlaneDriver::inbound`).
pub const CTX_OWD_PROBE: u64 = 2;
pub const CTX_OWD_REPORT: u64 = 3;
/// Most entries one `OwdReport` carries.
pub const OWD_REPORT_MAX_ENTRIES: usize = 64;

fn put_varint(buf: &mut BytesMut, v: u64) {
    match v {
        0..=63 => buf.put_u8(v as u8),
        64..=16383 => buf.put_u16(0x4000 | v as u16),
        16384..=1_073_741_823 => buf.put_u32(0x8000_0000 | v as u32),
        _ => buf.put_u64(0xc000_0000_0000_0000 | v),
    }
}

fn get_varint(buf: &mut &[u8]) -> Option<u64> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut v = (first & 0x3f) as u64;
    for b in &buf[1..len] {
        v = (v << 8) | *b as u64;
    }
    buf.advance(len);
    Some(v)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Datagram {
    Whole(Bytes),
    Fragment {
        packet_id: u32,
        index: u8,
        count: u8,
        chunk: Bytes,
    },
    /// Sent by the data sender; the receiver notes when it arrived.
    OwdProbe {
        seq: u32,
    },
    /// The receiver's clock (`owd::owd_clock_us`) when each probe `seq`
    /// arrived. At most `OWD_REPORT_MAX_ENTRIES` entries.
    OwdReport {
        entries: Vec<(u32, u64)>,
    },
}

impl Datagram {
    /// Header bytes ahead of the frame for `Whole` datagrams.
    pub const WHOLE_OVERHEAD: usize = 1;
    pub const FRAGMENT_OVERHEAD: usize = 1 + 4 + 1 + 1;

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        match self {
            Datagram::Whole(frame) => {
                put_varint(&mut buf, CTX_WHOLE);
                buf.extend_from_slice(frame);
            }
            Datagram::Fragment {
                packet_id,
                index,
                count,
                chunk,
            } => {
                put_varint(&mut buf, CTX_FRAGMENT);
                buf.put_u32(*packet_id);
                buf.put_u8(*index);
                buf.put_u8(*count);
                buf.extend_from_slice(chunk);
            }
            Datagram::OwdProbe { seq } => {
                put_varint(&mut buf, CTX_OWD_PROBE);
                buf.put_u32(*seq);
            }
            Datagram::OwdReport { entries } => {
                put_varint(&mut buf, CTX_OWD_REPORT);
                let count = entries.len().min(OWD_REPORT_MAX_ENTRIES);
                buf.put_u8(count as u8);
                for (seq, recv_us) in &entries[..count] {
                    buf.put_u32(*seq);
                    buf.put_u64(*recv_us);
                }
            }
        }
        buf.freeze()
    }

    /// Bytes an `OwdReport` of `entries` entries takes.
    pub const fn owd_report_len(entries: usize) -> usize {
        1 + 1 + entries * (4 + 8)
    }

    /// Decode a received datagram; `None` for a reserved context or a
    /// malformed header.
    pub fn decode(data: &Bytes) -> Option<Self> {
        let mut b = &data[..];
        let context = get_varint(&mut b)?;
        let rest = |b: &[u8]| data.slice(data.len() - b.len()..);
        Some(match context {
            CTX_WHOLE => Datagram::Whole(rest(b)),
            CTX_FRAGMENT => {
                if b.len() < 6 {
                    return None;
                }
                let packet_id = b.get_u32();
                let index = b.get_u8();
                let count = b.get_u8();
                if count == 0 || index >= count {
                    return None;
                }
                Datagram::Fragment {
                    packet_id,
                    index,
                    count,
                    chunk: rest(b),
                }
            }
            CTX_OWD_PROBE => {
                if b.len() != 4 {
                    return None;
                }
                Datagram::OwdProbe { seq: b.get_u32() }
            }
            CTX_OWD_REPORT => {
                let count = *b.first()? as usize;
                if count == 0
                    || count > OWD_REPORT_MAX_ENTRIES
                    || b.len() != Self::owd_report_len(count) - 1
                {
                    return None;
                }
                b.advance(1);
                let entries = (0..count)
                    .map(|_| (b.get_u32(), b.get_u64()))
                    .collect();
                Datagram::OwdReport { entries }
            }
            _ => return None,
        })
    }
}

// ---------------------------------------------------------------------------
// Fragmentation (oversize policy `fragment`)
// ---------------------------------------------------------------------------

/// Split `frame` into at most `MAX_FRAGMENTS` datagrams no longer than
/// `max_datagram`; `None` if it needs more.
pub fn fragment(frame: &Bytes, packet_id: u32, max_datagram: usize) -> Option<Vec<Datagram>> {
    let chunk = max_datagram.checked_sub(Datagram::FRAGMENT_OVERHEAD)?;
    if chunk == 0 {
        return None;
    }
    let count = frame.len().div_ceil(chunk);
    if count == 0 || count > MAX_FRAGMENTS {
        return None;
    }
    Some(
        (0..count)
            .map(|index| Datagram::Fragment {
                packet_id,
                index: index as u8,
                count: count as u8,
                chunk: frame.slice(index * chunk..((index + 1) * chunk).min(frame.len())),
            })
            .collect(),
    )
}

struct PartialPacket {
    started: Instant,
    chunks: Vec<Option<Bytes>>,
}

#[derive(Default)]
pub struct Reassembler {
    partial: HashMap<u32, PartialPacket>,
}

impl Reassembler {
    /// Add one fragment; returns the whole frame once complete.
    pub fn add(
        &mut self,
        packet_id: u32,
        index: u8,
        count: u8,
        chunk: Bytes,
        now: Instant,
    ) -> Option<Bytes> {
        if count as usize > MAX_FRAGMENTS {
            return None;
        }
        let entry = self.partial.entry(packet_id).or_insert_with(|| PartialPacket {
            started: now,
            chunks: vec![None; count as usize],
        });
        if entry.chunks.len() != count as usize {
            return None;
        }
        entry.chunks[index as usize] = Some(chunk);
        if entry.chunks.iter().any(Option::is_none) {
            return None;
        }
        let entry = self.partial.remove(&packet_id)?;
        let mut frame = BytesMut::new();
        for chunk in entry.chunks.into_iter().flatten() {
            frame.extend_from_slice(&chunk);
        }
        Some(frame.freeze())
    }

    /// Drop incomplete packets older than `REASSEMBLY_TIMEOUT`; returns how
    /// many were dropped.
    pub fn expire(&mut self, now: Instant) -> usize {
        let before = self.partial.len();
        self.partial
            .retain(|_, p| now.saturating_duration_since(p.started) < REASSEMBLY_TIMEOUT);
        before - self.partial.len()
    }
}

// ---------------------------------------------------------------------------
// Reliable streams per flow
// ---------------------------------------------------------------------------

/// Maps `(class, flow bucket)` to QUIC stream ids, bounded by `max` with LRU
/// reuse and idle reaping.
pub struct ReliableStreams {
    max: usize,
    idle: Duration,
    by_flow: HashMap<(u8, u8), (u64, Instant)>,
    pub recycled: u64,
}

impl ReliableStreams {
    pub fn new(max: u32, idle: Duration) -> Self {
        Self {
            max: max.max(1) as usize,
            idle,
            by_flow: HashMap::new(),
            recycled: 0,
        }
    }

    pub fn set_limits(&mut self, max: u32, idle: Duration) {
        self.max = max.max(1) as usize;
        self.idle = idle;
    }

    /// Stream for a flow: the existing one, a new one from `open`, or a share
    /// of the least recently used one when `max` streams are open. A flow
    /// never moves to another stream while it is mapped: its frames would
    /// overtake the ones still in flight on the old stream.
    pub fn stream_for(
        &mut self,
        flow: (u8, u8),
        now: Instant,
        open: impl FnOnce() -> Option<u64>,
    ) -> Option<u64> {
        if let Some((stream, used)) = self.by_flow.get_mut(&flow) {
            *used = now;
            return Some(*stream);
        }
        if self.open_count() < self.max
            && let Some(stream) = open()
        {
            self.by_flow.insert(flow, (stream, now));
            return Some(stream);
        }
        // Share the least recently used stream; its flows stay on it.
        let &(stream, _) = self.by_flow.values().min_by_key(|(_, used)| *used)?;
        self.by_flow.insert(flow, (stream, now));
        self.recycled += 1;
        Some(stream)
    }

    /// Streams unused for `idle`; the caller finishes them. A flow stays on
    /// its stream while `in_flight` says the stream still holds data the
    /// peer has not received, whatever its idle time: a sender held back by
    /// flow control or a dark path routes nothing for a while, and its next
    /// frame on a fresh stream would overtake that data.
    pub fn reap_idle(&mut self, now: Instant, mut in_flight: impl FnMut(u64) -> bool) -> Vec<u64> {
        let idle = self.idle;
        let mut reaped = Vec::new();
        self.by_flow.retain(|_, (stream, used)| {
            let keep = now.saturating_duration_since(*used) < idle || in_flight(*stream);
            if !keep {
                reaped.push(*stream);
            }
            keep
        });
        let still_used = self.open_streams();
        reaped.retain(|stream| !still_used.contains(stream));
        reaped.sort_unstable();
        reaped.dedup();
        self.recycled += reaped.len() as u64;
        reaped
    }

    /// Distinct open streams: several flows can share one.
    fn open_streams(&self) -> std::collections::HashSet<u64> {
        self.by_flow.values().map(|(stream, _)| *stream).collect()
    }

    pub fn open_count(&self) -> usize {
        self.open_streams().len()
    }

    pub fn open_count_for(&self, class: u8) -> u32 {
        self.by_flow
            .iter()
            .filter(|((c, _), _)| *c == class)
            .map(|(_, (stream, _))| *stream)
            .collect::<std::collections::HashSet<_>>()
            .len() as u32
    }
}

// ---------------------------------------------------------------------------
// Negotiation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Negotiated {
    Datagram { caps: u32 },
    StreamFallback(String),
    Disabled(String),
}

impl Negotiated {
    pub fn name(&self) -> &'static str {
        match self {
            Negotiated::Datagram { .. } => "datagram",
            Negotiated::StreamFallback(_) => "stream_fallback",
            Negotiated::Disabled(_) => "disabled",
        }
    }

    /// Whether both ends agreed to one-way delay probing
    /// (OWD_AUTORATE_PLAN.md 1.1): both ends announced `CAP_OWD_PROBE`.
    pub fn owd_probe(&self) -> bool {
        matches!(self, Negotiated::Datagram { caps } if caps & CAP_OWD_PROBE != 0)
    }

    pub fn reason(&self) -> &str {
        match self {
            Negotiated::Datagram { .. } => "",
            Negotiated::StreamFallback(reason) | Negotiated::Disabled(reason) => reason,
        }
    }
}

/// Decide the data plane of one session: both ends must have enabled it
/// (the peer's `max_datagram_frame_size` transport parameter) and the peer
/// must announce `mp_dataplane_caps` with the datagram bit.
pub fn negotiate(
    local_enabled: bool,
    peer_caps: Option<u32>,
    peer_max_datagram: Option<usize>,
) -> Negotiated {
    if !local_enabled {
        return Negotiated::Disabled("disabled in local config".into());
    }
    if peer_max_datagram.is_none() {
        return Negotiated::StreamFallback(
            "peer did not advertise max_datagram_frame_size".into(),
        );
    }
    let Some(peer_caps) = peer_caps else {
        return Negotiated::StreamFallback("peer did not announce mp_dataplane_caps".into());
    };
    if peer_caps & CAP_DATAGRAM == 0 {
        return Negotiated::StreamFallback("peer lacks the datagram capability".into());
    }
    Negotiated::Datagram {
        caps: LOCAL_DATAPLANE_CAPS & peer_caps,
    }
}

/// Virtual NIC MTU that keeps every inner packet within one datagram.
pub fn recommended_mtu(max_datagram: usize) -> u32 {
    max_datagram
        .saturating_sub(Datagram::WHOLE_OVERHEAD)
        .saturating_sub(TCP_TUNNEL_HEADER_SIZE)
        .saturating_sub(PEER_MANAGER_HEADER_SIZE)
        .saturating_sub(ET_AEAD_OVERHEAD) as u32
}

/// Largest inner IP packet that still fits in one datagram, for the
/// `icmp_ptb` oversize policy.
pub fn inner_packet_limit(max_datagram: usize) -> usize {
    recommended_mtu(max_datagram) as usize
}

// ---------------------------------------------------------------------------
// ICMP Packet Too Big (oversize policy `icmp_ptb`)
// ---------------------------------------------------------------------------

/// Build the ICMP "fragmentation needed" (IPv4) or "Packet Too Big" (IPv6)
/// the local host should see for `inner`, as if sent by its destination.
/// Built with pnet like ET's `gateway::icmp_proxy` replies.
pub fn build_packet_too_big(inner: &[u8], mtu: u32) -> Option<Vec<u8>> {
    use pnet::packet::{
        MutablePacket as _, Packet as _,
        icmp::{self, IcmpCode, IcmpTypes, MutableIcmpPacket},
        icmpv6::{self, Icmpv6Code, Icmpv6Types, MutableIcmpv6Packet},
        ip::IpNextHeaderProtocols,
        ipv4::{self, Ipv4Packet, MutableIpv4Packet},
        ipv6::{Ipv6Packet, MutableIpv6Packet},
    };
    let parsed = parse_inner_ip(inner)?;
    match (parsed.src, parsed.dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let ip = Ipv4Packet::new(inner)?;
            // Do not answer an ICMP error with an ICMP error.
            if parsed.protocol == IP_PROTO_ICMP
                && ip.payload().first().is_some_and(|t| *t != 8 && *t != 0)
            {
                return None;
            }
            let ihl = ip.get_header_length() as usize * 4;
            let quoted = &inner[..inner.len().min(ihl + 8)];
            // ICMP header 4 + unused 2 + next-hop MTU 2 (RFC 1191).
            let icmp_len = 8 + quoted.len();
            let mut buf = vec![0u8; 20 + icmp_len];
            {
                let mut icmp_packet = MutableIcmpPacket::new(&mut buf[20..])?;
                icmp_packet.set_icmp_type(IcmpTypes::DestinationUnreachable);
                icmp_packet.set_icmp_code(IcmpCode::new(4));
                let payload = icmp_packet.payload_mut();
                payload[2..4].copy_from_slice(&(mtu.min(u16::MAX as u32) as u16).to_be_bytes());
                payload[4..].copy_from_slice(quoted);
                icmp_packet.set_checksum(icmp::checksum(&icmp_packet.to_immutable()));
            }
            let mut ip_packet = MutableIpv4Packet::new(&mut buf[..])?;
            ip_packet.set_version(4);
            ip_packet.set_header_length(5);
            ip_packet.set_total_length((20 + icmp_len) as u16);
            ip_packet.set_ttl(64);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ip_packet.set_source(dst);
            ip_packet.set_destination(src);
            ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));
            Some(buf)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let ip = Ipv6Packet::new(inner)?;
            if parsed.protocol == IP_PROTO_ICMPV6 && ip.payload().first().is_some_and(|t| *t < 128) {
                return None;
            }
            // The whole error must fit the IPv6 minimum MTU.
            let quoted = &inner[..inner.len().min(1280 - 40 - 8)];
            let icmp_len = 8 + quoted.len();
            let mut buf = vec![0u8; 40 + icmp_len];
            {
                let mut icmp_packet = MutableIcmpv6Packet::new(&mut buf[40..])?;
                icmp_packet.set_icmpv6_type(Icmpv6Types::PacketTooBig);
                icmp_packet.set_icmpv6_code(Icmpv6Code::new(0));
                let payload = icmp_packet.payload_mut();
                payload[..4].copy_from_slice(&mtu.to_be_bytes());
                payload[4..].copy_from_slice(quoted);
                icmp_packet.set_checksum(icmpv6::checksum(&icmp_packet.to_immutable(), &dst, &src));
            }
            let mut ip_packet = MutableIpv6Packet::new(&mut buf[..])?;
            ip_packet.set_version(6);
            ip_packet.set_payload_length(icmp_len as u16);
            ip_packet.set_next_header(IpNextHeaderProtocols::Icmpv6);
            ip_packet.set_hop_limit(64);
            ip_packet.set_source(dst);
            ip_packet.set_destination(src);
            Some(buf)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Counters and status
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClassCounters {
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DataPlaneCounters {
    pub classes: BTreeMap<TrafficClass, ClassCounters>,
    /// Packets too large for a datagram that were dropped without an ICMP
    /// answer (not IP, or no limit known yet).
    pub oversize_dropped: u64,
    pub oversize_ptb: u64,
    pub frag_sent: u64,
    pub frag_reassembled: u64,
    pub frag_timeout: u64,
}

impl DataPlaneCounters {
    pub fn class(&mut self, class: TrafficClass) -> &mut ClassCounters {
        self.classes.entry(class).or_default()
    }

    pub fn on_tx(&mut self, class: TrafficClass, bytes: usize) {
        let c = self.class(class);
        c.tx_packets += 1;
        c.tx_bytes += bytes as u64;
    }

    pub fn on_rx(&mut self, class: TrafficClass, bytes: usize) {
        let c = self.class(class);
        c.rx_packets += 1;
        c.rx_bytes += bytes as u64;
    }
}

/// Everything `MpDataPlaneStatus` reports, gathered by the driver.
pub struct DataPlaneStatusInput<'a> {
    pub policy: &'a DataPlanePolicy,
    pub negotiated: &'a Negotiated,
    pub max_datagram: Option<usize>,
    pub counters: &'a DataPlaneCounters,
    pub open_streams: &'a dyn Fn(TrafficClass) -> u32,
    pub streams_recycled: u64,
    pub dgram_queue_dropped: u64,
    pub circuit_breaker_trips: u32,
    pub stream_aqm_drops: u64,
    pub stream_overlimit_drops: u64,
    pub dgram_aqm_drops: u64,
    pub dgram_overlimit_drops: u64,
}

pub fn status(input: DataPlaneStatusInput<'_>) -> MpDataPlaneStatus {
    let mut classes = input
        .policy
        .classes()
        .into_iter()
        .map(|class| {
            let counters = input.counters.classes.get(&class).cloned().unwrap_or_default();
            let mode = match input.negotiated {
                Negotiated::Datagram { .. } => input.policy.mode_for(class).name(),
                _ => "stream",
            };
            MpClassStatus {
                class: input.policy.class_name(class),
                mode: mode.to_string(),
                tx_packets: counters.tx_packets,
                tx_bytes: counters.tx_bytes,
                rx_packets: counters.rx_packets,
                rx_bytes: counters.rx_bytes,
                open_streams: (input.open_streams)(class),
                streams_recycled: 0,
            }
        })
        .collect::<Vec<_>>();
    // Stream recycling is per session; report it on the first class that
    // uses reliable streams.
    if let Some(first) = classes.iter_mut().find(|c| c.mode == "reliable_stream") {
        first.streams_recycled = input.streams_recycled;
    }
    MpDataPlaneStatus {
        negotiated: input.negotiated.name().to_string(),
        fallback_reason: input.negotiated.reason().to_string(),
        max_datagram_bytes: input.max_datagram.unwrap_or(0) as u32,
        recommended_mtu: input.max_datagram.map(recommended_mtu).unwrap_or(0),
        classes,
        oversize_dropped: input.counters.oversize_dropped,
        oversize_ptb: input.counters.oversize_ptb,
        frag_sent: input.counters.frag_sent,
        frag_reassembled: input.counters.frag_reassembled,
        frag_timeout: input.counters.frag_timeout,
        dgram_queue_dropped: input.dgram_queue_dropped,
        circuit_breaker_trips: input.circuit_breaker_trips,
        stream_aqm_drops: input.stream_aqm_drops,
        stream_overlimit_drops: input.stream_overlimit_drops,
        dgram_aqm_drops: input.dgram_aqm_drops,
        dgram_overlimit_drops: input.dgram_overlimit_drops,
    }
}

/// Status of a session that never runs the data plane.
pub fn disabled_status(reason: &str) -> MpDataPlaneStatus {
    MpDataPlaneStatus {
        negotiated: "disabled".to_string(),
        fallback_reason: reason.to_string(),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn class_policy(class: &str, mode: &str) -> MpClassPolicy {
        MpClassPolicy {
            class: class.to_string(),
            mode: mode.to_string(),
            ..Default::default()
        }
    }

    fn rule(name: &str, protocol: &str, ports: &str, cidr: &str) -> MpClassRule {
        MpClassRule {
            name: name.to_string(),
            protocol: protocol.to_string(),
            port_range: ports.to_string(),
            dst_cidr: cidr.to_string(),
            enabled: true,
        }
    }

    fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, proto, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&[0; 16]);
        p
    }

    fn ipv6(proto: u8, sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0, 0, 16, proto, 64];
        p.extend_from_slice(&"fd00::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&"fd00::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&[0; 12]);
        p
    }

    #[test]
    fn default_policy_is_disabled_and_datagram_except_tcp_and_proxy() {
        let policy = DataPlanePolicy::from_config(&MpDataPlaneConfig::default()).unwrap();
        assert!(!policy.enabled);
        assert_eq!(policy.oversize, OversizePolicy::IcmpPtb);
        for class in BUILTIN_CLASSES {
            let expected = if class == TrafficClass::Tcp || class == TrafficClass::Proxy {
                ClassMode::ReliableStream
            } else {
                ClassMode::Datagram
            };
            assert_eq!(policy.mode_for(class), expected, "{class:?}");
        }
        // An explicit policy still wins.
        let policy = DataPlanePolicy::from_config(&MpDataPlaneConfig {
            class_policies: vec![class_policy("tcp", "datagram")],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(policy.mode_for(TrafficClass::Tcp), ClassMode::Datagram);
        // The proxy rides streams unless a policy puts it on datagrams.
        let policy = DataPlanePolicy::from_config(&MpDataPlaneConfig {
            class_policies: vec![class_policy("proxy", "datagram")],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(policy.mode_for(TrafficClass::Proxy), ClassMode::Datagram);
        assert_eq!(policy.reliable_stream_max, DEFAULT_RELIABLE_STREAM_MAX);
        assert_eq!(policy.reliable_stream_idle, DEFAULT_RELIABLE_STREAM_IDLE);
    }

    /// The removed `stream` oversize policy reads as the default, so an old
    /// config keeps its data plane instead of failing to parse.
    #[test]
    fn legacy_stream_oversize_policy_means_icmp_ptb() {
        for value in ["", "stream", "icmp_ptb"] {
            let config = MpDataPlaneConfig {
                enabled: true,
                oversize: value.into(),
                ..Default::default()
            };
            assert_eq!(
                DataPlanePolicy::from_config(&config).unwrap().oversize,
                OversizePolicy::IcmpPtb,
                "{value:?}"
            );
        }
    }

    #[test]
    fn policy_parses_every_mode_and_rejects_bad_values() {
        let mut config = MpDataPlaneConfig {
            enabled: true,
            oversize: "fragment".into(),
            class_policies: vec![
                class_policy("tcp", "reliable_stream"),
                class_policy("game", "datagram"),
            ],
            class_rules: vec![rule("game", "udp", "27015-27030", "")],
            ..Default::default()
        };
        let policy = DataPlanePolicy::from_config(&config).unwrap();
        assert_eq!(policy.oversize, OversizePolicy::Fragment);
        assert_eq!(policy.mode_for(TrafficClass::Tcp), ClassMode::ReliableStream);
        assert_eq!(policy.mode_for(TrafficClass::Udp), ClassMode::Datagram);
        assert_eq!(policy.mode_for(TrafficClass::Rule(0)), ClassMode::Datagram);
        assert_eq!(policy.class_name(TrafficClass::Rule(0)), "game");

        config.class_policies[1].mode = "bounded_arq".into();
        assert!(DataPlanePolicy::from_config(&config).is_err());
        config.class_policies[1].mode = "fec".into();
        assert!(DataPlanePolicy::from_config(&config).is_err());
        config.class_policies[1].mode = "datagram".into();
        config.oversize = "truncate".into();
        assert!(DataPlanePolicy::from_config(&config).is_err());
        config.oversize = "icmp_ptb".into();
        config.class_policies.push(class_policy("nope", "datagram"));
        assert!(DataPlanePolicy::from_config(&config).is_err());
        config.class_policies.pop();
        config.class_policies.push(class_policy("tcp", "datagram"));
        assert!(DataPlanePolicy::from_config(&config).is_err());
        config.class_policies.pop();
        config.class_rules.push(rule("udp", "udp", "", ""));
        assert!(DataPlanePolicy::from_config(&config).is_err());
        config.class_rules.pop();
        config.class_rules.push(rule("bad", "icmp", "22", ""));
        assert!(DataPlanePolicy::from_config(&config).is_err());
        config.class_rules.pop();
        config.class_rules.push(rule("bad", "tcp", "30-20", ""));
        assert!(DataPlanePolicy::from_config(&config).is_err());
        config.class_rules.pop();
        assert!(DataPlanePolicy::from_config(&config).is_ok());
    }

    #[test]
    fn policy_for_a_disabled_rule_is_accepted_but_inert() {
        let mut game = rule("game", "udp", "", "");
        game.enabled = false;
        let config = MpDataPlaneConfig {
            class_policies: vec![class_policy("game", "reliable_stream")],
            class_rules: vec![game],
            ..Default::default()
        };
        let policy = DataPlanePolicy::from_config(&config).unwrap();
        assert!(policy.rules.is_empty());
        assert_eq!(policy.classes().len(), BUILTIN_CLASSES.len());
    }

    #[test]
    fn classifier_table() {
        let config = MpDataPlaneConfig {
            class_rules: vec![
                rule("ssh", "tcp", "22", ""),
                rule("lan", "any", "", "10.9.0.0/16"),
                rule("dns6", "udp", "53", "fd00::/64"),
            ],
            ..Default::default()
        };
        let policy = DataPlanePolicy::from_config(&config).unwrap();
        let cases: Vec<(Vec<u8>, TrafficClass)> = vec![
            (ipv4(6, [10, 0, 0, 1], [10, 1, 0, 1], 5000, 22), TrafficClass::Rule(0)),
            (ipv4(6, [10, 1, 0, 1], [10, 0, 0, 1], 22, 5000), TrafficClass::Rule(0)),
            (ipv4(6, [10, 0, 0, 1], [10, 1, 0, 1], 5000, 80), TrafficClass::Tcp),
            (ipv4(17, [10, 0, 0, 1], [10, 9, 3, 3], 5000, 80), TrafficClass::Rule(1)),
            (ipv4(17, [10, 0, 0, 1], [10, 1, 0, 1], 5000, 80), TrafficClass::Udp),
            (ipv4(1, [10, 0, 0, 1], [10, 1, 0, 1], 0, 0), TrafficClass::Icmp),
            (ipv4(47, [10, 0, 0, 1], [10, 1, 0, 1], 0, 0), TrafficClass::Other),
            (ipv6(17, 4000, 53), TrafficClass::Rule(2)),
            (ipv6(6, 4000, 53), TrafficClass::Tcp),
            (ipv6(58, 0, 0), TrafficClass::Icmp),
            (vec![0x00, 1, 2], TrafficClass::Other),
        ];
        for (packet, expected) in cases {
            assert_eq!(policy.classify_ip(&packet).0, expected, "{packet:?}");
        }
    }

    #[test]
    fn flow_hash_is_direction_independent() {
        let policy = DataPlanePolicy::default();
        let a = policy.classify_ip(&ipv4(6, [10, 0, 0, 1], [10, 1, 0, 1], 5000, 443)).1;
        let b = policy.classify_ip(&ipv4(6, [10, 1, 0, 1], [10, 0, 0, 1], 443, 5000)).1;
        assert_eq!(a, b);
        assert_ne!(a, 0);
    }

    /// The reliable-stream mapping must not change with the 32-bit hash: the
    /// bucket is the hash's low byte, as the 8-bit hash was.
    #[test]
    fn flow_hash_keeps_the_reliable_stream_bucket_of_the_old_u8_hash() {
        use std::hash::{Hash, Hasher};
        let packet = ipv4(6, [10, 0, 0, 1], [10, 1, 0, 1], 5000, 443);
        let inner = parse_inner_ip(&packet).unwrap();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        let (a, b) = (
            (inner.src, inner.ports.map(|p| p.0)),
            (inner.dst, inner.ports.map(|p| p.1)),
        );
        a.hash(&mut hasher);
        b.hash(&mut hasher);
        inner.protocol.hash(&mut hasher);
        let old_bucket = hasher.finish() as u8;
        let frame = PipeFrame {
            frame: Bytes::new(),
            tag: 0,
            flow_hash: DataPlanePolicy::default().classify_ip(&packet).1,
        };
        assert_eq!(frame.bucket(), old_bucket);
    }

    #[test]
    fn flows_and_non_ip_packets_get_distinct_and_zero_hashes() {
        let policy = DataPlanePolicy::default();
        let a = policy.classify_ip(&ipv4(17, [10, 0, 0, 1], [10, 1, 0, 1], 5000, 443)).1;
        let b = policy.classify_ip(&ipv4(17, [10, 0, 0, 1], [10, 1, 0, 1], 5001, 443)).1;
        assert_ne!(a, b);
        assert_eq!(policy.classify_ip(&[0x00, 1, 2]).1, 0);
    }

    #[test]
    fn untagged_frames_are_classified_by_packet_type() {
        let cases = [
            (PacketType::Data, TrafficClass::Other),
            (PacketType::Ping, TrafficClass::EtControl),
            (PacketType::RpcReq, TrafficClass::EtControl),
            (PacketType::HandShake, TrafficClass::EtControl),
            (PacketType::QuicSrc, TrafficClass::Proxy),
            (PacketType::KcpDst, TrafficClass::Proxy),
            (PacketType::MpRelayDatagram, TrafficClass::EtControl),
        ];
        for (packet_type, class) in cases {
            assert_eq!(TrafficClass::from_packet_type(packet_type as u8), class);
        }
        for class in BUILTIN_CLASSES.into_iter().chain([TrafficClass::Rule(3)]) {
            assert_eq!(TrafficClass::from_tag(class.tag()), Some(class));
        }
        assert_eq!(TrafficClass::from_tag(0), None);
    }

    fn frame(packet_type: u8, payload: &[u8]) -> Vec<u8> {
        let body = PEER_MANAGER_HEADER_SIZE + payload.len();
        let mut f = (body as u32).to_le_bytes().to_vec();
        let mut header = vec![0u8; PEER_MANAGER_HEADER_SIZE];
        header[8] = packet_type;
        f.extend_from_slice(&header);
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn splitter_restores_clean_headers_and_handles_partial_input() {
        let mut first = frame(PacketType::Data as u8, b"hello");
        let tagged = encode_pipe_len(PEER_MANAGER_HEADER_SIZE + 5, 2);
        first[..4].copy_from_slice(&tagged.to_le_bytes());
        first.extend_from_slice(&0xdead_beef_u32.to_le_bytes());
        let mut second = frame(PacketType::Ping as u8, b"x");
        let clean_second = second.clone();
        second.extend_from_slice(&0u32.to_le_bytes());
        let mut stream = first.clone();
        stream.extend_from_slice(&second);

        let mut splitter = FrameSplitter::pipe();
        splitter.push(&stream[..7]);
        assert!(splitter.next_frame().is_none());
        splitter.push(&stream[7..stream.len() - 1]);
        // The last frame lacks the final byte of its trailer.
        let a = splitter.next_frame().unwrap().unwrap();
        assert_eq!((a.tag, a.flow_hash, a.flow()), (2, 0xdead_beef, Some(0xdead_beef)));
        assert_eq!(a.class(), TrafficClass::Tcp);
        assert_eq!(&a.frame[..], &frame(PacketType::Data as u8, b"hello")[..]);
        assert!(splitter.next_frame().is_none());
        splitter.push(&stream[stream.len() - 1..]);
        let b = splitter.next_frame().unwrap().unwrap();
        assert_eq!((b.tag, b.flow_hash, b.flow()), (0, 0, None));
        assert_eq!(b.class(), TrafficClass::EtControl);
        assert_eq!(&b.frame[..], &clean_second[..]);
        assert!(splitter.next_frame().is_none());
        assert_eq!(splitter.buffered(), 0);

        splitter.push(&[1, 0, 0, 0]);
        assert!(splitter.next_frame().unwrap().is_err());

        // A stream from the network has no trailer.
        let mut network = FrameSplitter::default();
        network.push(&clean_second);
        let n = network.next_frame().unwrap().unwrap();
        assert_eq!(&n.frame[..], &clean_second[..]);
        assert_eq!(n.flow_hash, 0);

        assert!(is_whole_frame(&clean_second));
        assert!(!is_whole_frame(&clean_second[..clean_second.len() - 1]));
        assert!(!is_whole_frame(&first));
        assert!(!is_whole_frame(&[0, 0, 0, 0]));
    }

    #[test]
    fn datagram_header_round_trips() {
        let frame = Bytes::from(frame(1, b"payload"));
        let cases = vec![
            Datagram::Whole(frame.clone()),
            Datagram::Fragment {
                packet_id: 0xdead_beef,
                index: 2,
                count: 3,
                chunk: frame.slice(3..9),
            },
        ];
        for datagram in cases {
            let encoded = datagram.encode();
            assert_eq!(Datagram::decode(&encoded), Some(datagram));
        }
        assert_eq!(
            Datagram::Whole(frame.clone()).encode().len(),
            frame.len() + Datagram::WHOLE_OVERHEAD
        );
    }

    /// OWD_AUTORATE_PLAN.md 1.1 (R3): the probe and its report survive the codec.
    #[test]
    fn owd_probe_and_report_round_trip() {
        let probe = Datagram::OwdProbe { seq: 0xfeed_0042 };
        assert_eq!(Datagram::decode(&probe.encode()), Some(probe));

        let report = Datagram::OwdReport {
            entries: vec![(7, 1), (8, u64::MAX), (u32::MAX, 123_456_789_012)],
        };
        let encoded = report.encode();
        assert_eq!(encoded.len(), Datagram::owd_report_len(3));
        assert_eq!(Datagram::decode(&encoded), Some(report));

        let full = Datagram::OwdReport {
            entries: (0..OWD_REPORT_MAX_ENTRIES as u32)
                .map(|i| (i, i as u64 * 10))
                .collect(),
        };
        assert_eq!(Datagram::decode(&full.encode()), Some(full));
        // An empty report, or one that claims more than the limit, is malformed.
        let mut over = BytesMut::new();
        over.put_u8(CTX_OWD_REPORT as u8);
        over.put_u8(OWD_REPORT_MAX_ENTRIES as u8 + 1);
        over.resize(2 + 12 * (OWD_REPORT_MAX_ENTRIES + 1), 0);
        assert_eq!(Datagram::decode(&over.freeze()), None);
        assert_eq!(Datagram::decode(&Bytes::from_static(&[3, 0])), None);
    }

    /// OWD_AUTORATE_PLAN.md 1.1 (R3): probes are sent only when both ends
    /// announce `CAP_OWD_PROBE`; a peer that predates it is left as it was.
    #[test]
    fn owd_contexts_are_dropped_without_the_capability() {
        let both = negotiate(true, Some(LOCAL_DATAPLANE_CAPS), Some(1400));
        assert!(
            LOCAL_DATAPLANE_CAPS & CAP_OWD_PROBE != 0,
            "this build announces the capability"
        );
        assert!(both.owd_probe());
        let old_peer = negotiate(true, Some(CAP_DATAGRAM | CAP_FRAGMENT), Some(1400));
        assert_eq!(
            old_peer,
            Negotiated::Datagram {
                caps: CAP_DATAGRAM | CAP_FRAGMENT
            },
            "the capability is the intersection of both ends"
        );
        assert!(
            !old_peer.owd_probe(),
            "no probe to a peer without the capability"
        );
        assert!(!negotiate(true, Some(LOCAL_DATAPLANE_CAPS), None).owd_probe());
        assert!(!negotiate(true, None, Some(1400)).owd_probe());
        assert!(!negotiate(false, Some(LOCAL_DATAPLANE_CAPS), Some(1400)).owd_probe());
        // What a peer without the capability does with a probe: decode gives
        // `None` for contexts it does not know (the previous test), so it drops it.
    }

    #[test]
    fn datagram_header_rejects_reserved_and_malformed() {
        // Contexts 4 and above are reserved; a probe or report cut short is malformed.
        assert_eq!(Datagram::decode(&Bytes::from_static(&[2, 1, 2])), None);
        assert_eq!(
            Datagram::decode(&Bytes::from_static(&[3, 2, 0, 0, 0, 1])),
            None
        );
        assert_eq!(Datagram::decode(&Bytes::from_static(&[3, 0])), None);
        assert_eq!(Datagram::decode(&Bytes::from_static(&[4, 1, 2])), None);
        assert_eq!(Datagram::decode(&Bytes::from_static(&[0x40])), None);
        assert_eq!(Datagram::decode(&Bytes::from_static(&[1, 0, 0])), None);
        // index >= count
        assert_eq!(
            Datagram::decode(&Bytes::from_static(&[1, 0, 0, 0, 1, 3, 3, 9])),
            None
        );
        assert_eq!(Datagram::decode(&Bytes::new()), None);
    }

    #[test]
    fn fragmentation_round_trip_and_limits() {
        let frame = Bytes::from((0..3000u32).map(|i| i as u8).collect::<Vec<_>>());
        let pieces = fragment(&frame, 7, 1000).unwrap();
        assert_eq!(pieces.len(), 4);
        let mut reassembler = Reassembler::default();
        let now = Instant::now();
        let mut whole = None;
        for piece in pieces.into_iter().rev() {
            let encoded = piece.encode();
            assert!(encoded.len() <= 1000);
            match Datagram::decode(&encoded).unwrap() {
                Datagram::Fragment {
                    packet_id,
                    index,
                    count,
                    chunk,
                } => {
                    whole = reassembler.add(packet_id, index, count, chunk, now);
                }
                _ => unreachable!(),
            }
        }
        assert_eq!(whole.unwrap(), frame);
        assert!(fragment(&frame, 8, 700).is_none());
        assert!(fragment(&frame, 8, Datagram::FRAGMENT_OVERHEAD).is_none());
    }

    #[test]
    fn reassembly_times_out() {
        let mut reassembler = Reassembler::default();
        let now = Instant::now();
        assert!(reassembler.add(1, 0, 2, Bytes::from_static(b"a"), now).is_none());
        assert_eq!(reassembler.expire(now + REASSEMBLY_TIMEOUT / 2), 0);
        assert_eq!(reassembler.expire(now + REASSEMBLY_TIMEOUT), 1);
        assert!(reassembler.add(1, 1, 2, Bytes::from_static(b"b"), now).is_none());
    }

    #[test]
    fn reliable_streams_lru_and_idle() {
        let now = Instant::now();
        let mut streams = ReliableStreams::new(2, Duration::from_secs(30));
        let mut next = 4u64;
        let mut open = || {
            let id = next;
            next += 4;
            Some(id)
        };
        assert_eq!(streams.stream_for((2, 1), now, &mut open), Some(4));
        assert_eq!(streams.stream_for((2, 1), now, &mut open), Some(4));
        assert_eq!(
            streams.stream_for((2, 2), now + Duration::from_secs(1), &mut open),
            Some(8)
        );
        // Limit reached: flow 3 shares the least recently used stream (flow
        // 1's), and flow 1 stays on it.
        assert_eq!(
            streams.stream_for((2, 3), now + Duration::from_secs(2), &mut open),
            Some(4)
        );
        assert_eq!(streams.recycled, 1);
        assert_eq!(streams.open_count(), 2);
        assert_eq!(streams.open_count_for(2), 2);
        assert_eq!(streams.stream_for((2, 1), now + Duration::from_secs(2), &mut open), Some(4));
        // Flow 2's stream (last used at 1 s) is idle past 30 s; the shared
        // stream (last used at 2 s) is not yet.
        let reaped = streams.reap_idle(now + Duration::from_millis(31_500), |_| false);
        assert_eq!(reaped, vec![8]);
        assert_eq!(streams.open_count(), 1);
    }

    /// A flow whose stream still holds unacknowledged data stays on it
    /// however long it routed nothing; its next frame must not overtake
    /// that data on a fresh stream.
    #[test]
    fn reliable_streams_keep_a_flow_with_data_in_flight() {
        let now = Instant::now();
        let mut streams = ReliableStreams::new(8, Duration::from_millis(200));
        let mut next = 4u64;
        let mut open = || {
            let id = next;
            next += 4;
            Some(id)
        };
        assert_eq!(streams.stream_for((5, 0), now, &mut open), Some(4));
        assert_eq!(streams.stream_for((5, 1), now, &mut open), Some(8));
        let later = now + Duration::from_secs(5);
        let reaped = streams.reap_idle(later, |stream| stream == 4);
        assert_eq!(reaped, vec![8]);
        assert_eq!(streams.stream_for((5, 0), later, &mut open), Some(4));
        // Delivered: now it may go.
        let reaped = streams.reap_idle(later + Duration::from_secs(1), |_| false);
        assert_eq!(reaped, vec![4]);
        assert_eq!(streams.open_count(), 0);
    }

    #[test]
    fn negotiation_matrix() {
        assert_eq!(
            negotiate(true, Some(LOCAL_DATAPLANE_CAPS), Some(1400)),
            Negotiated::Datagram {
                caps: LOCAL_DATAPLANE_CAPS
            }
        );
        assert!(matches!(
            negotiate(true, Some(LOCAL_DATAPLANE_CAPS), None),
            Negotiated::StreamFallback(_)
        ));
        assert!(matches!(
            negotiate(true, None, Some(1400)),
            Negotiated::StreamFallback(_)
        ));
        assert!(matches!(
            negotiate(true, Some(CAP_FRAGMENT), Some(1400)),
            Negotiated::StreamFallback(_)
        ));
        assert!(matches!(
            negotiate(false, Some(LOCAL_DATAPLANE_CAPS), Some(1400)),
            Negotiated::Disabled(_)
        ));
        // A peer that cannot reassemble gets the ICMP answer instead.
        assert_eq!(
            OversizePolicy::Fragment.restricted_to(CAP_DATAGRAM),
            OversizePolicy::IcmpPtb
        );
        assert_eq!(
            OversizePolicy::Fragment.restricted_to(LOCAL_DATAPLANE_CAPS),
            OversizePolicy::Fragment
        );
    }

    #[test]
    fn packet_too_big_ipv4_fields() {
        use pnet::packet::{Packet as _, icmp, icmp::IcmpPacket, ipv4, ipv4::Ipv4Packet};
        let inner = ipv4(17, [10, 0, 0, 1], [10, 1, 0, 1], 5000, 80);
        let ptb = build_packet_too_big(&inner, 1300).unwrap();
        let ip = Ipv4Packet::new(&ptb).unwrap();
        assert_eq!(ip.get_version(), 4);
        assert_eq!(ip.get_next_level_protocol().0, IP_PROTO_ICMP);
        assert_eq!(ip.get_source().octets(), [10, 1, 0, 1]);
        assert_eq!(ip.get_destination().octets(), [10, 0, 0, 1]);
        assert_eq!(ip.get_checksum(), ipv4::checksum(&ip));
        assert_eq!(ip.get_total_length() as usize, ptb.len());
        let icmp_packet = IcmpPacket::new(ip.payload()).unwrap();
        assert_eq!((icmp_packet.get_icmp_type().0, icmp_packet.get_icmp_code().0), (3, 4));
        assert_eq!(icmp_packet.get_checksum(), icmp::checksum(&icmp_packet));
        let rest = icmp_packet.payload();
        assert_eq!(u16::from_be_bytes([rest[2], rest[3]]), 1300);
        assert_eq!(&rest[4..], &inner[..28]);
    }

    #[test]
    fn packet_too_big_ipv6_fields() {
        use pnet::packet::{Packet as _, icmpv6, icmpv6::Icmpv6Packet, ipv6::Ipv6Packet};
        let inner = ipv6(17, 4000, 53);
        let ptb = build_packet_too_big(&inner, 1400).unwrap();
        let ip = Ipv6Packet::new(&ptb).unwrap();
        assert_eq!(ip.get_version(), 6);
        assert_eq!(ip.get_next_header().0, IP_PROTO_ICMPV6);
        assert_eq!(&ptb[8..24], &inner[24..40]);
        assert_eq!(&ptb[24..40], &inner[8..24]);
        let icmp_packet = Icmpv6Packet::new(ip.payload()).unwrap();
        assert_eq!(icmp_packet.get_icmpv6_type().0, 2);
        assert_eq!(
            icmp_packet.get_checksum(),
            icmpv6::checksum(&icmp_packet, &ip.get_source(), &ip.get_destination())
        );
        let rest = icmp_packet.payload();
        assert_eq!(u32::from_be_bytes(rest[..4].try_into().unwrap()), 1400);
        // No error in response to an ICMPv6 error.
        let mut error = ipv6(58, 0, 0);
        error[40] = 1;
        assert!(build_packet_too_big(&error, 1400).is_none());
    }

    #[test]
    fn inner_ip_parser_matches_flow_hash_needs() {
        let tcp = parse_inner_ip(&ipv4(6, [10, 0, 0, 1], [10, 1, 0, 1], 5000, 80)).unwrap();
        assert_eq!((tcp.protocol, tcp.ports, tcp.fragment_id), (IP_PROTO_TCP, Some((5000, 80)), None));
        // A non-first IPv4 fragment has no ports but keeps its identification.
        let mut frag = ipv4(17, [10, 0, 0, 1], [10, 1, 0, 1], 5000, 80);
        frag[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        frag[6..8].copy_from_slice(&0x0010u16.to_be_bytes());
        let frag = parse_inner_ip(&frag).unwrap();
        assert_eq!((frag.ports, frag.fragment_id), (None, Some(0x1234)));
        let v6 = parse_inner_ip(&ipv6(17, 4000, 53)).unwrap();
        assert_eq!(v6.ports, Some((4000, 53)));
        assert!(parse_inner_ip(&[0x45, 0, 0]).is_none());
    }

    #[test]
    fn recommended_mtu_subtracts_every_header() {
        assert_eq!(
            recommended_mtu(1400) as usize,
            1400 - 1 - TCP_TUNNEL_HEADER_SIZE - PEER_MANAGER_HEADER_SIZE - ET_AEAD_OVERHEAD
        );
        assert_eq!(recommended_mtu(0), 0);
    }

    #[test]
    fn status_reports_modes_and_counters() {
        let config = MpDataPlaneConfig {
            enabled: true,
            class_policies: vec![class_policy("tcp", "reliable_stream")],
            ..Default::default()
        };
        let policy = DataPlanePolicy::from_config(&config).unwrap();
        let mut counters = DataPlaneCounters::default();
        counters.on_tx(TrafficClass::Tcp, 100);
        counters.on_rx(TrafficClass::Udp, 50);
        counters.oversize_dropped = 3;
        let negotiated = Negotiated::Datagram {
            caps: LOCAL_DATAPLANE_CAPS,
        };
        let status = status(DataPlaneStatusInput {
            policy: &policy,
            negotiated: &negotiated,
            max_datagram: Some(1400),
            counters: &counters,
            open_streams: &|class| u32::from(class == TrafficClass::Tcp),
            streams_recycled: 5,
            dgram_queue_dropped: 2,
            circuit_breaker_trips: 1,
            stream_aqm_drops: 7,
            stream_overlimit_drops: 3,
            dgram_aqm_drops: 5,
            dgram_overlimit_drops: 4,
        });
        assert_eq!(status.negotiated, "datagram");
        assert_eq!(status.max_datagram_bytes, 1400);
        assert_eq!(status.recommended_mtu, recommended_mtu(1400));
        let tcp = status.classes.iter().find(|c| c.class == "tcp").unwrap();
        assert_eq!(tcp.mode, "reliable_stream");
        assert_eq!((tcp.tx_packets, tcp.tx_bytes, tcp.open_streams), (1, 100, 1));
        assert_eq!(tcp.streams_recycled, 5);
        let udp = status.classes.iter().find(|c| c.class == "udp").unwrap();
        assert_eq!((udp.mode.as_str(), udp.rx_bytes), ("datagram", 50));
        assert_eq!(status.oversize_dropped, 3);
        assert_eq!(status.dgram_queue_dropped, 2);
        assert_eq!(status.circuit_breaker_trips, 1);
        assert_eq!((status.stream_aqm_drops, status.stream_overlimit_drops), (7, 3));
        assert_eq!((status.dgram_aqm_drops, status.dgram_overlimit_drops), (5, 4));

        let fallback = Negotiated::StreamFallback("peer did not announce mp_dataplane_caps".into());
        let status = super::status(DataPlaneStatusInput {
            policy: &policy,
            negotiated: &fallback,
            max_datagram: None,
            counters: &counters,
            open_streams: &|_| 0,
            streams_recycled: 0,
            dgram_queue_dropped: 0,
            circuit_breaker_trips: 0,
            stream_aqm_drops: 0,
            stream_overlimit_drops: 0,
            dgram_aqm_drops: 0,
            dgram_overlimit_drops: 0,
        });
        assert_eq!(status.negotiated, "stream_fallback");
        assert!(status.fallback_reason.contains("mp_dataplane_caps"));
        assert!(status.classes.iter().all(|c| c.mode == "stream"));
    }
}

//! Linux CAKE (`net/sched/sch_cake.c`, compiled unchanged) as a reusable user-space smart queue.
//!
//! [`Cake<T>`] is one CAKE qdisc. It never touches real packets: the caller enqueues an item of
//! its own type `T` together with the packet's length and header (see [`PacketMeta`]), and gets
//! the item back from [`Cake::dequeue`] when CAKE lets it go, or from [`Cake::enqueue`] /
//! [`Cake::take_dropped`] when CAKE drops it. Time is whatever [`Instant`] the caller passes in,
//! so tests run on a virtual clock and never sleep.
//!
//! Every call needs `&mut self`; an instance is `Send` (if `T` is) and not `Sync`.

mod ffi;

use std::net::{IpAddr, SocketAddr};
use std::ptr::NonNull;
use std::time::{Duration, Instant};

/// SHA-256 of the `sch_cake.c` this crate was built from (checked by `build.rs`).
pub const SCH_CAKE_SHA256: &str = env!("CAKE_SQM_SCH_CAKE_SHA256");

/// CAKE's clock starts here, so that a timestamp is never 0 (`wake_ns == 0` means "no timer").
const CLOCK_OFFSET_NS: u64 = 1_000_000_000;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

// TCA_CAKE_* attribute types (include/uapi/linux/pkt_sched.h).
const TCA_CAKE_BASE_RATE64: u16 = 2;
const TCA_CAKE_DIFFSERV_MODE: u16 = 3;
const TCA_CAKE_FLOW_MODE: u16 = 5;
const TCA_CAKE_OVERHEAD: u16 = 6;
const TCA_CAKE_RTT: u16 = 7;
const TCA_CAKE_TARGET: u16 = 8;
const TCA_CAKE_MEMORY: u16 = 10;
const TCA_CAKE_RAW: u16 = 12;
const TCA_CAKE_WASH: u16 = 13;
const TCA_CAKE_MPU: u16 = 14;
const TCA_CAKE_ACK_FILTER: u16 = 16;

/// How CAKE sorts packets into priority tins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Diffserv {
    Diffserv3,
    Diffserv4,
    Diffserv8,
    /// One tin: no priorities.
    BestEffort,
    Precedence,
}

impl Diffserv {
    fn code(self) -> u32 {
        match self {
            Diffserv::Diffserv3 => 0,
            Diffserv::Diffserv4 => 1,
            Diffserv::Diffserv8 => 2,
            Diffserv::BestEffort => 3,
            Diffserv::Precedence => 4,
        }
    }
}

/// What CAKE isolates: flows, hosts or both (`tc` keywords in the comments).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowMode {
    /// `flowblind`
    FlowBlind,
    /// `srchost`
    SrcHost,
    /// `dsthost`
    DstHost,
    /// `hosts`
    Hosts,
    /// `flows`
    Flows,
    /// `dual-srchost`
    DualSrc,
    /// `dual-dsthost`
    DualDst,
    /// `triple-isolate`
    Triple,
}

impl FlowMode {
    fn code(self) -> u32 {
        match self {
            FlowMode::FlowBlind => 0,
            FlowMode::SrcHost => 1,
            FlowMode::DstHost => 2,
            FlowMode::Hosts => 3,
            FlowMode::Flows => 4,
            FlowMode::DualSrc => 5,
            FlowMode::DualDst => 6,
            FlowMode::Triple => 7,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckFilter {
    Off,
    Filter,
    Aggressive,
}

impl AckFilter {
    fn code(self) -> u32 {
        match self {
            AckFilter::Off => 0,
            AckFilter::Filter => 1,
            AckFilter::Aggressive => 2,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CakeConfig {
    /// Bytes per second; 0 = unlimited (CAKE's own meaning).
    pub bandwidth: u64,
    /// `rtt` of `tc`: CAKE's interval, the worst-case round trip it is tuned for.
    pub rtt: Duration,
    /// Target sojourn time of the AQM.
    pub target: Duration,
    /// MTU of the egress; decides `mtu_time`, below which CAKE never drops a flow's last packet.
    pub mtu: u32,
    /// Per-packet overhead added to the length before shaping; `None` = raw (none).
    pub overhead: Option<i32>,
    pub mpu: u32,
    pub diffserv: Diffserv,
    pub flow_mode: FlowMode,
    /// Packet memory limit in bytes; `None` = CAKE's default.
    pub memory_limit: Option<u32>,
    pub ack_filter: AckFilter,
    pub wash: bool,
    /// Seed of the flow hash and of the dithering/BLUE random numbers.
    pub seed: u64,
}

impl Default for CakeConfig {
    fn default() -> Self {
        Self {
            bandwidth: 0,
            rtt: Duration::from_millis(100),
            target: Duration::from_millis(5),
            mtu: 1500,
            overhead: None,
            mpu: 0,
            diffserv: Diffserv::BestEffort,
            flow_mode: FlowMode::Triple,
            memory_limit: None,
            ack_filter: AckFilter::Off,
            wash: false,
            seed: 1,
        }
    }
}

/// What CAKE looks at to place a packet.
#[derive(Clone, Copy, Debug)]
pub enum PacketHeader<'a> {
    /// The start of the real IPv4 or IPv6 packet (at least the IP header and, to see ports, the
    /// TCP/UDP header; at most 128 bytes are used).
    Ip(&'a [u8]),
    /// An outer UDP datagram, from which CAKE gets the addresses, ports and DSCP.
    Udp {
        src: SocketAddr,
        dst: SocketAddr,
        dscp: u8,
    },
    /// Nothing to look at: the packet is placed by `flow_hash` alone, or in a single flow.
    None,
}

#[derive(Clone, Copy, Debug)]
pub struct PacketMeta<'a> {
    /// Length on the wire, as CAKE shapes it.
    pub len: u32,
    pub header: PacketHeader<'a>,
    /// A flow hash computed elsewhere (what `skb->hash` is for the kernel's CAKE). With one,
    /// packets are isolated by this value instead of by the header's ports; hosts still come
    /// from the header. This is how WireGuard keeps inner flows apart in the outer packets.
    pub flow_hash: Option<u32>,
    pub mark: u32,
}

#[derive(Debug)]
pub enum Dequeued<T> {
    /// CAKE lets this packet go; `sojourn` is how long it waited in the queue.
    Packet { item: T, sojourn: Duration },
    /// Nothing may leave before this time (the shaper's next slot).
    NotBefore(Instant),
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CakeError {
    /// `cake_init`/`cake_change` refused with this (negative) errno.
    Kernel(i32),
    OutOfMemory,
}

impl std::fmt::Display for CakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CakeError::Kernel(errno) => write!(f, "cake refused the configuration (errno {errno})"),
            CakeError::OutOfMemory => write!(f, "out of memory"),
        }
    }
}

impl std::error::Error for CakeError {}

/// One tin, in the order `tc -s qdisc show` prints them. Names and meaning are those of the
/// `TCA_CAKE_TIN_STATS_*` attributes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TinStats {
    pub threshold_rate: u64,
    /// Bytes CAKE accepted into this tin.
    pub sent_bytes: u64,
    pub sent_packets: u32,
    pub backlog_bytes: u32,
    pub target_us: u32,
    pub interval_us: u32,
    pub dropped_packets: u32,
    pub ecn_marked: u32,
    pub ack_drops: u32,
    pub peak_delay_us: u32,
    pub avg_delay_us: u32,
    pub base_delay_us: u32,
    pub way_hits: u32,
    pub way_misses: u32,
    pub way_collisions: u32,
    /// Sparse and decaying flows, as `tc` reports them together.
    pub sparse_flows: u32,
    pub bulk_flows: u32,
    pub unresponsive_flows: u32,
    pub max_skblen: u32,
    pub flow_quantum: u32,
    /// Packets dropped because the memory limit was reached.
    pub drop_overlimit: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CakeStats {
    pub capacity_estimate: u64,
    pub memory_limit: u32,
    /// Peak, as `tc` reports it.
    pub memory_used: u32,
    /// Bytes accounted right now.
    pub memory_now: u32,
    pub avg_netoff: u32,
    pub min_netlen: u32,
    pub max_netlen: u32,
    pub min_adjlen: u32,
    pub max_adjlen: u32,
    pub active_queues: u32,
    pub qlen: u32,
    pub backlog: u32,
    pub overlimits: u32,
    pub drops: u32,
    /// Handed out by `dequeue`.
    pub dequeued_bytes: u64,
    pub dequeued_packets: u64,
    pub tins: Vec<TinStats>,
}

/// One CAKE qdisc holding items of type `T`.
pub struct Cake<T> {
    glue: NonNull<ffi::cake_glue>,
    epoch: Instant,
    /// The items inside the queue, by cookie (the index).
    slab: Vec<Option<T>>,
    free: Vec<u32>,
    /// Cookies CAKE reported as gone but the caller has not collected yet.
    dropped: Vec<T>,
    scratch: Vec<u64>,
}

// SAFETY: the C state is reached only through `&mut self` and holds no thread affinity (the
// shim's per-call context is thread-local and set up inside every call).
unsafe impl<T: Send> Send for Cake<T> {}

fn push_attr(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    out.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(value);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

fn micros(d: Duration) -> u32 {
    d.as_micros().clamp(1, u32::MAX as u128) as u32
}

fn encode_config(cfg: &CakeConfig) -> Vec<u8> {
    let mut out = Vec::with_capacity(160);
    push_attr(&mut out, TCA_CAKE_BASE_RATE64, &cfg.bandwidth.to_ne_bytes());
    push_attr(&mut out, TCA_CAKE_DIFFSERV_MODE, &cfg.diffserv.code().to_ne_bytes());
    push_attr(&mut out, TCA_CAKE_FLOW_MODE, &cfg.flow_mode.code().to_ne_bytes());
    push_attr(&mut out, TCA_CAKE_RTT, &micros(cfg.rtt).to_ne_bytes());
    push_attr(&mut out, TCA_CAKE_TARGET, &micros(cfg.target).to_ne_bytes());
    push_attr(&mut out, TCA_CAKE_MPU, &cfg.mpu.to_ne_bytes());
    match cfg.overhead {
        Some(overhead) => push_attr(&mut out, TCA_CAKE_OVERHEAD, &overhead.to_ne_bytes()),
        None => push_attr(&mut out, TCA_CAKE_RAW, &1u32.to_ne_bytes()),
    }
    // 0 is CAKE's "use the default".
    push_attr(
        &mut out,
        TCA_CAKE_MEMORY,
        &cfg.memory_limit.unwrap_or(0).to_ne_bytes(),
    );
    push_attr(&mut out, TCA_CAKE_ACK_FILTER, &cfg.ack_filter.code().to_ne_bytes());
    push_attr(&mut out, TCA_CAKE_WASH, &u32::from(cfg.wash).to_ne_bytes());
    out
}

/// The header snapshot CAKE parses, and its EtherType.
fn snapshot(header: &PacketHeader<'_>, buf: &mut [u8; 128]) -> (usize, u16) {
    match *header {
        PacketHeader::Ip(bytes) => {
            let n = bytes.len().min(buf.len());
            buf[..n].copy_from_slice(&bytes[..n]);
            let protocol = match bytes.first().map(|b| b >> 4) {
                Some(6) => ETH_P_IPV6,
                _ => ETH_P_IP,
            };
            (n, protocol)
        }
        PacketHeader::Udp { src, dst, dscp } => {
            let tos = dscp << 2;
            match (src.ip(), dst.ip()) {
                (IpAddr::V4(s), IpAddr::V4(d)) => {
                    buf[0] = 0x45;
                    buf[1] = tos;
                    buf[9] = 17;
                    buf[12..16].copy_from_slice(&s.octets());
                    buf[16..20].copy_from_slice(&d.octets());
                    buf[20..22].copy_from_slice(&src.port().to_be_bytes());
                    buf[22..24].copy_from_slice(&dst.port().to_be_bytes());
                    (28, ETH_P_IP)
                }
                (s, d) => {
                    let v6 = |ip: IpAddr| match ip {
                        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                        IpAddr::V6(v6) => v6,
                    };
                    buf[0] = 0x60 | (tos >> 4);
                    buf[1] = tos << 4;
                    buf[6] = 17;
                    buf[8..24].copy_from_slice(&v6(s).octets());
                    buf[24..40].copy_from_slice(&v6(d).octets());
                    buf[40..42].copy_from_slice(&src.port().to_be_bytes());
                    buf[42..44].copy_from_slice(&dst.port().to_be_bytes());
                    (48, ETH_P_IPV6)
                }
            }
        }
        PacketHeader::None => (0, ETH_P_IP),
    }
}

impl<T> Cake<T> {
    pub fn new(cfg: &CakeConfig, now: Instant) -> Result<Self, CakeError> {
        let attrs = encode_config(cfg);
        let mut err = 0;
        // SAFETY: `attrs` outlives the call; `err` is a valid out pointer.
        let glue = unsafe {
            ffi::cake_glue_new(
                cfg.seed,
                cfg.mtu,
                attrs.as_ptr(),
                attrs.len() as u32,
                CLOCK_OFFSET_NS,
                &mut err,
            )
        };
        let Some(glue) = NonNull::new(glue) else {
            return Err(if err == -12 {
                CakeError::OutOfMemory
            } else {
                CakeError::Kernel(err)
            });
        };
        Ok(Self {
            glue,
            epoch: now,
            slab: Vec::new(),
            free: Vec::new(),
            dropped: Vec::new(),
            scratch: Vec::new(),
        })
    }

    fn ns(&self, now: Instant) -> u64 {
        CLOCK_OFFSET_NS + now.saturating_duration_since(self.epoch).as_nanos() as u64
    }

    fn instant(&self, ns: u64) -> Instant {
        self.epoch + Duration::from_nanos(ns.saturating_sub(CLOCK_OFFSET_NS))
    }

    /// Sets the rate and nothing else (`tc qdisc change ... bandwidth`). 0 = unlimited.
    pub fn set_bandwidth(&mut self, bytes_per_sec: u64, now: Instant) -> Result<(), CakeError> {
        let mut attrs = Vec::with_capacity(12);
        push_attr(&mut attrs, TCA_CAKE_BASE_RATE64, &bytes_per_sec.to_ne_bytes());
        self.change(0, &attrs, now)
    }

    /// Applies a whole configuration to the running queue.
    pub fn reconfigure(&mut self, cfg: &CakeConfig, now: Instant) -> Result<(), CakeError> {
        self.change(cfg.mtu, &encode_config(cfg), now)
    }

    fn change(&mut self, mtu: u32, attrs: &[u8], now: Instant) -> Result<(), CakeError> {
        let ns = self.ns(now);
        // SAFETY: `glue` is live and exclusively ours; `attrs` outlives the call.
        let rc = unsafe {
            ffi::cake_glue_change(self.glue.as_ptr(), mtu, attrs.as_ptr(), attrs.len() as u32, ns)
        };
        match rc {
            0 => Ok(()),
            -12 => Err(CakeError::OutOfMemory),
            other => Err(CakeError::Kernel(other)),
        }
    }

    fn collect_dropped(&mut self) {
        loop {
            self.scratch.resize(64, 0);
            // SAFETY: `scratch` has room for 64 cookies.
            let n = unsafe {
                ffi::cake_glue_take_dropped(self.glue.as_ptr(), self.scratch.as_mut_ptr(), 64)
            } as usize;
            for &cookie in &self.scratch[..n] {
                if let Some(item) = self.slab.get_mut(cookie as usize).and_then(Option::take) {
                    self.free.push(cookie as u32);
                    self.dropped.push(item);
                }
            }
            if n < 64 {
                break;
            }
        }
    }

    /// Queues `item`. Returns every item CAKE has dropped and the caller has not collected yet:
    /// the new packet itself when it was refused, others when the memory limit made CAKE drop
    /// from the longest queue, and anything dropped by earlier `dequeue` calls.
    pub fn enqueue(&mut self, meta: PacketMeta<'_>, item: T, now: Instant) -> Vec<T> {
        let cookie = match self.free.pop() {
            Some(slot) => {
                self.slab[slot as usize] = Some(item);
                slot
            }
            None => {
                self.slab.push(Some(item));
                (self.slab.len() - 1) as u32
            }
        };
        let mut hdr = [0u8; 128];
        let (hdr_len, protocol) = snapshot(&meta.header, &mut hdr);
        let ns = self.ns(now);
        // SAFETY: `glue` is live and exclusively ours; `hdr` outlives the call.
        unsafe {
            ffi::cake_glue_enqueue(
                self.glue.as_ptr(),
                u64::from(cookie),
                meta.len,
                hdr.as_ptr(),
                hdr_len as u32,
                protocol,
                meta.flow_hash.unwrap_or(0),
                meta.flow_hash.is_some(),
                meta.mark,
                ns,
            );
        }
        self.collect_dropped();
        std::mem::take(&mut self.dropped)
    }

    pub fn dequeue(&mut self, now: Instant) -> Dequeued<T> {
        let ns = self.ns(now);
        let (mut cookie, mut enqueued_ns) = (0u64, 0u64);
        // SAFETY: `glue` is live and exclusively ours; both out pointers are valid.
        let got = unsafe {
            ffi::cake_glue_dequeue(self.glue.as_ptr(), ns, &mut cookie, &mut enqueued_ns)
        };
        self.collect_dropped();
        if got {
            let item = self.slab[cookie as usize]
                .take()
                .expect("cake returned a packet that is not in the queue");
            self.free.push(cookie as u32);
            return Dequeued::Packet {
                item,
                sojourn: Duration::from_nanos(ns.saturating_sub(enqueued_ns)),
            };
        }
        match self.next_wake() {
            Some(at) => Dequeued::NotBefore(at),
            None => Dequeued::Empty,
        }
    }

    /// Items CAKE dropped while dequeuing (its AQM), and any not yet collected from `enqueue`.
    pub fn take_dropped(&mut self) -> Vec<T> {
        self.collect_dropped();
        std::mem::take(&mut self.dropped)
    }

    /// When the shaper next lets a packet go, if it is holding any back.
    pub fn next_wake(&self) -> Option<Instant> {
        // SAFETY: `glue` is live.
        let ns = unsafe { ffi::cake_glue_wake_ns(self.glue.as_ptr()) };
        (ns != 0).then(|| self.instant(ns))
    }

    pub fn len(&self) -> usize {
        // SAFETY: `glue` is live.
        unsafe { ffi::cake_glue_qlen(self.glue.as_ptr()) as usize }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn backlog_bytes(&self) -> u64 {
        // SAFETY: `glue` is live.
        u64::from(unsafe { ffi::cake_glue_backlog(self.glue.as_ptr()) })
    }

    /// The configuration CAKE currently runs with, as `(TCA_CAKE_* type, value)` attributes
    /// (what `cake_dump()` emits for `tc qdisc show`).
    pub fn config_attrs(&mut self) -> Vec<(u16, Vec<u8>)> {
        let mut buf = vec![0u8; 512];
        // SAFETY: `glue` is live and exclusively ours; `buf` has the stated capacity.
        let n = unsafe {
            ffi::cake_glue_dump_config(self.glue.as_ptr(), buf.as_mut_ptr(), buf.len() as u32)
        };
        let mut out = Vec::new();
        if n < 4 {
            return out;
        }
        // One TCA_OPTIONS nest; its payload is the attributes.
        let mut rest = &buf[4..n as usize];
        while rest.len() >= 4 {
            let len = u16::from_ne_bytes([rest[0], rest[1]]) as usize;
            let kind = u16::from_ne_bytes([rest[2], rest[3]]);
            if len < 4 || len > rest.len() {
                break;
            }
            out.push((kind, rest[4..len].to_vec()));
            rest = &rest[(len + 3 & !3).min(rest.len())..];
        }
        out
    }

    pub fn stats(&self) -> CakeStats {
        let mut raw = ffi::cake_glue_stats::default();
        // SAFETY: `glue` is live; `raw` is a valid out struct.
        unsafe { ffi::cake_glue_stats(self.glue.as_ptr(), &mut raw) };
        let tins = raw.tin[..(raw.tin_cnt as usize).min(ffi::MAX_TINS)]
            .iter()
            .map(|t| TinStats {
                threshold_rate: t.threshold_rate,
                sent_bytes: t.sent_bytes,
                sent_packets: t.sent_packets,
                backlog_bytes: t.backlog_bytes,
                target_us: t.target_us,
                interval_us: t.interval_us,
                dropped_packets: t.dropped_packets,
                ecn_marked: t.ecn_marked,
                ack_drops: t.ack_drops,
                peak_delay_us: t.peak_delay_us,
                avg_delay_us: t.avg_delay_us,
                base_delay_us: t.base_delay_us,
                way_hits: t.way_hits,
                way_misses: t.way_misses,
                way_collisions: t.way_collisions,
                sparse_flows: t.sparse_flows,
                bulk_flows: t.bulk_flows,
                unresponsive_flows: t.unresponsive_flows,
                max_skblen: t.max_skblen,
                flow_quantum: t.flow_quantum,
                drop_overlimit: t.drop_overlimit,
            })
            .collect();
        CakeStats {
            capacity_estimate: raw.capacity_estimate,
            memory_limit: raw.memory_limit,
            memory_used: raw.memory_used,
            memory_now: raw.memory_now,
            avg_netoff: raw.avg_netoff,
            min_netlen: raw.min_netlen,
            max_netlen: raw.max_netlen,
            min_adjlen: raw.min_adjlen,
            max_adjlen: raw.max_adjlen,
            active_queues: raw.active_queues,
            qlen: raw.qlen,
            backlog: raw.backlog,
            overlimits: raw.overlimits,
            drops: raw.drops,
            dequeued_bytes: raw.dequeued_bytes,
            dequeued_packets: raw.dequeued_packets,
            tins,
        }
    }
}

impl<T> Drop for Cake<T> {
    fn drop(&mut self) {
        // SAFETY: `glue` is live and never used again; its leftover packets are reported to
        // the glue's own list, which is freed with it, and the items drop with `slab`.
        unsafe { ffi::cake_glue_free(self.glue.as_ptr()) };
    }
}

impl<T> std::fmt::Debug for Cake<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cake")
            .field("len", &self.len())
            .field("backlog_bytes", &self.backlog_bytes())
            .finish()
    }
}

/// The COBALT (CoDel + BLUE) state of one queue that is not CAKE's own, built from CAKE's own
/// functions with the parameters a CAKE tin of the same rate would have. Time is whatever
/// [`Instant`]s the caller passes in.
pub struct Cobalt {
    state: NonNull<ffi::cake_glue_cobalt>,
    epoch: Instant,
}

// SAFETY: plain data behind `&mut self`, no thread affinity.
unsafe impl Send for Cobalt {}

impl Cobalt {
    /// `rate` in bytes per second (0 = unlimited), `mtu` the egress MTU, `target` and `rtt` as
    /// in [`CakeConfig`]. `epoch` is not later than any [`Instant`] given to the other methods
    /// (an earlier one is read as `epoch`).
    pub fn new(rate: u64, mtu: u32, target: Duration, rtt: Duration, now: Instant) -> Result<Self, CakeError> {
        // SAFETY: plain value arguments.
        let state = unsafe {
            ffi::cake_glue_cobalt_new(rate, mtu, target.as_nanos() as u64, rtt.as_nanos() as u64)
        };
        NonNull::new(state)
            .map(|state| Self { state, epoch: now })
            .ok_or(CakeError::OutOfMemory)
    }

    fn ns(&self, t: Instant) -> u64 {
        CLOCK_OFFSET_NS + t.saturating_duration_since(self.epoch).as_nanos() as u64
    }

    /// New parameters for a new rate, keeping the CoDel/BLUE state, as CAKE keeps every flow's
    /// state when a tin's rate changes (`cake_set_rate`).
    pub fn set_rate(&mut self, rate: u64, mtu: u32, target: Duration, rtt: Duration) -> Result<(), CakeError> {
        // SAFETY: `state` is live and exclusively ours.
        let ok = unsafe {
            ffi::cake_glue_cobalt_set_rate(
                self.state.as_ptr(),
                rate,
                mtu,
                target.as_nanos() as u64,
                rtt.as_nanos() as u64,
            )
        };
        if ok { Ok(()) } else { Err(CakeError::OutOfMemory) }
    }

    /// Whether the packet that waited since `enqueued` and leaves the queue at `now` is to be
    /// dropped. `bulk_flows` is CAKE's count for ingress mode; 0 for a plain queue.
    pub fn should_drop(&mut self, now: Instant, enqueued: Instant, bulk_flows: u32) -> bool {
        let (now, enqueued) = (self.ns(now), self.ns(enqueued));
        // SAFETY: `state` is live and exclusively ours.
        unsafe { ffi::cake_glue_cobalt_should_drop(self.state.as_ptr(), now, enqueued, bulk_flows) }
    }

    /// The queue ran empty: BLUE decays and CoDel's count winds down.
    pub fn queue_empty(&mut self, now: Instant) {
        let now = self.ns(now);
        // SAFETY: as above.
        unsafe { ffi::cake_glue_cobalt_queue_empty(self.state.as_ptr(), now) };
    }

    /// A packet of this queue was dropped because the memory was full: BLUE's drop
    /// probability goes up (`cake_drop`).
    pub fn queue_full(&mut self, now: Instant) {
        let now = self.ns(now);
        // SAFETY: as above.
        unsafe { ffi::cake_glue_cobalt_queue_full(self.state.as_ptr(), now) };
    }
}

impl Drop for Cobalt {
    fn drop(&mut self) {
        // SAFETY: `state` is live and never used again.
        unsafe { ffi::cake_glue_cobalt_free(self.state.as_ptr()) };
    }
}

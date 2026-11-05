//! Public ICMP-timestamp reflectors for Autorate, one set per network card
//! (PLAN-20261027-reflectors.md).
//!
//! The delay Autorate reacts to must be the card's own queue. A single MP peer
//! is one far end, so its jitter or its own queue looked like bufferbloat on
//! the card (incident 2026-10-26 08:25). cake-autorate measures against
//! several public reflectors instead (`defaults.sh`: `no_pingers=6`,
//! `reflector_ping_interval_s=0.3`) and so does sqm-autorate (third smallest of
//! the reflectors' delays, `ratecontroller_ewma.lua:241-245`). Round trips would
//! carry the download direction's jitter into the upload estimate, so the probe
//! is the RFC 792 Timestamp message (cake-autorate's `tsping`/`fping-ts`
//! method): `receive - originate` is the upstream one-way delay.
//!
//! [`ReflectorEngine`] is the whole decision logic with no I/O and an explicit
//! clock; [`ReflectorProber`] runs it on a thread with a raw socket bound to
//! the card; [`prober_for`] shares one prober between every user of the same
//! card and reflector set.

use std::{
    collections::{HashMap, VecDeque},
    mem::MaybeUninit,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::common::egress_inventory::EgressStableId;

/// The default reflectors: public anycast resolvers that answer ICMP
/// timestamps on both Ethernet and WLAN (measured on .99, 2026-10-27). The
/// first `NO_PINGERS` are active; any more are spares.
pub const DEFAULT_REFLECTORS: [Ipv4Addr; 6] = [
    Ipv4Addr::new(223, 5, 5, 5),
    Ipv4Addr::new(223, 6, 6, 6),
    Ipv4Addr::new(119, 28, 28, 28),
    Ipv4Addr::new(1, 2, 4, 8),
    Ipv4Addr::new(101, 226, 4, 6),
    Ipv4Addr::new(182, 254, 116, 116),
];

/// `no_pingers`: reflectors probed at once.
pub const NO_PINGERS: usize = 6;
/// `reflector_ping_interval_s`: each reflector gets one request this often;
/// the reflectors are staggered by `PING_INTERVAL / NO_PINGERS`
/// (`sleep_until_next_pinger_time_slot`).
pub const PING_INTERVAL: Duration = Duration::from_millis(300);
/// `alpha_baseline_increase` / `alpha_baseline_decrease`, in millionths.
const ALPHA_BASELINE_INCREASE: i64 = 1_000;
const ALPHA_BASELINE_DECREASE: i64 = 900_000;
/// `alpha_delta_ewma`, in millionths.
const ALPHA_DELTA_EWMA: i64 = 95_000;
/// A delta pair this large (50 minutes, in µs) is a clock rollover or a new
/// path, not queueing: the baselines restart (`cake-autorate.sh:1608-1626`).
const BASELINE_RESET_US: i64 = 3_000_000_000;
/// `reflector_health_check_interval_s`.
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(1);
/// `reflector_response_deadline_s`.
const RESPONSE_DEADLINE: Duration = Duration::from_secs(1);
/// `reflector_misbehaving_detection_window` / `_thr`.
const MISBEHAVING_WINDOW: usize = 60;
const MISBEHAVING_THR: u32 = 3;
/// `reflector_comparison_interval_mins`.
const COMPARISON_INTERVAL: Duration = Duration::from_secs(60);
/// `reflector_sum_owd_baselines_delta_thr_ms`, against the round-trip
/// baseline here (see `compare_reflectors`).
const BASELINE_DELTA_THR_US: i64 = 20_000;
/// `reflector_owd_delta_ewma_delta_thr_ms`.
const EWMA_DELTA_THR_US: i64 = 10_000;
/// `sustained_idle_sleep_thr_s`.
const SUSTAINED_IDLE: Duration = Duration::from_secs(60);
/// `high_load_thr`, percent: the delay EWMAs only move below it.
const HIGH_LOAD_PERCENT: u64 = 75;
/// Users report their load once per Autorate tick (0.5 s); a high-load report
/// stands for a few ticks of every user.
const HIGH_LOAD_HOLD: Duration = Duration::from_secs(2);
/// How long a reply's delta stays available to `tick_deltas`.
const SAMPLE_KEEP: Duration = Duration::from_secs(10);
const SAMPLE_CAP: usize = 64;
const INFLIGHT_KEEP: Duration = Duration::from_secs(10);
/// How long a failed raw-socket creation is not retried.
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(60);
/// The receive timeout, which is also the sending resolution.
const RECV_TIMEOUT: Duration = Duration::from_millis(20);

const DAY_MS: i64 = 86_400_000;
const ICMP_TIMESTAMP: u8 = 13;
const ICMP_TIMESTAMP_REPLY: u8 = 14;
pub const ICMP_TIMESTAMP_LEN: usize = 20;

// ---------------------------------------------------------------------------
// Packets (RFC 792 Timestamp / Timestamp Reply)
// ---------------------------------------------------------------------------

/// RFC 1071 Internet checksum.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for pair in &mut chunks {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The fields of a Timestamp or Timestamp Reply message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimestampMessage {
    pub identifier: u16,
    pub sequence: u16,
    pub originate: u32,
    pub receive: u32,
    pub transmit: u32,
}

/// A Timestamp request (type 13) with `originate` set.
pub fn encode_request(identifier: u16, sequence: u16, originate: u32) -> [u8; ICMP_TIMESTAMP_LEN] {
    encode(ICMP_TIMESTAMP, &TimestampMessage {
        identifier,
        sequence,
        originate,
        receive: 0,
        transmit: 0,
    })
}

fn encode(kind: u8, m: &TimestampMessage) -> [u8; ICMP_TIMESTAMP_LEN] {
    let mut p = [0u8; ICMP_TIMESTAMP_LEN];
    p[0] = kind;
    p[4..6].copy_from_slice(&m.identifier.to_be_bytes());
    p[6..8].copy_from_slice(&m.sequence.to_be_bytes());
    p[8..12].copy_from_slice(&m.originate.to_be_bytes());
    p[12..16].copy_from_slice(&m.receive.to_be_bytes());
    p[16..20].copy_from_slice(&m.transmit.to_be_bytes());
    let checksum = internet_checksum(&p);
    p[2..4].copy_from_slice(&checksum.to_be_bytes());
    p
}

/// A Timestamp Reply (type 14), as a reflector would send it.
pub fn encode_reply(m: &TimestampMessage) -> [u8; ICMP_TIMESTAMP_LEN] {
    encode(ICMP_TIMESTAMP_REPLY, m)
}

/// Parse a received datagram of a raw ICMP socket (it carries the IPv4
/// header) into its source address and Timestamp Reply. `None` for anything
/// else, a bad checksum, or a reply with a non-standard time (the high-order
/// bit of a timestamp set: RFC 792, "the time ... is not in milliseconds since
/// midnight UT"), which cannot be used.
pub fn parse_reply(datagram: &[u8]) -> Option<(Ipv4Addr, TimestampMessage)> {
    let first = *datagram.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let header_len = (first & 0x0f) as usize * 4;
    if header_len < 20 || datagram.len() < header_len + ICMP_TIMESTAMP_LEN || datagram[9] != 1 {
        return None;
    }
    let source = Ipv4Addr::new(datagram[12], datagram[13], datagram[14], datagram[15]);
    let icmp = &datagram[header_len..];
    if icmp[0] != ICMP_TIMESTAMP_REPLY || icmp[1] != 0 {
        return None;
    }
    if internet_checksum(&icmp[..ICMP_TIMESTAMP_LEN]) != 0 {
        return None;
    }
    let word = |at: usize| u32::from_be_bytes([icmp[at], icmp[at + 1], icmp[at + 2], icmp[at + 3]]);
    let message = TimestampMessage {
        identifier: u16::from_be_bytes([icmp[4], icmp[5]]),
        sequence: u16::from_be_bytes([icmp[6], icmp[7]]),
        originate: word(8),
        receive: word(12),
        transmit: word(16),
    };
    if (message.originate | message.receive | message.transmit) & 0x8000_0000 != 0 {
        return None;
    }
    Some((source, message))
}

/// Milliseconds since midnight UT, the unit of the ICMP timestamps.
pub fn ut_ms_of_day() -> u32 {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64);
    ms.rem_euclid(DAY_MS) as u32
}

/// The difference of two times of day, mapped into (-12 h, 12 h] so a
/// midnight between them does not read as a day-long delay.
pub fn wrap_ms(difference: i64) -> i64 {
    let m = difference.rem_euclid(DAY_MS);
    if m > DAY_MS / 2 { m - DAY_MS } else { m }
}

// ---------------------------------------------------------------------------
// Per-reflector statistics (cake-autorate.sh tsping branch)
// ---------------------------------------------------------------------------

fn baseline_step(baseline: i64, owd: i64) -> i64 {
    let alpha = if owd >= baseline {
        ALPHA_BASELINE_INCREASE
    } else {
        ALPHA_BASELINE_DECREASE
    };
    (alpha * owd + (1_000_000 - alpha) * baseline) / 1_000_000
}

fn ewma_step(ewma: i64, delta: i64) -> i64 {
    (ALPHA_DELTA_EWMA * delta + (1_000_000 - ALPHA_DELTA_EWMA) * ewma) / 1_000_000
}

/// One reflector's baselines and delay-delta EWMAs, in µs. Kept per address,
/// so a reflector rotated out and back in resumes them
/// (`retain_reflector_stats=1`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReflectorStats {
    seeded: bool,
    pub ul_baseline_us: i64,
    pub dl_baseline_us: i64,
    /// Round trip on this machine's monotonic clock. cake-autorate compares
    /// the sum of the two one-way baselines, which is the round trip because
    /// each is offset by the clock difference with that reflector in opposite
    /// signs; measuring the round trip directly has the same result.
    pub rtt_baseline_us: i64,
    pub ul_delta_ewma_us: i64,
    pub dl_delta_ewma_us: i64,
}

impl ReflectorStats {
    /// Fold one reply in; returns the upstream delta (µs, may be negative).
    /// `ul_owd_us = receive - originate`, `dl_owd_us = finished - transmit`.
    pub fn update(&mut self, ul_owd_us: i64, dl_owd_us: i64, rtt_us: i64, low_load: bool) -> i64 {
        let (ul_delta, dl_delta);
        if !self.seeded {
            self.seeded = true;
            self.ul_baseline_us = ul_owd_us;
            self.dl_baseline_us = dl_owd_us;
            self.rtt_baseline_us = rtt_us;
            ul_delta = 0;
            dl_delta = 0;
        } else {
            let ul_first = ul_owd_us - self.ul_baseline_us;
            let dl_first = dl_owd_us - self.dl_baseline_us;
            self.rtt_baseline_us = baseline_step(self.rtt_baseline_us, rtt_us);
            if ul_first.abs() + dl_first.abs() < BASELINE_RESET_US {
                self.ul_baseline_us = baseline_step(self.ul_baseline_us, ul_owd_us);
                self.dl_baseline_us = baseline_step(self.dl_baseline_us, dl_owd_us);
                ul_delta = ul_owd_us - self.ul_baseline_us;
                dl_delta = dl_owd_us - self.dl_baseline_us;
            } else {
                self.ul_baseline_us = ul_owd_us;
                self.dl_baseline_us = dl_owd_us;
                ul_delta = 0;
                dl_delta = 0;
            }
        }
        if low_load {
            self.ul_delta_ewma_us = ewma_step(self.ul_delta_ewma_us, ul_delta);
            self.dl_delta_ewma_us = ewma_step(self.dl_delta_ewma_us, dl_delta);
        }
        ul_delta
    }
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

struct Slot {
    addr: Ipv4Addr,
    next_due: Instant,
    last_reply: Instant,
    /// The last `MISBEHAVING_WINDOW` health checks, true = no reply in time.
    offences: Vec<bool>,
    offence_count: u32,
}

impl Slot {
    fn new(addr: Ipv4Addr, next_due: Instant, now: Instant) -> Self {
        Self {
            addr,
            next_due,
            last_reply: now,
            offences: vec![false; MISBEHAVING_WINDOW],
            offence_count: 0,
        }
    }

    fn misbehaving(&self) -> bool {
        self.offence_count >= MISBEHAVING_THR
    }
}

/// The reflector set's decisions: what to send when, what each reply means,
/// which reflector to rotate out, when to sleep. No I/O, no clock of its own.
pub struct ReflectorEngine {
    identifier: u16,
    slots: Vec<Slot>,
    spares: VecDeque<Ipv4Addr>,
    stats: HashMap<Ipv4Addr, ReflectorStats>,
    /// Upstream deltas (µs, negatives as 0) of recent replies by address.
    samples: HashMap<Ipv4Addr, VecDeque<(Instant, u64)>>,
    inflight: HashMap<u16, (Ipv4Addr, Instant)>,
    next_sequence: u16,
    last_health_check: Instant,
    last_comparison: Instant,
    offence_index: usize,
    last_active: Instant,
    sleeping: bool,
    high_load_until: Option<Instant>,
}

impl ReflectorEngine {
    /// `reflectors[..NO_PINGERS]` are active, the rest spares.
    pub fn new(reflectors: &[Ipv4Addr], identifier: u16, now: Instant) -> Self {
        let active = reflectors.len().min(NO_PINGERS);
        let slots = reflectors[..active]
            .iter()
            .enumerate()
            .map(|(k, addr)| Slot::new(*addr, now + Self::phase(k), now))
            .collect();
        Self {
            identifier,
            slots,
            spares: reflectors[active..].iter().copied().collect(),
            stats: HashMap::new(),
            samples: HashMap::new(),
            inflight: HashMap::new(),
            next_sequence: 0,
            last_health_check: now,
            last_comparison: now,
            offence_index: 0,
            last_active: now,
            sleeping: false,
            high_load_until: None,
        }
    }

    fn phase(k: usize) -> Duration {
        PING_INTERVAL / NO_PINGERS as u32 * k as u32
    }

    pub fn identifier(&self) -> u16 {
        self.identifier
    }

    /// The addresses probed now, in slot order.
    pub fn active_reflectors(&self) -> Vec<Ipv4Addr> {
        self.slots.iter().map(|slot| slot.addr).collect()
    }

    pub fn stats_of(&self, addr: Ipv4Addr) -> Option<ReflectorStats> {
        self.stats.get(&addr).copied()
    }

    pub fn is_sleeping(&self) -> bool {
        self.sleeping
    }

    /// A user's load for this tick. `achieved_bps >= active_thr_bps` is
    /// activity (wakes a sleeping set); `achieved_bps` at or above 75 % of
    /// `rate_bps` is high load, during which the delay EWMAs stand still.
    pub fn note_load(&mut self, now: Instant, achieved_bps: u64, rate_bps: u64, active_thr_bps: u64) {
        if achieved_bps >= active_thr_bps {
            self.last_active = now;
            if self.sleeping {
                self.sleeping = false;
                // Like cake-autorate resuming from IDLE: give the pingers time
                // to get going before judging any reflector.
                self.last_health_check = now;
                for (k, slot) in self.slots.iter_mut().enumerate() {
                    slot.last_reply = now;
                    slot.next_due = now + Self::phase(k);
                }
            }
        }
        if (achieved_bps as u128) * 100 >= (rate_bps as u128) * HIGH_LOAD_PERCENT as u128 {
            self.high_load_until = Some(now + HIGH_LOAD_HOLD);
        }
    }

    /// Go to sleep once no user has been active for `SUSTAINED_IDLE`.
    pub fn update_sleep(&mut self, now: Instant) {
        if !self.sleeping && now.saturating_duration_since(self.last_active) >= SUSTAINED_IDLE {
            self.sleeping = true;
        }
    }

    /// The requests due at `now`: `(destination, packet)`. `ut_ms` is the
    /// originate timestamp.
    pub fn poll_send(&mut self, now: Instant, ut_ms: u32) -> Vec<(Ipv4Addr, [u8; ICMP_TIMESTAMP_LEN])> {
        self.inflight
            .retain(|_, (_, sent)| now.saturating_duration_since(*sent) < INFLIGHT_KEEP);
        let mut due = Vec::new();
        if self.sleeping {
            return due;
        }
        for slot in &mut self.slots {
            if slot.next_due > now {
                continue;
            }
            while slot.next_due <= now {
                slot.next_due += PING_INTERVAL;
            }
            let sequence = self.next_sequence;
            self.next_sequence = self.next_sequence.wrapping_add(1);
            self.inflight.insert(sequence, (slot.addr, now));
            due.push((slot.addr, encode_request(self.identifier, sequence, ut_ms)));
        }
        due
    }

    /// A Timestamp Reply from `from` received at `now`, `finished_ms` being
    /// the local time of day then. Replies that are not for this engine's
    /// outstanding requests are ignored.
    pub fn on_reply(&mut self, now: Instant, from: Ipv4Addr, reply: &TimestampMessage, finished_ms: u32) {
        if reply.identifier != self.identifier {
            return;
        }
        let Some(&(addr, sent)) = self.inflight.get(&reply.sequence) else {
            return;
        };
        if addr != from {
            return;
        }
        self.inflight.remove(&reply.sequence);
        let Some(slot) = self.slots.iter_mut().find(|slot| slot.addr == from) else {
            return;
        };
        slot.last_reply = now;
        let ul_owd_us = wrap_ms(reply.receive as i64 - reply.originate as i64) * 1000;
        let dl_owd_us = wrap_ms(finished_ms as i64 - reply.transmit as i64) * 1000;
        let rtt_us = now.saturating_duration_since(sent).as_micros() as i64;
        let low_load = self.high_load_until.is_none_or(|until| now >= until);
        let ul_delta = self
            .stats
            .entry(from)
            .or_default()
            .update(ul_owd_us, dl_owd_us, rtt_us, low_load);
        let samples = self.samples.entry(from).or_default();
        while samples
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) > SAMPLE_KEEP)
            || samples.len() >= SAMPLE_CAP
        {
            samples.pop_front();
        }
        samples.push_back((now, ul_delta.max(0) as u64));
    }

    /// `cake-autorate.sh:1973-2085`: once a second, first compare the
    /// reflectors (every minute) and then count the late ones.
    pub fn health_check(&mut self, now: Instant) {
        if self.sleeping
            || now.saturating_duration_since(self.last_health_check) < HEALTH_CHECK_INTERVAL
        {
            return;
        }
        if now.saturating_duration_since(self.last_comparison) >= COMPARISON_INTERVAL {
            self.last_comparison = now;
            if self.compare_reflectors(now) {
                // The original goes round again without ending this check.
                return;
            }
        }
        let mut replaced_one = false;
        for index in 0..self.slots.len() {
            let slot = &mut self.slots[index];
            if std::mem::take(&mut slot.offences[self.offence_index]) {
                slot.offence_count -= 1;
            }
            if now.saturating_duration_since(slot.last_reply) > RESPONSE_DEADLINE {
                slot.offences[self.offence_index] = true;
                slot.offence_count += 1;
            }
            if slot.misbehaving() && !replaced_one {
                self.replace(index, now);
                replaced_one = true;
            }
        }
        self.offence_index = (self.offence_index + 1) % MISBEHAVING_WINDOW;
        self.last_health_check = now;
    }

    /// A reflector whose round-trip baseline is 20 ms above the smallest, or
    /// whose upstream or downstream delay EWMA is 10 ms above the smallest,
    /// is rotated out. Returns whether one was.
    fn compare_reflectors(&mut self, now: Instant) -> bool {
        let mut all = Vec::with_capacity(self.slots.len());
        for slot in &self.slots {
            match self.stats.get(&slot.addr) {
                Some(stats) if stats.seeded => all.push(*stats),
                _ => return false,
            }
        }
        let Some(min_rtt) = all.iter().map(|s| s.rtt_baseline_us).min() else {
            return false;
        };
        let min_ul = all.iter().map(|s| s.ul_delta_ewma_us).min().unwrap_or(0);
        let min_dl = all.iter().map(|s| s.dl_delta_ewma_us).min().unwrap_or(0);
        for (index, stats) in all.iter().enumerate() {
            if stats.rtt_baseline_us - min_rtt > BASELINE_DELTA_THR_US
                || stats.dl_delta_ewma_us - min_dl > EWMA_DELTA_THR_US
                || stats.ul_delta_ewma_us - min_ul > EWMA_DELTA_THR_US
            {
                self.replace(index, now);
                return true;
            }
        }
        false
    }

    /// `replace_pinger_reflector`: a spare takes the slot and the bad one goes
    /// to the back of the spares; with no spare the reflector stays. Either
    /// way its offences start over.
    fn replace(&mut self, index: usize, now: Instant) {
        if let Some(spare) = self.spares.pop_front() {
            let slot = &mut self.slots[index];
            let bad = std::mem::replace(&mut slot.addr, spare);
            self.spares.push_back(bad);
            slot.last_reply = now;
            tracing::debug!(?bad, new = ?spare, "replacing an Autorate reflector");
        }
        let slot = &mut self.slots[index];
        slot.offences.iter_mut().for_each(|o| *o = false);
        slot.offence_count = 0;
    }

    /// The RFC 6817 section 2.4.2 FILTER of one Autorate tick: per reflector
    /// that is not misbehaving and answered in `(since, now]`, the smallest
    /// upstream delta (µs) in that interval. Reflectors with no reply in it
    /// do not take part (sqm-autorate uses only fresh reflectors).
    pub fn tick_deltas(&self, since: Instant, now: Instant) -> Vec<u64> {
        self.slots
            .iter()
            .filter(|slot| !slot.misbehaving())
            .filter_map(|slot| {
                self.samples
                    .get(&slot.addr)?
                    .iter()
                    .filter(|(at, _)| *at > since && *at <= now)
                    .map(|(_, delta)| *delta)
                    .min()
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// The prober: engine + raw socket + thread
// ---------------------------------------------------------------------------

/// Which probe set a prober serves. Two users with equal keys share one.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProberKey {
    pub egress: EgressStableId,
    pub local: Ipv4Addr,
    pub device: String,
    pub socket_mark: Option<u32>,
    pub reflectors: Vec<Ipv4Addr>,
}

struct ProberShared {
    engine: Mutex<ReflectorEngine>,
}

/// A running probe set. The thread ends when the last `Arc` of it is gone.
pub struct ReflectorProber {
    shared: Arc<ProberShared>,
}

impl ReflectorProber {
    fn start(key: &ProberKey) -> anyhow::Result<Arc<Self>> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
        crate::tunnel::common::setup_socket2_ext(
            &socket,
            &SocketAddr::V4(SocketAddrV4::new(key.local, 0)),
            Some(key.device.clone()),
            false,
            key.socket_mark,
        )
        .map_err(|e| anyhow::anyhow!("binding the reflector socket: {e}"))?;
        // `setup_socket2_ext` makes it non-blocking; the thread paces itself
        // on the receive timeout.
        socket.set_nonblocking(false)?;
        socket.set_read_timeout(Some(RECV_TIMEOUT))?;

        let identifier = rand::random::<u16>();
        let shared = Arc::new(ProberShared {
            engine: Mutex::new(ReflectorEngine::new(&key.reflectors, identifier, Instant::now())),
        });
        let weak = Arc::downgrade(&shared);
        std::thread::Builder::new()
            .name("autorate-reflectors".to_string())
            .spawn(move || probe_loop(socket, weak))?;
        Ok(Arc::new(Self { shared }))
    }

    /// A user's load this tick; see [`ReflectorEngine::note_load`].
    pub fn note_load(&self, achieved_bps: u64, rate_bps: u64, active_thr_bps: u64) {
        self.shared
            .engine
            .lock()
            .unwrap()
            .note_load(Instant::now(), achieved_bps, rate_bps, active_thr_bps);
    }

    /// See [`ReflectorEngine::tick_deltas`].
    pub fn tick_deltas(&self, since: Instant, now: Instant) -> Vec<u64> {
        self.shared.engine.lock().unwrap().tick_deltas(since, now)
    }

    /// For tests and diagnostics.
    pub fn with_engine<T>(&self, f: impl FnOnce(&ReflectorEngine) -> T) -> T {
        f(&self.shared.engine.lock().unwrap())
    }
}

fn probe_loop(socket: Socket, shared: Weak<ProberShared>) {
    let mut buffer = [MaybeUninit::<u8>::uninit(); 256];
    loop {
        let Some(live) = shared.upgrade() else { return };
        let sends = {
            let mut engine = live.engine.lock().unwrap();
            let now = Instant::now();
            engine.update_sleep(now);
            engine.health_check(now);
            engine.poll_send(now, ut_ms_of_day())
        };
        drop(live);
        for (addr, packet) in sends {
            if let Err(error) = socket.send_to(&packet, &SockAddr::from(SocketAddrV4::new(addr, 0))) {
                tracing::debug!(?addr, ?error, "reflector request not sent");
            }
        }
        match socket.recv(&mut buffer) {
            Ok(received) => {
                let finished = ut_ms_of_day();
                let now = Instant::now();
                // SAFETY: `recv` initialised the first `received` bytes.
                let datagram: &[u8] = unsafe {
                    std::slice::from_raw_parts(buffer.as_ptr() as *const u8, received)
                };
                if let Some((from, reply)) = parse_reply(datagram)
                    && let Some(live) = shared.upgrade()
                {
                    live.engine.lock().unwrap().on_reply(now, from, &reply, finished);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => {
                tracing::debug!(?error, "reflector receive failed");
                std::thread::sleep(RECV_TIMEOUT);
            }
        }
    }
}

#[derive(Default)]
struct Registry {
    probers: HashMap<ProberKey, Weak<ReflectorProber>>,
    failed: HashMap<ProberKey, Instant>,
}

static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();

/// The prober of `key`, started if no user has one. Two users with an equal
/// key (the same card, address, SO_MARK and reflectors) get the same prober, so
/// the reflectors are probed once per card. `None` when the raw socket cannot
/// be made (no administrator/root, Android): the reason is logged once and not
/// retried for 60 s, and the caller behaves as without reflectors.
pub fn prober_for(key: &ProberKey) -> Option<Arc<ReflectorProber>> {
    let mut registry = REGISTRY.get_or_init(Default::default).lock().unwrap();
    registry.probers.retain(|_, prober| prober.strong_count() > 0);
    if let Some(prober) = registry.probers.get(key).and_then(Weak::upgrade) {
        return Some(prober);
    }
    let now = Instant::now();
    registry
        .failed
        .retain(|_, at| now.saturating_duration_since(*at) < RETRY_AFTER_FAILURE);
    if registry.failed.contains_key(key) {
        return None;
    }
    match ReflectorProber::start(key) {
        Ok(prober) => {
            registry.probers.insert(key.clone(), Arc::downgrade(&prober));
            Some(prober)
        }
        Err(error) => {
            tracing::info!(
                device = %key.device,
                local = %key.local,
                %error,
                "Autorate reflectors unavailable on this card; using the peer's delay only"
            );
            registry.failed.insert(key.clone(), now);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    fn msg(originate: u32, receive: u32, transmit: u32) -> TimestampMessage {
        TimestampMessage { identifier: 0x1234, sequence: 7, originate, receive, transmit }
    }

    fn with_ip_header(icmp: &[u8], source: Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0];
        p.extend_from_slice(&source.octets());
        p.extend_from_slice(&[10, 0, 0, 1]);
        p.extend_from_slice(icmp);
        p
    }

    /// T1: encoding, checksum (RFC 1071) and parsing; a reply with a
    /// non-standard time (high-order bit) is refused.
    #[test]
    fn t1_packet_codec_and_checksum() {
        let request = encode_request(0xbeef, 3, 1_000);
        assert_eq!(request[0], 13);
        assert_eq!(request[1], 0);
        assert_eq!(&request[4..8], &[0xbe, 0xef, 0, 3]);
        assert_eq!(&request[8..12], &1_000u32.to_be_bytes());
        assert_eq!(internet_checksum(&request), 0, "a valid message sums to zero");
        // RFC 1071 section 3 example data.
        assert_eq!(
            internet_checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            !0xddf2u16
        );
        // An odd length pads with a zero byte.
        assert_eq!(internet_checksum(&[0xff]), !0xff00u16);

        let reply = encode_reply(&msg(1_000, 1_020, 1_021));
        let datagram = with_ip_header(&reply, Ipv4Addr::new(223, 5, 5, 5));
        let (from, parsed) = parse_reply(&datagram).unwrap();
        assert_eq!(from, Ipv4Addr::new(223, 5, 5, 5));
        assert_eq!(parsed, msg(1_000, 1_020, 1_021));

        // Not a reply / corrupted / truncated.
        let echo_like = with_ip_header(&request, Ipv4Addr::new(1, 1, 1, 1));
        assert!(parse_reply(&echo_like).is_none());
        let mut corrupted = datagram.clone();
        corrupted[20 + 9] ^= 1;
        assert!(parse_reply(&corrupted).is_none());
        assert!(parse_reply(&datagram[..30]).is_none());
        // IP options (IHL 6) are skipped.
        let mut optioned = vec![0x46];
        optioned.extend_from_slice(&datagram[1..20]);
        optioned.extend_from_slice(&[0; 4]);
        optioned.extend_from_slice(&reply);
        assert_eq!(parse_reply(&optioned).unwrap().1, msg(1_000, 1_020, 1_021));

        // Non-standard time in receive or transmit.
        for bad in [msg(1_000, 0x8000_0000 | 5, 1_021), msg(1_000, 1_020, 0x8000_0000 | 9)] {
            let datagram = with_ip_header(&encode_reply(&bad), Ipv4Addr::new(1, 2, 4, 8));
            assert!(parse_reply(&datagram).is_none());
        }
    }

    /// T2: across midnight, originate 86 399 990 and receive 5 is 15 ms.
    #[test]
    fn t2_midnight_wrap() {
        assert_eq!(wrap_ms(5 - 86_399_990), 15);
        assert_eq!(wrap_ms(86_399_990 - 5), -15);
        assert_eq!(wrap_ms(0), 0);
        assert_eq!(wrap_ms(43_200_000), 43_200_000);
        assert_eq!(wrap_ms(43_200_001), -43_199_999);
        assert_eq!(wrap_ms(-43_200_000), 43_200_000);
    }

    /// cake-autorate.sh's tsping branch, transcribed from the bash arithmetic
    /// (`((...))` integer division truncates toward zero, as Rust's does).
    struct BashReference {
        dl_baseline: i64,
        ul_baseline: i64,
        dl_ewma: i64,
        ul_ewma: i64,
    }

    impl BashReference {
        fn step(&mut self, dl_owd_us: i64, ul_owd_us: i64, low_load: bool) -> (i64, i64) {
            let alpha_baseline_increase = 1_000i64;
            let alpha_baseline_decrease = 900_000i64;
            let alpha_delta_ewma = 95_000i64;
            let mut dl_delta = dl_owd_us - self.dl_baseline;
            let mut ul_delta = ul_owd_us - self.ul_baseline;
            if dl_delta.abs() + ul_delta.abs() < 3_000_000_000 {
                let dl_alpha = if dl_owd_us >= self.dl_baseline {
                    alpha_baseline_increase
                } else {
                    alpha_baseline_decrease
                };
                let ul_alpha = if ul_owd_us >= self.ul_baseline {
                    alpha_baseline_increase
                } else {
                    alpha_baseline_decrease
                };
                self.dl_baseline = (dl_alpha * dl_owd_us + (1_000_000 - dl_alpha) * self.dl_baseline) / 1_000_000;
                self.ul_baseline = (ul_alpha * ul_owd_us + (1_000_000 - ul_alpha) * self.ul_baseline) / 1_000_000;
                dl_delta = dl_owd_us - self.dl_baseline;
                ul_delta = ul_owd_us - self.ul_baseline;
            } else {
                self.dl_baseline = dl_owd_us;
                self.ul_baseline = ul_owd_us;
                dl_delta = 0;
                ul_delta = 0;
            }
            if low_load {
                self.dl_ewma = (alpha_delta_ewma * dl_delta + (1_000_000 - alpha_delta_ewma) * self.dl_ewma) / 1_000_000;
                self.ul_ewma = (alpha_delta_ewma * ul_delta + (1_000_000 - alpha_delta_ewma) * self.ul_ewma) / 1_000_000;
            }
            (ul_delta, dl_delta)
        }
    }

    /// T3: baselines, deltas and EWMAs equal the original's integer algorithm
    /// value for value, over a rising, falling and spiking sequence.
    #[test]
    fn t3_baseline_and_delta_match_cake_autorate() {
        let mut stats = ReflectorStats::default();
        // The first sample seeds both baselines (a deliberate difference from
        // the original's 100 ms initial baseline: clock offsets of seconds
        // between hosts would otherwise take hours to settle).
        let first_ul = 12_000;
        let first_dl = 40_000;
        assert_eq!(stats.update(first_ul, first_dl, 52_000, true), 0);
        let mut reference = BashReference {
            dl_baseline: first_dl,
            ul_baseline: first_ul,
            dl_ewma: 0,
            ul_ewma: 0,
        };
        let mut state = 0x2545F4914F6CDD1Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for i in 0..2_000 {
            // Whole milliseconds, as the wire carries them.
            let ul = 12_000 + (next() % 30) as i64 * 1_000 + if i % 97 == 0 { 80_000 } else { 0 };
            let dl = 40_000 + (next() % 60) as i64 * 1_000 - if i % 53 == 0 { 9_000 } else { 0 };
            let low_load = i % 7 != 0;
            let (want_ul, _want_dl) = reference.step(dl, ul, low_load);
            let got_ul = stats.update(ul, dl, 52_000, low_load);
            assert_eq!(got_ul, want_ul, "ul delta at {i}");
            assert_eq!(stats.ul_baseline_us, reference.ul_baseline, "ul baseline at {i}");
            assert_eq!(stats.dl_baseline_us, reference.dl_baseline, "dl baseline at {i}");
            assert_eq!(stats.ul_delta_ewma_us, reference.ul_ewma, "ul ewma at {i}");
            assert_eq!(stats.dl_delta_ewma_us, reference.dl_ewma, "dl ewma at {i}");
        }
    }

    /// T4: a delta pair of 50 minutes or more resets the baselines to the
    /// sample (clock rollover or a new path) and reports no delta.
    #[test]
    fn t4_baseline_resets_past_fifty_minutes() {
        let mut stats = ReflectorStats::default();
        stats.update(10_000, 20_000, 30_000, true);
        for _ in 0..20 {
            stats.update(10_000, 20_000, 30_000, true);
        }
        // Just under: still folded in with the slow rise.
        let under = stats.update(10_000 + 2_999_000_000, 20_000, 30_000, true);
        assert!(under > 2_900_000_000, "{under}");
        assert!(stats.ul_baseline_us < 10_000 + 3_000_000);
        // At the limit: reset.
        let mut stats = ReflectorStats::default();
        stats.update(10_000, 20_000, 30_000, true);
        let delta = stats.update(10_000 + 3_000_000_000, 20_000, 30_000, true);
        assert_eq!(delta, 0);
        assert_eq!(stats.ul_baseline_us, 10_000 + 3_000_000_000);
        assert_eq!(stats.dl_baseline_us, 20_000);
        // The sum of the two deltas counts, in either direction.
        let mut stats = ReflectorStats::default();
        stats.update(10_000, 20_000, 30_000, true);
        let delta = stats.update(10_000 - 1_600_000_000, 20_000 + 1_500_000_000, 30_000, true);
        assert_eq!(delta, 0);
        assert_eq!(stats.dl_baseline_us, 20_000 + 1_500_000_000);
    }

    fn addrs(n: u8) -> Vec<Ipv4Addr> {
        (1..=n).map(|i| Ipv4Addr::new(203, 0, 113, i)).collect()
    }

    /// Answer every due request after a fixed upstream/downstream delay.
    fn run(
        engine: &mut ReflectorEngine,
        start: Instant,
        seconds: f64,
        answer: &mut dyn FnMut(Ipv4Addr) -> Option<(u32, u32, u32)>,
    ) -> Instant {
        let mut at = start;
        let end = start + Duration::from_secs_f64(seconds);
        let mut ut = 40_000_000u32;
        while at < end {
            engine.update_sleep(at);
            engine.health_check(at);
            for (addr, packet) in engine.poll_send(at, ut) {
                let (_, request) = parse_reply(&with_ip_header(
                    &{
                        let mut p = packet;
                        p[0] = 14;
                        p[2] = 0;
                        p[3] = 0;
                        let c = internet_checksum(&p);
                        p[2..4].copy_from_slice(&c.to_be_bytes());
                        p
                    },
                    addr,
                ))
                .unwrap();
                if let Some((up_ms, down_ms, _)) = answer(addr) {
                    let reply = TimestampMessage {
                        receive: request.originate + up_ms,
                        transmit: request.originate + up_ms,
                        ..request
                    };
                    engine.on_reply(
                        at + Duration::from_millis((up_ms + down_ms) as u64),
                        addr,
                        &reply,
                        reply.transmit + down_ms,
                    );
                }
            }
            at += Duration::from_millis(10);
            ut += 10;
        }
        at
    }

    /// Sending is staggered 50 ms apart, each reflector every 0.3 s; asleep
    /// sends nothing.
    #[test]
    fn requests_are_staggered_and_paced() {
        let start = t0();
        let mut engine = ReflectorEngine::new(&addrs(6), 1, start);
        let mut times: HashMap<Ipv4Addr, Vec<Duration>> = HashMap::new();
        let mut at = start;
        while at < start + Duration::from_millis(1_000) {
            for (addr, _) in engine.poll_send(at, 0) {
                times.entry(addr).or_default().push(at - start);
            }
            at += Duration::from_millis(5);
        }
        let list = addrs(6);
        for (k, addr) in list.iter().enumerate() {
            let sent = &times[addr];
            assert_eq!(sent[0], Duration::from_millis(50 * k as u64));
            assert_eq!(sent[1] - sent[0], Duration::from_millis(300));
            assert_eq!(sent[2] - sent[1], Duration::from_millis(300));
        }
    }

    /// T5 (engine side): only fresh, well-behaved reflectors give a delta, the
    /// smallest in the interval, negatives as zero.
    #[test]
    fn t5_tick_deltas_take_the_interval_minimum_of_fresh_reflectors() {
        let start = t0();
        let mut engine = ReflectorEngine::new(&addrs(6), 1, start);
        // Reflector 6 never answers; the others sit at 5 ms up.
        let mut silent_sixth = |addr: Ipv4Addr| (addr != addrs(6)[5]).then_some((5, 5, 0));
        let end = run(&mut engine, start, 3.0, &mut silent_sixth);
        let deltas = engine.tick_deltas(end - Duration::from_millis(500), end);
        assert_eq!(deltas.len(), 5);
        assert!(deltas.iter().all(|d| *d <= 1_000), "{deltas:?}");
        // A window with no replies at all is empty.
        assert!(engine.tick_deltas(end + Duration::from_secs(1), end + Duration::from_secs(2)).is_empty());
    }

    /// T6: 3 late checks of the last 60 replace a reflector, once per round,
    /// with a spare if there is one, else it stays and its count restarts.
    #[test]
    fn t6_health_check_replaces_with_spare_and_keeps_without() {
        let start = t0();
        let list = addrs(7);
        let mut engine = ReflectorEngine::new(&list, 1, start);
        let dead = list[0];
        let mut answer = |addr: Ipv4Addr| (addr != dead).then_some((5, 5, 0));
        run(&mut engine, start, 6.0, &mut answer);
        let active = engine.active_reflectors();
        assert!(!active.contains(&dead), "{active:?}");
        assert!(active.contains(&list[6]));
        assert_eq!(active.len(), 6);
        // The bad one is the spare now (the back of the queue).
        assert_eq!(engine.spares.back(), Some(&dead));

        // No spare: it stays, and the count restarts after each detection.
        let start = t0();
        let mut engine = ReflectorEngine::new(&addrs(6), 1, start);
        let dead = addrs(6)[0];
        let mut answer = |addr: Ipv4Addr| (addr != dead).then_some((5, 5, 0));
        run(&mut engine, start, 6.0, &mut answer);
        assert!(engine.active_reflectors().contains(&dead));
        assert!(engine.slots[0].offence_count < MISBEHAVING_THR);
        // ...and it takes no part in the tick's delta while misbehaving.
        let mut engine = ReflectorEngine::new(&addrs(6), 1, start);
        run(&mut engine, start, 2.5, &mut answer);
        assert!(engine.slots[0].misbehaving() || engine.slots[0].offence_count > 0);

        // Fewer than 3 late checks in a window are tolerated: 2 s of silence
        // then recovery.
        let start = t0();
        let mut engine = ReflectorEngine::new(&addrs(7), 1, start);
        let mut now_ms = 0u64;
        let mut flaky = |addr: Ipv4Addr| {
            now_ms += 1;
            let _ = addr;
            Some((5, 5, 0))
        };
        run(&mut engine, start, 5.0, &mut flaky);
        assert_eq!(engine.active_reflectors(), addrs(6));
    }

    /// T6: the minute comparison rotates out a reflector 20 ms above the
    /// smallest round-trip baseline, or whose delay EWMA is 10 ms above.
    #[test]
    fn t6_comparison_thresholds() {
        let seeded = |rtt: i64, ul_ewma: i64, dl_ewma: i64| ReflectorStats {
            seeded: true,
            ul_baseline_us: 0,
            dl_baseline_us: 0,
            rtt_baseline_us: rtt,
            ul_delta_ewma_us: ul_ewma,
            dl_delta_ewma_us: dl_ewma,
        };
        let check = |third: ReflectorStats| {
            let start = t0();
            let list = addrs(7);
            let mut engine = ReflectorEngine::new(&list, 1, start);
            for addr in &list[..6] {
                engine.stats.insert(*addr, seeded(30_000, 0, 0));
            }
            engine.stats.insert(list[2], third);
            engine.compare_reflectors(start);
            engine.active_reflectors().contains(&list[2])
        };
        // Round-trip baseline: exactly 20 ms above stays, more goes.
        assert!(check(seeded(50_000, 0, 0)));
        assert!(!check(seeded(50_001, 0, 0)));
        // Delay EWMAs: exactly 10 ms above stays, more goes (both directions).
        assert!(check(seeded(30_000, 10_000, 0)));
        assert!(!check(seeded(30_000, 10_001, 0)));
        assert!(check(seeded(30_000, 0, 10_000)));
        assert!(!check(seeded(30_000, 0, 10_001)));
        // A reflector with no statistics yet postpones the comparison.
        let start = t0();
        let list = addrs(7);
        let mut engine = ReflectorEngine::new(&list, 1, start);
        for addr in &list[..5] {
            engine.stats.insert(*addr, seeded(30_000, 0, 0));
        }
        assert!(!engine.compare_reflectors(start));
    }

    /// T7: 60 s with every user below the active threshold stops the
    /// sending; one user at or above it resumes it, statistics kept.
    #[test]
    fn t7_idle_stops_sending_and_load_resumes() {
        let start = t0();
        let mut engine = ReflectorEngine::new(&addrs(6), 1, start);
        let thr = 50_000;
        let mut answer = |_: Ipv4Addr| Some((5, 5, 0));
        let mut at = run(&mut engine, start, 2.0, &mut answer);
        let baseline = engine.stats_of(addrs(6)[0]).unwrap();
        assert!(baseline.seeded);
        // The last activity was now. Below the threshold for 59 s: still sending.
        engine.note_load(at, thr, 1_000_000, thr);
        for s in 0..59 {
            engine.note_load(at + Duration::from_secs(s), thr - 1, 1_000_000, thr);
        }
        at += Duration::from_secs(59);
        engine.update_sleep(at);
        assert!(!engine.is_sleeping());
        assert!(!engine.poll_send(at, 0).is_empty() || !engine.poll_send(at + PING_INTERVAL, 0).is_empty());
        // 60 s: asleep, nothing is sent.
        engine.note_load(at + Duration::from_secs(1), thr - 1, 1_000_000, thr);
        at += Duration::from_secs(3);
        engine.update_sleep(at);
        assert!(engine.is_sleeping());
        assert!(engine.poll_send(at, 0).is_empty());
        assert!(engine.poll_send(at + Duration::from_secs(5), 0).is_empty());
        // A user at the threshold wakes it; the baselines are still there.
        let wake = at + Duration::from_secs(10);
        engine.note_load(wake, thr, 1_000_000, thr);
        assert!(!engine.is_sleeping());
        assert_eq!(engine.stats_of(addrs(6)[0]).unwrap().ul_baseline_us, baseline.ul_baseline_us);
        let mut sent = 0;
        let mut t = wake;
        while t < wake + Duration::from_millis(400) {
            sent += engine.poll_send(t, 0).len();
            t += Duration::from_millis(5);
        }
        assert!(sent >= 6, "{sent}");
        // The health check does not judge the pause as silence.
        engine.health_check(wake + Duration::from_millis(500));
        assert!(engine.slots.iter().all(|s| s.offence_count == 0));
    }

    /// Replies with a wrong identifier, an unknown sequence or the wrong
    /// source are ignored.
    #[test]
    fn foreign_replies_are_ignored() {
        let start = t0();
        let list = addrs(6);
        let mut engine = ReflectorEngine::new(&list, 0x1234, start);
        let sent = engine.poll_send(start, 5_000);
        let (addr, packet) = sent[0];
        let (_, request) = parse_reply(&with_ip_header(
            &encode_reply(&TimestampMessage {
                identifier: 0x1234,
                sequence: u16::from_be_bytes([packet[6], packet[7]]),
                originate: 5_000,
                receive: 5_010,
                transmit: 5_010,
            }),
            addr,
        ))
        .unwrap();
        let at = start + Duration::from_millis(30);
        engine.on_reply(at, list[3], &request, 5_020);
        engine.on_reply(at, addr, &TimestampMessage { identifier: 1, ..request }, 5_020);
        engine.on_reply(at, addr, &TimestampMessage { sequence: 999, ..request }, 5_020);
        assert!(engine.stats_of(addr).is_none());
        engine.on_reply(at, addr, &request, 5_020);
        assert!(engine.stats_of(addr).is_some());
        // The same reply twice counts once.
        let before = engine.samples[&addr].len();
        engine.on_reply(at, addr, &request, 5_020);
        assert_eq!(engine.samples[&addr].len(), before);
    }
}

/// Real sockets in a private network namespace (Linux, root): the test thread
/// leaves the host's namespace for a fresh one, `A`, and a child `unshare -n`
/// process is `B`, holding the six reflector addresses. Netem delays one
/// direction at a time. Run one test per process.
#[cfg(all(test, target_os = "linux"))]
mod netns_tests {
    use super::*;
    use std::process::{Child, Command, Stdio};

    fn sh(command: &str) {
        let output = Command::new("sh").arg("-c").arg(command).output().unwrap();
        assert!(
            output.status.success(),
            "`{command}` failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    struct World {
        other: Child,
    }

    impl World {
        /// `A` (this thread) and `B` joined by `vethA`/`vethB` (10.77.0.0/24)
        /// and by `vethC`/`vethD` (10.79.0.0/24), the better route to B's six
        /// reflector addresses 10.78.0.1-6 (on B's `lo`).
        fn new() -> Option<Self> {
            if unsafe { nix::libc::geteuid() } != 0 {
                eprintln!("reflector netns test skipped (not root)");
                return None;
            }
            assert_eq!(unsafe { nix::libc::unshare(nix::libc::CLONE_NEWNET) }, 0);
            let other = Command::new("unshare")
                .args(["-n", "sleep", "300"])
                .stdout(Stdio::null())
                .spawn()
                .unwrap();
            let pid = other.id();
            // Wait for B's namespace to exist (the child has unshared).
            std::thread::sleep(Duration::from_millis(300));
            let b = |command: &str| sh(&format!("nsenter -t {pid} -n sh -c \"{command}\""));
            sh("ip link set lo up");
            sh("sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0");
            sh("ip link add vethA type veth peer name vethB");
            sh("ip link add vethC type veth peer name vethD");
            sh(&format!("ip link set vethB netns {pid}"));
            sh(&format!("ip link set vethD netns {pid}"));
            sh("ip addr add 10.77.0.1/24 dev vethA && ip link set vethA up");
            sh("ip addr add 10.79.0.1/24 dev vethC && ip link set vethC up");
            b("ip link set lo up");
            b("sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0");
            b("ip addr add 10.77.0.2/24 dev vethB && ip link set vethB up");
            b("ip addr add 10.79.0.2/24 dev vethD && ip link set vethD up");
            for i in 1..=6 {
                b(&format!("ip addr add 10.78.0.{i}/32 dev lo"));
            }
            sh("ip route add 10.78.0.0/24 via 10.79.0.2 dev vethC metric 10");
            sh("ip route add 10.78.0.0/24 via 10.77.0.2 dev vethA metric 100");
            Some(Self { other })
        }

        fn in_b(&self, command: &str) {
            sh(&format!("nsenter -t {} -n sh -c \"{command}\"", self.other.id()));
        }

        /// A prober on `vethA`, the worse route; `vethC` is where plain
        /// routing would send the packets.
        fn prober(&self) -> Arc<ReflectorProber> {
            ReflectorProber::start(&ProberKey {
                egress: EgressStableId::Linux { netns_inode: 0, ifindex: 0 },
                local: Ipv4Addr::new(10, 77, 0, 1),
                device: "vethA".to_string(),
                socket_mark: None,
                reflectors: (1..=6).map(|i| Ipv4Addr::new(10, 78, 0, i)).collect(),
            })
            .unwrap()
        }
    }

    impl Drop for World {
        fn drop(&mut self) {
            let _ = self.other.kill();
            let _ = self.other.wait();
        }
    }

    fn settle(seconds: u64) {
        std::thread::sleep(Duration::from_secs(seconds));
    }

    /// The deltas of the last second.
    fn last_second(prober: &ReflectorProber) -> Vec<u64> {
        let now = Instant::now();
        prober.tick_deltas(now - Duration::from_secs(1), now)
    }

    /// N1a: 80 ms added to the upload only (A -> B) shows as an upstream delta
    /// of at least 70 ms on every reflector.
    #[test]
    fn n1_upload_delay_shows_in_the_upstream_delta() {
        let Some(world) = World::new() else { return };
        let prober = world.prober();
        settle(3);
        let calm = last_second(&prober);
        assert!(calm.len() >= 5 && calm.iter().all(|d| *d < 5_000), "{calm:?}");
        sh("tc qdisc add dev vethA root netem delay 80ms");
        settle(2);
        let delayed = last_second(&prober);
        assert!(delayed.len() >= 5, "{delayed:?}");
        assert!(delayed.iter().all(|d| *d >= 70_000), "{delayed:?}");
    }

    /// N1b: 80 ms added to the download only (B -> A) leaves the upstream delta
    /// under 5 ms, while the downstream delay EWMA (and so the round trip) rises.
    #[test]
    fn n1_download_delay_does_not_show_in_the_upstream_delta() {
        let Some(world) = World::new() else { return };
        let prober = world.prober();
        settle(3);
        world.in_b("tc qdisc add dev vethB root netem delay 80ms");
        settle(3);
        let deltas = last_second(&prober);
        assert!(deltas.len() >= 5, "{deltas:?}");
        assert!(deltas.iter().all(|d| *d < 5_000), "{deltas:?}");
        prober.with_engine(|engine| {
            for addr in engine.active_reflectors() {
                let stats = engine.stats_of(addr).unwrap();
                assert!(stats.dl_delta_ewma_us > 20_000, "{addr}: {stats:?}");
                assert!(stats.ul_delta_ewma_us < 5_000, "{addr}: {stats:?}");
            }
        });
    }

    /// N1c: the socket is bound to `vethA` (SO_BINDTODEVICE) although the route
    /// to the reflectors prefers `vethC`: 80 ms both ways on the `vethC`/`vethD`
    /// link does not reach the result.
    #[test]
    fn n1_binding_keeps_the_probes_on_their_own_card() {
        let Some(world) = World::new() else { return };
        sh("tc qdisc add dev vethC root netem delay 80ms");
        world.in_b("tc qdisc add dev vethD root netem delay 80ms");
        let prober = world.prober();
        settle(4);
        let deltas = last_second(&prober);
        assert!(deltas.len() >= 5, "{deltas:?}");
        assert!(deltas.iter().all(|d| *d < 5_000), "{deltas:?}");
        // `/proc/net/dev` of a child process: it has this thread's namespace.
        let sent = |card: &str| -> u64 {
            let out = Command::new("cat").arg("/proc/net/dev").output().unwrap();
            let table = String::from_utf8_lossy(&out.stdout).into_owned();
            let line = table
                .lines()
                .find_map(|l| l.trim_start().strip_prefix(&format!("{card}:")))
                .unwrap();
            line.split_whitespace().nth(9).unwrap().parse().unwrap()
        };
        // ~3.3 requests/s x 6 reflectors x 4 s on vethA; none on vethC.
        assert!(sent("vethA") > 50, "vethA sent {}", sent("vethA"));
        assert!(sent("vethC") < 10, "vethC sent {}", sent("vethC"));
        prober.with_engine(|engine| {
            for addr in engine.active_reflectors() {
                let stats = engine.stats_of(addr).unwrap();
                assert!(stats.dl_delta_ewma_us < 5_000, "{addr}: {stats:?}");
                assert!(stats.rtt_baseline_us < 20_000, "{addr}: {stats:?}");
            }
        });
    }
}

/// W1: a real prober on a real card for 30 s (`REFLECTOR_LIVE=1`,
/// `REFLECTOR_LIVE_LOCAL=<the card's IPv4>`; needs administrator/root). All six
/// default reflectors must answer and the upstream delta's standard deviation
/// stay under 5 ms.
#[cfg(test)]
mod live_tests {
    use super::*;

    #[test]
    #[ignore = "needs REFLECTOR_LIVE=1, REFLECTOR_LIVE_LOCAL and a public network"]
    fn w1_live_card_reaches_every_default_reflector_with_a_quiet_upstream() {
        if std::env::var_os("REFLECTOR_LIVE").is_none() {
            eprintln!("w1: REFLECTOR_LIVE is not set");
            return;
        }
        let local: Ipv4Addr = std::env::var("REFLECTOR_LIVE_LOCAL")
            .expect("REFLECTOR_LIVE_LOCAL=<IPv4 of the card>")
            .parse()
            .unwrap();
        let device = crate::tunnel::common::get_interface_name_by_ip(&std::net::IpAddr::V4(local))
            .expect("no interface for REFLECTOR_LIVE_LOCAL");
        let key = ProberKey {
            egress: EgressStableId::Fallback { platform: "live".into(), opaque: device.clone() },
            local,
            device,
            socket_mark: None,
            reflectors: DEFAULT_REFLECTORS.to_vec(),
        };
        let prober = prober_for(&key).expect("raw socket (administrator/root needed)");
        let mut seen: HashMap<(Ipv4Addr, Instant), u64> = HashMap::new();
        for _ in 0..15 {
            std::thread::sleep(Duration::from_secs(2));
            prober.with_engine(|engine| {
                for (addr, samples) in &engine.samples {
                    for (at, delta) in samples {
                        seen.insert((*addr, *at), *delta);
                    }
                }
            });
        }
        for addr in DEFAULT_REFLECTORS {
            let own = seen.keys().filter(|(a, _)| *a == addr).count();
            eprintln!("{addr}: {own} samples");
            assert!(own > 0, "{addr} gave no timestamp reply");
        }
        let values = seen.values().map(|d| *d as f64 / 1000.0).collect::<Vec<_>>();
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        let std =
            (values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / values.len() as f64).sqrt();
        eprintln!("{} samples, mean {mean:.2} ms, std {std:.2} ms", values.len());
        assert!(std < 5.0, "std {std} ms");
    }
}

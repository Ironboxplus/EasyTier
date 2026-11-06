//! A small discrete-event simulator around `Cake`: constant-rate sources feed one queue, the
//! queue is drained exactly when it allows, and everything runs on a virtual clock.

#![allow(dead_code)]

use cake_sqm::{Cake, CakeConfig, Dequeued, PacketHeader, PacketMeta};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

pub const MBIT: u64 = 125_000; // bytes per second

#[derive(Debug)]
pub struct Pkt {
    pub source: usize,
}

pub struct Source {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub flow_hash: Option<u32>,
    pub len: u32,
    pub interval: Duration,
    pub next: Duration,
    pub stop: Duration,
}

impl Source {
    /// A source of `len`-byte packets that offers `bytes_per_sec`, from host `src_host` (the last
    /// octet of 10.0.0.x) port `port` to host `dst_host` of 192.0.2.x.
    pub fn new(src_host: u8, port: u16, dst_host: u8, len: u32, bytes_per_sec: u64) -> Self {
        Self {
            src: SocketAddr::from((Ipv4Addr::new(10, 0, 0, src_host), port)),
            dst: SocketAddr::from((Ipv4Addr::new(192, 0, 2, dst_host), 443)),
            flow_hash: None,
            len,
            interval: Duration::from_nanos(len as u64 * 1_000_000_000 / bytes_per_sec),
            next: Duration::ZERO,
            stop: Duration::MAX,
        }
    }

    pub fn hash(mut self, hash: u32) -> Self {
        self.flow_hash = Some(hash);
        self
    }

    pub fn starting(mut self, at: Duration) -> Self {
        self.next = at;
        self
    }
}

#[derive(Default, Clone)]
pub struct PerSource {
    pub sent_bytes: u64,
    pub sent_packets: u64,
    pub dropped_packets: u64,
    pub sojourns: Vec<Duration>,
}

impl PerSource {
    pub fn mean_sojourn(&self) -> Duration {
        if self.sojourns.is_empty() {
            return Duration::ZERO;
        }
        self.sojourns.iter().sum::<Duration>() / self.sojourns.len() as u32
    }

    pub fn max_sojourn(&self) -> Duration {
        self.sojourns.iter().copied().max().unwrap_or_default()
    }
}

pub struct Sim {
    pub cake: Cake<Pkt>,
    pub t0: Instant,
    pub now: Duration,
    pub sources: Vec<Source>,
    pub per: Vec<PerSource>,
    sent_len: Vec<u32>,
}

impl Sim {
    pub fn new(cfg: &CakeConfig, sources: Vec<Source>) -> Self {
        let t0 = Instant::now();
        let n = sources.len();
        Self {
            cake: Cake::new(cfg, t0).expect("cake_init"),
            t0,
            now: Duration::ZERO,
            sources,
            per: vec![PerSource::default(); n],
            sent_len: Vec::new(),
        }
    }

    fn enqueue_from(&mut self, i: usize) {
        let s = &self.sources[i];
        let meta = PacketMeta {
            len: s.len,
            header: PacketHeader::Udp {
                src: s.src,
                dst: s.dst,
                dscp: 0,
            },
            flow_hash: s.flow_hash,
            mark: 0,
        };
        let len = s.len;
        let dropped = self
            .cake
            .enqueue(meta, Pkt { source: i }, self.t0 + self.now);
        let _ = len;
        for d in dropped {
            self.per[d.source].dropped_packets += 1;
        }
    }

    fn drain(&mut self) -> Option<Duration> {
        let at = self.t0 + self.now;
        let wake = loop {
            match self.cake.dequeue(at) {
                Dequeued::Packet { item, sojourn } => {
                    let len = self.sources[item.source].len as u64;
                    let p = &mut self.per[item.source];
                    p.sent_bytes += len;
                    p.sent_packets += 1;
                    p.sojourns.push(sojourn);
                }
                Dequeued::NotBefore(t) => break Some(t.saturating_duration_since(self.t0)),
                Dequeued::Empty => break None,
            }
        };
        for d in self.cake.take_dropped() {
            self.per[d.source].dropped_packets += 1;
        }
        wake
    }

    /// Runs until virtual time `end`.
    pub fn run_until(&mut self, end: Duration) {
        loop {
            // Arrivals due now.
            for i in 0..self.sources.len() {
                while self.sources[i].next <= self.now && self.sources[i].next < self.sources[i].stop {
                    self.enqueue_from(i);
                    let s = &mut self.sources[i];
                    s.next += s.interval;
                }
            }
            let wake = self.drain();
            let arrival = self
                .sources
                .iter()
                .filter(|s| s.next < s.stop)
                .map(|s| s.next)
                .min();
            let next = match (wake, arrival) {
                (Some(w), Some(a)) => w.min(a),
                (Some(t), None) | (None, Some(t)) => t,
                (None, None) => break,
            };
            if next >= end {
                break;
            }
            // A wake-up that is not in the future would spin; step a microsecond instead.
            self.now = if next > self.now {
                next
            } else {
                self.now + Duration::from_micros(1)
            };
        }
        self.now = end;
    }

    pub fn total_bytes(&self) -> u64 {
        self.per.iter().map(|p| p.sent_bytes).sum()
    }

    pub fn share(&self, i: usize) -> f64 {
        self.per[i].sent_bytes as f64 / self.total_bytes() as f64
    }
}

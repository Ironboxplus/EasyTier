//! CAKE_SQM_PLAN.md phase A: the compiled sch_cake.c behaves like Linux's CAKE. All tests run on
//! a virtual clock; none sleeps.

mod common;

use cake_sqm::{AckFilter, Cake, CakeConfig, Dequeued, FlowMode, PacketHeader, PacketMeta};
use common::*;
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const PINNED_SHA256: &str = "bafe5df74aa52b00ff1625985ca8b592f418dff79fd9cc21d1c1dce17d7607f9";
const SEC: Duration = Duration::from_secs(1);

fn cfg(bandwidth: u64) -> CakeConfig {
    CakeConfig {
        bandwidth,
        ..CakeConfig::default()
    }
}

fn within(actual: f64, expected: f64, tolerance: f64) -> bool {
    (actual - expected).abs() <= expected * tolerance
}

// A1 -----------------------------------------------------------------------------------------

#[test]
fn a1_sch_cake_c_is_the_pristine_upstream_file() {
    let file = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/csrc/linux/sch_cake.c")).unwrap();
    let digest: String = Sha256::digest(&file).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(digest, PINNED_SHA256);
    assert_eq!(cake_sqm::SCH_CAKE_SHA256, PINNED_SHA256);
}

// A2 -----------------------------------------------------------------------------------------

fn throughput_within_one_percent(mbit: u64) {
    let rate = mbit * MBIT;
    // One flow offering 1.5 times the rate for 10 s.
    let source = Source::new(1, 5000, 1, 1250, rate * 3 / 2);
    let mut sim = Sim::new(&cfg(rate), vec![source]);
    sim.run_until(10 * SEC);
    let sent = sim.total_bytes() as f64;
    let expected = (rate * 10) as f64;
    assert!(
        within(sent, expected, 0.01),
        "{mbit} Mbit/s: sent {sent} B in 10 s, expected {expected} B +-1%"
    );
}

#[test]
fn a2_rate_is_exact_at_1_mbit() {
    throughput_within_one_percent(1);
}

#[test]
fn a2_rate_is_exact_at_10_mbit() {
    throughput_within_one_percent(10);
}

#[test]
fn a2_rate_is_exact_at_100_mbit() {
    throughput_within_one_percent(100);
}

// A3 -----------------------------------------------------------------------------------------

#[test]
fn a3_two_bulk_flows_share_equally_whatever_they_offer() {
    let rate = 10 * MBIT;
    let sources = vec![
        Source::new(1, 5000, 1, 1250, rate),
        Source::new(1, 5001, 1, 1250, rate * 3),
    ];
    let mut sim = Sim::new(&cfg(rate), sources);
    sim.run_until(10 * SEC);
    for i in 0..2 {
        assert!(
            (sim.share(i) - 0.5).abs() <= 0.05,
            "flow {i} got {:.3} of the link",
            sim.share(i)
        );
    }
}

// A4 -----------------------------------------------------------------------------------------

#[test]
fn a4_a_sparse_flow_is_not_delayed_by_a_saturating_bulk_flow() {
    let rate = 10 * MBIT;
    let packet_time = Duration::from_micros(1250 * 1_000_000 / rate);
    let sources = vec![
        Source::new(1, 5000, 1, 1250, rate * 2),
        // One small packet every 100 ms.
        Source::new(1, 5001, 1, 100, 1000),
    ];
    let mut sim = Sim::new(&cfg(rate), sources);
    sim.run_until(10 * SEC);
    let sparse = &sim.per[1];
    assert!(sparse.sent_packets >= 95, "sparse flow sent {}", sparse.sent_packets);
    assert_eq!(sparse.dropped_packets, 0);
    assert!(
        sparse.max_sojourn() < 2 * packet_time,
        "sparse packets waited up to {:?}, two packet times are {:?}",
        sparse.max_sojourn(),
        2 * packet_time
    );
    // The bulk flow is queued deep enough that a FIFO would have delayed them much longer.
    assert!(sim.per[0].mean_sojourn() > 4 * packet_time);
}

// A5 -----------------------------------------------------------------------------------------

/// With the buffer sized to a bandwidth-delay product (rate x rtt, what RFC 7567 asks for: limits
/// that reflect bursts), COBALT's drop schedule and then BLUE bring an unresponsive flow at twice
/// the rate down to a queue of a few target times within three seconds.
#[test]
fn a5_an_unresponsive_flow_at_twice_the_rate_is_dropped_and_kept_short() {
    let rate = 10 * MBIT;
    let target = Duration::from_millis(5);
    let limit = (rate / 10) as u32; // rate x 100 ms
    let c = CakeConfig {
        bandwidth: rate,
        target,
        memory_limit: Some(limit),
        ..CakeConfig::default()
    };
    let mut sim = Sim::new(&c, vec![Source::new(1, 5000, 1, 1250, rate * 2)]);
    sim.run_until(3 * SEC);
    let settled = sim.per[0].sojourns.len();
    sim.run_until(10 * SEC);
    let p = &sim.per[0];
    assert!(p.dropped_packets > 0, "no drop at 2x overload");
    let late = &p.sojourns[settled..];
    let mean = late.iter().sum::<Duration>() / late.len() as u32;
    assert!(mean < 5 * target, "mean queueing time after 3 s: {mean:?}, limit {:?}", 5 * target);
    let stats = sim.cake.stats();
    // The peak may overshoot by the packet that triggered the drop (truesize = len + 256).
    assert!(stats.memory_used <= limit + 1250 + 256, "peak {} of {limit}", stats.memory_used);
    assert!(within(sim.total_bytes() as f64, (rate * 10) as f64, 0.02));
}

/// What the unmodified CAKE does with its default memory limit (max(4 MB, rate x rtt x 4), 3.2 s
/// of data at 10 Mbit/s): the same overload is queued for seconds before BLUE can act, because
/// BLUE only reacts to a full buffer. This is why ET sets `memory_limit` itself.
#[test]
fn a5_with_the_default_memory_limit_an_overloaded_queue_grows_for_seconds() {
    let rate = 10 * MBIT;
    let mut sim = Sim::new(&cfg(rate), vec![Source::new(1, 5000, 1, 1250, rate * 2)]);
    sim.run_until(10 * SEC);
    let p = &sim.per[0];
    assert!(p.dropped_packets > 0);
    assert!(p.mean_sojourn() > Duration::from_millis(500), "{:?}", p.mean_sojourn());
    let stats = sim.cake.stats();
    assert!(stats.memory_limit >= 4 << 20);
}

// A6 -----------------------------------------------------------------------------------------

/// The scenario of the former `fq_codel` red test
/// `a_queue_of_at_most_one_mtu_is_never_dropped`: 40 kB/s, one packet arrives as the previous one
/// leaves, so a packet always waits a whole packet time (31.25 ms, far above the 5 ms target)
/// while the queue never holds more than one.
#[test]
fn a6_a_queue_of_at_most_one_mtu_is_never_dropped() {
    let c = CakeConfig {
        bandwidth: 40_000,
        mtu: 1250,
        ..CakeConfig::default()
    };
    let t0 = Instant::now();
    let mut cake = Cake::<u32>::new(&c, t0).unwrap();
    let meta = PacketMeta {
        len: 1250,
        header: PacketHeader::Udp {
            src: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 5000)),
            dst: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 443)),
            dscp: 0,
        },
        flow_hash: None,
        mark: 0,
    };
    let tick = Duration::from_micros(31_250);
    let mut dropped = cake.enqueue(meta, 0, t0).len();
    let mut delivered = 0;
    for i in 1..=400u32 {
        let now = t0 + tick * i;
        let mut at = now;
        loop {
            match cake.dequeue(at) {
                Dequeued::Packet { .. } => {
                    delivered += 1;
                    break;
                }
                // The shaper's slot may land a few nanoseconds after the tick.
                Dequeued::NotBefore(t) if t.duration_since(now) < Duration::from_micros(10) => at = t,
                other => panic!("tick {i}: {other:?}"),
            }
        }
        dropped += cake.take_dropped().len();
        dropped += cake.enqueue(meta, i, at).len();
    }
    assert_eq!(dropped, 0, "a lone waiting packet was dropped");
    assert_eq!(delivered, 400);
}

// A7 -----------------------------------------------------------------------------------------

#[test]
fn a7_set_bandwidth_takes_effect_on_a_running_queue() {
    let rate = 10 * MBIT;
    let mut sim = Sim::new(&cfg(rate), vec![Source::new(1, 5000, 1, 1250, rate * 2)]);
    sim.run_until(5 * SEC);
    let first = sim.total_bytes();
    assert!(within(first as f64, (rate * 5) as f64, 0.02));
    sim.cake.set_bandwidth(rate / 2, sim.t0 + sim.now).unwrap();
    sim.run_until(10 * SEC);
    let second = sim.total_bytes() - first;
    assert!(
        within(second as f64, (rate / 2 * 5) as f64, 0.02),
        "after halving: {second} B in 5 s, expected {} B",
        rate / 2 * 5
    );
}

#[test]
fn a7_reconfigure_changes_target_and_rtt() {
    let t0 = Instant::now();
    let mut cake = Cake::<u8>::new(&cfg(MBIT), t0).unwrap();
    let attr = |cake: &mut Cake<u8>, kind: u16| {
        let attrs = cake.config_attrs();
        let (_, v) = attrs.into_iter().find(|(k, _)| *k == kind).unwrap_or_else(|| panic!("no attr {kind}"));
        u32::from_ne_bytes(v[..4].try_into().unwrap())
    };
    assert_eq!(attr(&mut cake, 7), 100_000, "default rtt is 100 ms");
    assert_eq!(attr(&mut cake, 8), 5_000, "default target is 5 ms");
    let mut c = cfg(2 * MBIT);
    c.rtt = Duration::from_millis(40);
    c.target = Duration::from_millis(2);
    cake.reconfigure(&c, t0).unwrap();
    assert_eq!(attr(&mut cake, 7), 40_000);
    assert_eq!(attr(&mut cake, 8), 2_000);
}

// A8 -----------------------------------------------------------------------------------------

#[test]
fn a8_triple_isolate_shares_per_host_not_per_flow() {
    let rate = 10 * MBIT;
    // Host 1 runs four flows to host 1', host 2 runs one flow to host 2'.
    let mut sources: Vec<Source> = (0..4).map(|i| Source::new(1, 5000 + i, 1, 1250, rate)).collect();
    sources.push(Source::new(2, 6000, 2, 1250, rate));
    let mut sim = Sim::new(&cfg(rate), sources);
    sim.run_until(10 * SEC);
    let host1: f64 = (0..4).map(|i| sim.share(i)).sum();
    let host2 = sim.share(4);
    assert!((host1 - 0.5).abs() <= 0.05, "host 1 got {host1:.3}");
    assert!((host2 - 0.5).abs() <= 0.05, "host 2 got {host2:.3}");
}

// A9 -----------------------------------------------------------------------------------------

#[test]
fn a9_a_given_flow_hash_isolates_packets_of_one_outer_tuple() {
    let rate = 10 * MBIT;
    // The same outer UDP tuple (one QUIC path), two inner flows told apart by their hash.
    let sources = vec![
        Source::new(1, 5000, 1, 1250, rate).hash(0x1111),
        Source::new(1, 5000, 1, 1250, rate * 3).hash(0x2222),
    ];
    let mut sim = Sim::new(&cfg(rate), sources);
    sim.run_until(10 * SEC);
    for i in 0..2 {
        assert!((sim.share(i) - 0.5).abs() <= 0.05, "flow {i} got {:.3}", sim.share(i));
    }
}

#[test]
fn a9_packets_with_the_same_flow_hash_share_one_queue() {
    let rate = 10 * MBIT;
    let sources = vec![
        Source::new(1, 5000, 1, 1250, rate).hash(0x1111),
        Source::new(1, 5000, 1, 1250, rate * 3).hash(0x1111),
    ];
    let mut sim = Sim::new(&cfg(rate), sources);
    sim.run_until(10 * SEC);
    // One FIFO: the shares follow what each puts in, about 1 : 3.
    assert!(sim.share(1) > 0.65, "the heavier source got {:.3}", sim.share(1));
}

// A10 ----------------------------------------------------------------------------------------

struct Tracked {
    id: usize,
    live: Arc<AtomicUsize>,
}

impl Tracked {
    fn new(id: usize, live: &Arc<AtomicUsize>) -> Self {
        live.fetch_add(1, Ordering::SeqCst);
        Self { id, live: live.clone() }
    }
}

impl Drop for Tracked {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

#[test]
fn a10_every_item_leaves_exactly_once_and_nothing_leaks() {
    let live = Arc::new(AtomicUsize::new(0));
    let mut rng = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let t0 = Instant::now();
    let mut now = Duration::ZERO;
    let c = CakeConfig {
        bandwidth: 5 * MBIT,
        memory_limit: Some(64 * 1024),
        ..CakeConfig::default()
    };
    let mut cake = Cake::<Tracked>::new(&c, t0).unwrap();
    let mut outcome = vec![0u8; 100_000];
    let mut record = |item: Tracked| {
        outcome[item.id] += 1;
        assert_eq!(outcome[item.id], 1, "item {} left twice", item.id);
    };
    for id in 0..100_000usize {
        let r = next();
        now += Duration::from_micros(r % 400);
        match r >> 60 {
            0..=9 => {
                let flow = (r >> 8) % 16;
                let meta = PacketMeta {
                    len: 60 + ((r >> 16) % 1400) as u32,
                    header: PacketHeader::Udp {
                        src: SocketAddr::from((Ipv4Addr::new(10, 0, 0, (flow % 3) as u8 + 1), 5000 + flow as u16)),
                        dst: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 443)),
                        dscp: ((r >> 40) % 64) as u8,
                    },
                    flow_hash: ((r >> 50) & 1 == 1).then_some((flow as u32) * 7919),
                    mark: 0,
                };
                for dropped in cake.enqueue(meta, Tracked::new(id, &live), t0 + now) {
                    record(dropped);
                }
            }
            10..=14 => {
                if let Dequeued::Packet { item, .. } = cake.dequeue(t0 + now) {
                    record(item);
                }
                for dropped in cake.take_dropped() {
                    record(dropped);
                }
            }
            _ => cake
                .set_bandwidth((1 + (r >> 20) % 20) * MBIT, t0 + now)
                .unwrap(),
        }
        if id % 5000 == 0 {
            let s = cake.stats();
            assert_eq!(s.qlen as usize, cake.len());
            assert_eq!(live.load(Ordering::SeqCst), cake.len(), "items alive vs queued");
        }
    }
    // Drain what is left, then drop the rest with the queue.
    for _ in 0..200_000 {
        now += Duration::from_millis(1);
        match cake.dequeue(t0 + now) {
            Dequeued::Packet { item, .. } => record(item),
            Dequeued::NotBefore(_) => {}
            Dequeued::Empty => break,
        }
        for dropped in cake.take_dropped() {
            record(dropped);
        }
    }
    assert!(cake.is_empty());
    drop(cake);
    assert_eq!(live.load(Ordering::SeqCst), 0, "items leaked");
}

#[test]
fn a10_items_still_queued_are_dropped_with_the_queue() {
    let live = Arc::new(AtomicUsize::new(0));
    let t0 = Instant::now();
    let mut cake = Cake::<Tracked>::new(&cfg(MBIT), t0).unwrap();
    for id in 0..100 {
        let meta = PacketMeta {
            len: 1000,
            header: PacketHeader::Udp {
                src: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 5000 + id as u16)),
                dst: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 443)),
                dscp: 0,
            },
            flow_hash: None,
            mark: 0,
        };
        assert!(cake.enqueue(meta, Tracked::new(id, &live), t0).is_empty());
    }
    assert_eq!(live.load(Ordering::SeqCst), 100);
    drop(cake);
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

// A11 ----------------------------------------------------------------------------------------

#[test]
fn a11_over_the_memory_limit_the_longest_queue_loses_packets() {
    let t0 = Instant::now();
    let c = CakeConfig {
        bandwidth: MBIT,
        memory_limit: Some(64 * 1024),
        ..CakeConfig::default()
    };
    let mut cake = Cake::<usize>::new(&c, t0).unwrap();
    let meta = |port: u16| PacketMeta {
        len: 1000,
        header: PacketHeader::Udp {
            src: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), port)),
            dst: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 443)),
            dscp: 0,
        },
        flow_hash: None,
        mark: 0,
    };
    // Three small flows of 5 packets each, then one flow that floods the queue.
    let mut dropped = Vec::new();
    for flow in 0..3usize {
        for i in 0..5 {
            dropped.extend(cake.enqueue(meta(6000 + flow as u16), flow * 100 + i, t0));
        }
    }
    for i in 0..200 {
        dropped.extend(cake.enqueue(meta(5000), 1000 + i, t0));
    }
    assert!(!dropped.is_empty(), "the limit was never reached");
    assert!(
        dropped.iter().all(|&id| id >= 1000),
        "a packet of a short flow was dropped: {:?}",
        dropped.iter().filter(|&&id| id < 1000).collect::<Vec<_>>()
    );
    let stats = cake.stats();
    assert!(stats.memory_now <= stats.memory_limit);
    assert_eq!(stats.tins[0].drop_overlimit as usize, dropped.len());
}

// A12 ----------------------------------------------------------------------------------------

#[test]
fn a12_statistics_match_a_hand_count() {
    let t0 = Instant::now();
    // Unlimited, so packets leave as soon as asked; 2 ms of waiting stays under the 5 ms target.
    let mut cake = Cake::<usize>::new(&cfg(0), t0).unwrap();
    let meta = |port: u16, len: u32| PacketMeta {
        len,
        header: PacketHeader::Udp {
            src: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), port)),
            dst: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 443)),
            dscp: 0,
        },
        flow_hash: None,
        mark: 0,
    };
    for (i, len) in [200u32, 400, 800].into_iter().enumerate() {
        assert!(cake.enqueue(meta(5000 + i as u16, len), i, t0).is_empty());
    }
    let s = cake.stats();
    assert_eq!((s.qlen, s.backlog), (3, 1400));
    assert_eq!(s.tins.len(), 1, "best effort has one tin");
    let tin = s.tins[0];
    assert_eq!((tin.sent_packets, tin.sent_bytes), (3, 1400));
    assert_eq!((tin.backlog_bytes, tin.sparse_flows, tin.bulk_flows), (1400, 3, 0));
    assert_eq!(cake.backlog_bytes(), 1400);

    let later = t0 + Duration::from_millis(2);
    let mut sojourns = Vec::new();
    while let Dequeued::Packet { sojourn, .. } = cake.dequeue(later) {
        sojourns.push(sojourn);
    }
    assert_eq!(sojourns, vec![Duration::from_millis(2); 3]);
    let s = cake.stats();
    assert_eq!((s.qlen, s.backlog, s.dequeued_packets, s.dequeued_bytes), (0, 0, 3, 1400));
    let tin = s.tins[0];
    assert_eq!((tin.dropped_packets, tin.ack_drops, tin.ecn_marked), (0, 0, 0));
    assert!(tin.peak_delay_us > 0 && tin.peak_delay_us <= 2_000, "{}", tin.peak_delay_us);
    assert!(tin.base_delay_us <= tin.avg_delay_us && tin.avg_delay_us <= tin.peak_delay_us);
}

// Shape of the configuration surface ---------------------------------------------------------

#[test]
fn flow_blind_puts_every_flow_in_one_queue() {
    let rate = 10 * MBIT;
    let c = CakeConfig {
        bandwidth: rate,
        flow_mode: FlowMode::FlowBlind,
        ack_filter: AckFilter::Off,
        ..CakeConfig::default()
    };
    let sources = vec![
        Source::new(1, 5000, 1, 1250, rate),
        Source::new(1, 5001, 1, 1250, rate * 3),
    ];
    let mut sim = Sim::new(&c, sources);
    sim.run_until(10 * SEC);
    // No flow isolation: shares follow the offered load.
    assert!(sim.share(1) > 0.65, "got {:.3}", sim.share(1));
}

//! The stand-alone COBALT state (`Cobalt`), which the reliable-stream queues of ET use: the same
//! functions CAKE runs per flow, so what is tested here is that the wrapper reaches them intact.

use cake_sqm::Cobalt;
use std::time::{Duration, Instant};

const RATE: u64 = 1_250_000; // 10 Mbit/s
const TARGET: Duration = Duration::from_millis(5);
const RTT: Duration = Duration::from_millis(100);

fn cobalt(t0: Instant) -> Cobalt {
    Cobalt::new(RATE, 1500, TARGET, RTT, t0).expect("cobalt")
}

/// A queue whose packets wait less than the target is never told to drop.
#[test]
fn short_waits_are_never_dropped() {
    let t0 = Instant::now();
    let mut c = cobalt(t0);
    for i in 0..2_000u64 {
        let now = t0 + Duration::from_millis(i);
        assert!(!c.should_drop(now, now, 0));
    }
}

/// A wait far above the target that persists for longer than the interval gets drops, at a
/// rising rate (CoDel's control law), and stops once the waits are short again.
#[test]
fn a_persistent_standing_queue_is_dropped_then_recovers() {
    let epoch = Instant::now();
    let t0 = epoch + Duration::from_secs(1);
    let mut c = cobalt(epoch);
    let wait = Duration::from_millis(80);
    let mut drops = Vec::new();
    for i in 0..1_000u64 {
        let now = t0 + Duration::from_millis(i * 2);
        if c.should_drop(now, now - wait, 0) {
            drops.push(i * 2);
        }
    }
    assert!(!drops.is_empty(), "a standing queue must be signalled");
    assert!(drops.len() > 5, "a standing queue gets repeated drops: {drops:?}");
    let gaps: Vec<u64> = drops.windows(2).map(|w| w[1] - w[0]).collect();
    assert!(
        gaps.last().unwrap() < gaps.first().unwrap(),
        "drops must speed up while the queue stands: {gaps:?}"
    );

    // A new rate keeps the state, as CAKE keeps every flow's when a tin's rate changes: the
    // drops go on at the pace they had reached instead of starting over (a fresh state's
    // second gap is interval/sqrt(2), ~71 ms).
    let pace = *gaps.last().unwrap();
    c.set_rate(RATE / 2, 1500, TARGET, RTT).expect("set_rate");
    let resume = t0 + Duration::from_millis(2_000);
    let mut after = Vec::new();
    for i in 0..200u64 {
        let now = resume + Duration::from_millis(i);
        if c.should_drop(now, now - wait, 0) {
            after.push(i);
        }
    }
    let first_gap = after[1] - after[0];
    assert!(
        first_gap <= pace + 2 && first_gap < 50,
        "the drop pace restarted after a rate change: {first_gap} ms after {pace} ms ({after:?})"
    );

    let later = t0 + Duration::from_secs(5);
    for i in 0..200u64 {
        let now = later + Duration::from_millis(i);
        assert!(!c.should_drop(now, now - Duration::from_millis(1), 0), "recovered queue dropped");
    }
}

/// Overflow raises BLUE (`cake_drop` -> `cobalt_queue_full`), and BLUE then drops packets of
/// short waits too, at random. The random draw used to need a context only `Cake` set up, so on
/// a thread that had never run a `Cake` it crashed (the ET stream driver's thread).
#[test]
fn queue_full_raises_blue_on_a_thread_without_a_cake() {
    std::thread::spawn(|| {
        let t0 = Instant::now();
        let mut c = cobalt(t0);
        // BLUE steps up at most once per target (`cobalt_queue_full`); 256 steps saturate it.
        for i in 0..300u32 {
            c.queue_full(t0 + TARGET * 2 * (i + 1));
        }
        let now = t0 + TARGET * 2 * 301;
        let drops = (0..1_000u64).filter(|_| c.should_drop(now, now, 0)).count();
        assert!(drops > 900, "BLUE at full probability dropped only {drops} of 1000");
    })
    .join()
    .expect("the thread crashed");
}

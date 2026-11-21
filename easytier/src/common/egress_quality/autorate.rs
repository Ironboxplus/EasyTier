//! Autorate estimator (MP_SQM_PLAN.md §4.3), shared by the per-peer
//! route-weighting consumer (`peers/link_sqm.rs`) and the per-physical-egress
//! [`super::manager::EgressQualityManager`]. The control law is
//! cake-autorate's (github.com/lynxthecat/cake-autorate, `cake-autorate.sh`
//! "Update shaper rates" and `set_shaper_rates`) on the MP control tick:
//! bufferbloat cuts the rate whatever the load, a high load without
//! bufferbloat raises it, anything else returns it towards its base. It reads
//! delay and the sent rate only; how the sender paces itself (BBR, CUBIC,
//! Brutal) does not enter it.
//!
//! `LinkSqmEstimator` is **estimate-only**: it never touches a socket, `tc`,
//! or CAKE, and its output is a plain [`SqmEstimate`] the caller must still
//! turn into a `WireBudget` with an explicit `max_age` before it can gate a
//! governor. autorate ≠ allocator ≠ hard governor ≠ kernel AQM
//! (MP_SQM_PLAN.md §1).

use std::collections::VecDeque;

/// Tunables for the autorate control law, cake-autorate's (`defaults.sh`),
/// with its per-sample factors converted to one MP control tick
/// (`MpConfig.control_interval_ms`, 500 ms by default).
#[derive(Clone, Debug)]
pub struct SqmConfig {
    /// Lower clamp for the bandwidth estimate.
    pub bw_min_bps: u64,
    /// Upper clamp for the bandwidth estimate (link ceiling).
    pub bw_max_bps: u64,
    /// A sample this far above the baseline delay is delayed
    /// (`owd_delta_delay_thr_ms`).
    pub delay_thr_us: u64,
    /// Average delay over the window at which a cut is the largest
    /// (`avg_owd_delta_max_adjust_down_thr_ms`).
    pub delay_max_cut_us: u64,
    /// Average delay over the window at or below which a raise is the
    /// largest (`avg_owd_delta_max_adjust_up_thr_ms`).
    pub delay_max_raise_us: u64,
    /// Largest packet on the wire, in bits. Every delay threshold grows by the
    /// time one such packet takes at the current rate, as cake-autorate's
    /// `set_shaper_rates` compensates its thresholds: below about 12 Mbit/s a
    /// single queued packet would otherwise already read as bufferbloat.
    pub wire_packet_bits: u64,
    /// Samples kept for bufferbloat detection (`bufferbloat_detection_window`).
    pub detection_window: usize,
    /// Delayed samples in the window that mean bufferbloat
    /// (`bufferbloat_detection_thr`).
    pub detection_thr: usize,
    /// Factor per tick on bufferbloat at the smallest average delay
    /// (`shaper_rate_min_adjust_down_bufferbloat`, 0.99 per 300 ms).
    pub cut_min: f64,
    /// Factor per tick on bufferbloat at `delay_max_cut_us` and above
    /// (`shaper_rate_max_adjust_down_bufferbloat`, 0.75 per 300 ms).
    pub cut_max: f64,
    /// Largest factor per tick under a high load without bufferbloat
    /// (`shaper_rate_max_adjust_up_load_high`, 1.04 per 200 ms).
    pub raise_max: f64,
    /// Sent rate over the estimate above which the load is high
    /// (`high_load_thr`).
    pub high_load: f64,
    /// Fraction per tick by which an estimate under a low load returns to its
    /// base (`shaper_rate_adjust_{down,up}_load_low`, 1% per second).
    pub return_to_base: f64,
    /// Sent rate below which the link is idle and its delay is not sampled:
    /// the delay comes from the round trips of what we send, which stop
    /// being measured when we send next to nothing (cake-autorate likewise
    /// stops pinging an idle link, `enable_sleep_function`).
    pub active_thr_bps: u64,
    /// Upward relaxation of the baseline delay per tick; a lower sample
    /// replaces it (`alpha_baseline_increase`/`alpha_baseline_decrease`).
    pub baseline_rise: f64,
}

/// Starting estimate of an egress whose capacity nobody declared: Brutal's
/// default uplink, playing the role of cake-autorate's base rate.
pub const DEFAULT_AUTORATE_START_BPS: u64 = 50_000_000;

impl Default for SqmConfig {
    fn default() -> Self {
        SqmConfig {
            bw_min_bps: 100_000,       // 100 kbps
            bw_max_bps: 1_000_000_000, // 1 Gbps
            delay_thr_us: 30_000,
            delay_max_cut_us: 60_000,
            delay_max_raise_us: 10_000,
            wire_packet_bits: 1500 * 8,
            detection_window: 6,
            detection_thr: 3,
            cut_min: 0.98,
            cut_max: 0.62,
            raise_max: 1.10,
            high_load: 0.75,
            return_to_base: 0.005,
            active_thr_bps: 50_000,
            baseline_rise: 0.005,
        }
    }
}

/// One measurement tick for a link direction.
#[derive(Clone, Copy, Debug)]
pub struct SqmSample {
    /// One-way delay for this tick (µs). Only used relative to the baseline, so
    /// a constant clock offset cancels.
    pub owd_us: u64,
    /// Wire bits/s sent this tick in this direction. The estimator, its
    /// `*_bps` outputs, and every caller use bit/s; transport byte/s values
    /// must be converted at their adapter boundary
    /// (`transport_quality::rate::WireBitrate::from_byte_delta_over_micros`).
    pub achieved_bps: u64,
}

/// The current estimate emitted after an update.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SqmEstimate {
    /// Usable-bandwidth estimate (bps).
    pub est_bw_bps: u64,
    /// Current baseline (unloaded) OWD (µs).
    pub baseline_owd_us: u64,
    /// Current bloat: the last active sample minus the baseline (µs).
    pub delta_us: i64,
    /// Headroom = est_bw - achieved (bps), for feed-forward damping.
    pub residual_bps: u64,
    /// Whether bufferbloat or a high load ever moved the estimate: an idle
    /// link keeps the start value, which is a guess, not a measured capacity.
    pub measured: bool,
}

/// Delay-based autorate estimator for one link direction.
#[derive(Clone, Debug)]
pub struct LinkSqmEstimator {
    cfg: SqmConfig,
    baseline_owd_us: Option<f64>,
    est_bw_bps: f64,
    /// What a low load returns the estimate to: the start value, or the
    /// capacity the user declared (`raise_start`).
    base_bps: f64,
    last_achieved_bps: u64,
    last_delta_us: f64,
    /// Delays of the last `detection_window` active samples.
    window: VecDeque<f64>,
    /// Whether bufferbloat ever cut the estimate. Until then a declared
    /// capacity (`raise_start`) may lift it; afterwards the measurement is
    /// the only authority.
    backed_off: bool,
    measured: bool,
}

impl LinkSqmEstimator {
    pub fn new(cfg: SqmConfig) -> Self {
        let start = cfg.bw_min_bps;
        Self::new_with_start(cfg, start)
    }

    /// Same as [`Self::new`], but the estimate starts, and under a low load
    /// returns, at `start_bps` (clamped into `[bw_min_bps, bw_max_bps]`):
    /// cake-autorate's base rate. MP_SQM_PLAN.md S2.5: the caller passes a
    /// capacity it already knows for this link (a configured static ceiling)
    /// or [`DEFAULT_AUTORATE_START_BPS`].
    pub fn new_with_start(cfg: SqmConfig, start_bps: u64) -> Self {
        let start = (start_bps as f64).clamp(cfg.bw_min_bps as f64, cfg.bw_max_bps as f64);
        LinkSqmEstimator {
            window: VecDeque::with_capacity(cfg.detection_window),
            cfg,
            baseline_owd_us: None,
            est_bw_bps: start,
            base_bps: start,
            last_achieved_bps: 0,
            last_delta_us: 0.0,
            backed_off: false,
            measured: false,
        }
    }

    /// `start_bps` is a capacity the user declared for this link (Brutal's
    /// `up_mbps`, Hysteria's "your uplink bandwidth"): it becomes the base a
    /// low load returns to, and lifts a cold estimate to it. Once bufferbloat
    /// has cut the estimate the measurement wins, which is what lets autorate
    /// pull an over-declared Brutal rate down to what the link carries.
    pub fn raise_start(&mut self, start_bps: u64) {
        let start = (start_bps as f64).clamp(self.cfg.bw_min_bps as f64, self.cfg.bw_max_bps as f64);
        self.base_bps = start;
        if !self.backed_off && start > self.est_bw_bps {
            self.est_bw_bps = start;
        }
    }

    fn return_to_base(&mut self) {
        let step = self.cfg.return_to_base;
        if self.est_bw_bps > self.base_bps {
            self.est_bw_bps = (self.est_bw_bps * (1.0 - step)).max(self.base_bps);
        } else if self.est_bw_bps < self.base_bps {
            self.est_bw_bps = (self.est_bw_bps * (1.0 + step)).min(self.base_bps);
        }
    }

    /// Feed one measurement tick and get the updated estimate.
    ///
    /// cake-autorate's rule. Bufferbloat is `detection_thr` of the last
    /// `detection_window` samples delayed past the delay threshold; it cuts
    /// the estimate whatever the load, by more the higher the average delay.
    /// A high load without bufferbloat raises it, by more the lower the
    /// delay. Otherwise it returns towards its base. Every threshold is
    /// compensated for one wire packet's time at the current estimate.
    pub fn update(&mut self, s: SqmSample) -> SqmEstimate {
        let owd = s.owd_us as f64;
        let baseline = match self.baseline_owd_us {
            Some(baseline) if owd >= baseline => {
                baseline + self.cfg.baseline_rise * (owd - baseline)
            }
            _ => owd,
        };
        self.baseline_owd_us = Some(baseline);
        self.last_achieved_bps = s.achieved_bps;

        if s.achieved_bps < self.cfg.active_thr_bps {
            self.window.clear();
            self.last_delta_us = 0.0;
            self.return_to_base();
            return self.estimate();
        }

        let compensation = self.cfg.wire_packet_bits as f64 * 1e6 / self.est_bw_bps;
        let thr = self.cfg.delay_thr_us as f64 + compensation;
        let max_cut = self.cfg.delay_max_cut_us as f64 + compensation;
        let max_raise = self.cfg.delay_max_raise_us as f64 + compensation;

        let delta = owd - baseline;
        self.last_delta_us = delta;
        if self.window.len() == self.cfg.detection_window {
            self.window.pop_front();
        }
        self.window.push_back(delta);
        let delayed = self.window.iter().filter(|d| **d > thr).count();
        // cake-autorate's window is always full; ours is refilling after a
        // cut (below), and its average is over the samples it holds.
        let avg = self.window.iter().sum::<f64>() / self.window.len() as f64;

        if delayed >= self.cfg.detection_thr {
            let severity = if max_cut <= thr {
                1.0
            } else {
                ((avg - thr) / (max_cut - thr)).clamp(0.0, 1.0)
            };
            self.est_bw_bps *= self.cfg.cut_min - severity * (self.cfg.cut_min - self.cfg.cut_max);
            self.backed_off = true;
            self.measured = true;
            // cake-autorate does not cut again within its refractory period,
            // which it sets longer than refilling the detection window with
            // new samples (`bufferbloat_refractory_period_ms`): the delays
            // that caused this cut must not cause the next one too. One
            // sample per tick, so the window starts over.
            self.window.clear();
        } else if s.achieved_bps as f64 > self.cfg.high_load * self.est_bw_bps {
            let room = if thr <= max_raise {
                1.0
            } else {
                ((thr - avg) / (thr - max_raise)).clamp(0.0, 1.0)
            };
            if room > 0.0 {
                self.est_bw_bps *= 1.0 + room * (self.cfg.raise_max - 1.0);
                self.measured = true;
            }
        } else {
            self.return_to_base();
        }

        self.est_bw_bps = self
            .est_bw_bps
            .clamp(self.cfg.bw_min_bps as f64, self.cfg.bw_max_bps as f64);
        self.estimate()
    }

    /// The current estimate without feeding a new sample.
    pub fn estimate(&self) -> SqmEstimate {
        let est = self.est_bw_bps.round().max(0.0) as u64;
        SqmEstimate {
            est_bw_bps: est,
            baseline_owd_us: self.baseline_owd_us.unwrap_or(0.0).round().max(0.0) as u64,
            delta_us: self.last_delta_us.round() as i64,
            residual_bps: est.saturating_sub(self.last_achieved_bps),
            measured: self.measured,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bottleneck of `cap` bit/s with a one-second buffer behind it, fed
    /// for one 500 ms tick: the queue grows by the excess and drains at
    /// `cap`. Returns the queueing delay (µs).
    struct Bottleneck {
        cap: u64,
        queue_bits: f64,
    }

    impl Bottleneck {
        fn new(cap: u64) -> Self {
            Bottleneck { cap, queue_bits: 0.0 }
        }

        fn tick(&mut self, offered: u64) -> u64 {
            let cap = self.cap as f64;
            self.queue_bits = (self.queue_bits + (offered as f64 - cap) * 0.5).clamp(0.0, cap);
            (self.queue_bits / cap * 1e6) as u64
        }
    }

    /// A rate-driven sender sends at the estimate through `link` for `ticks`
    /// ticks; returns the estimate after each tick.
    fn closed_loop(e: &mut LinkSqmEstimator, link: &mut Bottleneck, base_owd: u64, ticks: usize) -> Vec<u64> {
        (0..ticks)
            .map(|_| {
                let offered = e.estimate().est_bw_bps;
                let queue = link.tick(offered);
                e.update(SqmSample { owd_us: base_owd + queue, achieved_bps: offered }).est_bw_bps
            })
            .collect()
    }

    fn mean(values: &[u64]) -> u64 {
        values.iter().sum::<u64>() / values.len() as u64
    }

    /// A cellular uplink: its own delay already swings by up to `noise_us`
    /// at a light load, and the sender is an application sending a fixed
    /// `offered` rate that is far below the 50 Mbps start but above the
    /// link's capacity `cap`, so a queue builds there.
    fn weak_uplink(e: &mut LinkSqmEstimator, cap: u64, offered: u64, noise_us: u64, ticks: usize) {
        let mut link = Bottleneck::new(cap);
        let mut seed = 1u64;
        for _ in 0..ticks {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let noise = (seed >> 11) % noise_us.max(1);
            // The sender here ignores the estimate (the worst case: the cut
            // must come from the delay alone, not from the sender obeying).
            let queue = link.tick(offered);
            e.update(SqmSample { owd_us: 55_000 + queue + noise, achieved_bps: offered });
        }
    }

    /// The field failure: a 50 Mbps start, an application sending 2 Mbps
    /// into a 1 Mbps cellular uplink. Nothing like 37.5 Mbps is ever sent,
    /// yet the queue is ours and the estimate must come down and be reported
    /// as measured.
    #[test]
    fn a_queue_at_a_light_load_brings_the_start_value_down() {
        let mut e = LinkSqmEstimator::new_with_start(SqmConfig::default(), DEFAULT_AUTORATE_START_BPS);
        e.update(SqmSample { owd_us: 55_000, achieved_bps: 0 });
        weak_uplink(&mut e, 1_000_000, 2_000_000, 20_000, 40);
        let est = e.estimate();
        assert!(est.measured, "{est:?}");
        assert!(est.est_bw_bps < DEFAULT_AUTORATE_START_BPS / 4, "{est:?}");
    }

    #[test]
    fn probes_up_on_headroom() {
        let mut e = LinkSqmEstimator::new(SqmConfig::default());
        let mut last = 0;
        for _ in 0..10 {
            // we saturate our own estimate, low delay
            let offered = e.estimate().est_bw_bps;
            let est = e.update(SqmSample { owd_us: 20_000, achieved_bps: offered });
            assert!(est.est_bw_bps >= last, "est should not shrink with headroom");
            last = est.est_bw_bps;
        }
        assert!(last > SqmConfig::default().bw_min_bps, "est must grow");
    }

    /// An idle link keeps the start value, which is reported as unmeasured.
    #[test]
    fn the_start_value_is_unmeasured_until_load_moves_it() {
        let mut e = LinkSqmEstimator::new_with_start(SqmConfig::default(), DEFAULT_AUTORATE_START_BPS);
        for _ in 0..20 {
            let est = e.update(SqmSample { owd_us: 20_000, achieved_bps: 30_000 });
            assert!(!est.measured);
            assert_eq!(est.est_bw_bps, DEFAULT_AUTORATE_START_BPS);
        }
        let est = e.update(SqmSample { owd_us: 20_000, achieved_bps: DEFAULT_AUTORATE_START_BPS });
        assert!(est.measured, "saturating the estimate without bloat probes up");
    }

    #[test]
    fn backs_off_on_bloat() {
        let mut e = LinkSqmEstimator::new_with_start(SqmConfig::default(), 20_000_000);
        for _ in 0..5 {
            e.update(SqmSample { owd_us: 20_000, achieved_bps: 10_000_000 });
        }
        let before = e.estimate().est_bw_bps;
        for _ in 0..10 {
            e.update(SqmSample { owd_us: 60_000, achieved_bps: 20_000_000 });
        }
        assert!(e.estimate().est_bw_bps < before, "est must shrink under bloat: {:?}", e.estimate());
    }

    /// Bufferbloat cuts the estimate whatever the load: a sender far below
    /// the estimate still fills a link that is far slower than it.
    #[test]
    fn bloat_at_a_low_load_still_cuts() {
        let mut e = LinkSqmEstimator::new_with_start(SqmConfig::default(), DEFAULT_AUTORATE_START_BPS);
        e.update(SqmSample { owd_us: 80_000, achieved_bps: 0 });
        for _ in 0..20 {
            e.update(SqmSample { owd_us: 180_000, achieved_bps: 300_000 });
        }
        let est = e.estimate();
        assert!(est.measured, "{est:?}");
        assert!(est.est_bw_bps < DEFAULT_AUTORATE_START_BPS / 10, "{est:?}");
    }

    /// One or two delayed samples are not bufferbloat.
    #[test]
    fn a_short_delay_spike_does_not_cut() {
        let mut e = LinkSqmEstimator::new_with_start(SqmConfig::default(), DEFAULT_AUTORATE_START_BPS);
        e.update(SqmSample { owd_us: 20_000, achieved_bps: 0 });
        for _ in 0..2 {
            e.update(SqmSample { owd_us: 120_000, achieved_bps: 1_000_000 });
        }
        for _ in 0..20 {
            e.update(SqmSample { owd_us: 20_000, achieved_bps: 1_000_000 });
        }
        let est = e.estimate();
        assert_eq!(est.est_bw_bps, DEFAULT_AUTORATE_START_BPS);
        assert!(!est.measured);
    }

    /// Below `active_thr_bps` the delay is not sampled: the round trips it
    /// comes from are not being measured.
    #[test]
    fn bloat_on_a_nearly_idle_link_holds_the_estimate() {
        let mut e = LinkSqmEstimator::new_with_start(SqmConfig::default(), DEFAULT_AUTORATE_START_BPS);
        e.update(SqmSample { owd_us: 80_000, achieved_bps: 0 });
        for _ in 0..30 {
            e.update(SqmSample { owd_us: 1_300_000, achieved_bps: 10_000 });
        }
        let est = e.estimate();
        assert_eq!(est.est_bw_bps, DEFAULT_AUTORATE_START_BPS);
        assert!(!est.measured);
    }

    /// cake-autorate's `set_shaper_rates` compensation: at 200 kbit/s one
    /// 1500-byte packet takes 60 ms on the wire, so a 70 ms queue is one or
    /// two packets, not bufferbloat, and a fully loaded link keeps probing up.
    /// Without the compensation the 30 ms threshold would cut it to the floor.
    #[test]
    fn one_packet_of_serialization_at_a_low_rate_is_not_bloat() {
        let mut e = LinkSqmEstimator::new_with_start(SqmConfig::default(), 200_000);
        e.update(SqmSample { owd_us: 50_000, achieved_bps: 0 });
        for _ in 0..20 {
            let offered = e.estimate().est_bw_bps;
            e.update(SqmSample { owd_us: 50_000 + 70_000, achieved_bps: offered });
        }
        let est = e.estimate();
        assert!(est.est_bw_bps >= 200_000, "{est:?}");
    }

    /// A sender at the estimate converges near the link's capacity.
    #[test]
    fn converges_near_capacity() {
        let cap = 50_000_000;
        let mut e = LinkSqmEstimator::new(SqmConfig::default());
        e.update(SqmSample { owd_us: 20_000, achieved_bps: 0 });
        let history = closed_loop(&mut e, &mut Bottleneck::new(cap), 20_000, 800);
        let tail = mean(&history[600..]);
        assert!((cap * 7 / 10..=cap * 12 / 10).contains(&tail), "mean {tail} not near capacity {cap}");
    }

    /// The weak-link case: the 50 Mbps start over a 2 Mbps or a 0.3 Mbps
    /// link. One cut per three ticks of fresh delay brings the estimate to
    /// the link within 10 or 16 s, and it then stays around its capacity.
    #[test]
    fn a_rate_driven_sender_comes_down_to_a_slow_link() {
        for (cap, max_ticks) in [(2_000_000u64, 20usize), (300_000, 32)] {
            let mut e = LinkSqmEstimator::new_with_start(SqmConfig::default(), DEFAULT_AUTORATE_START_BPS);
            e.update(SqmSample { owd_us: 80_000, achieved_bps: 0 });
            let history = closed_loop(&mut e, &mut Bottleneck::new(cap), 80_000, 300);
            let reached = history.iter().position(|est| *est <= cap * 2);
            assert!(reached.is_some_and(|tick| tick < max_ticks), "cap {cap}: {:?}", &history[..20]);
            assert!(e.estimate().measured);
            let tail = mean(&history[60..]);
            assert!((cap * 7 / 10..=cap * 12 / 10).contains(&tail), "cap {cap}: mean {tail}");
        }
    }

    /// MP_SQM_PLAN.md S2.5 RED requirement: "autorate 在带宽阶跃下降后 5 s 内
    /// 估计值跟随下降". One tick is one `EgressHandle::publish_sample` call at
    /// the 500 ms control interval, so 5 s is 10 ticks.
    #[test]
    fn autorate_estimate_measurably_decreases_within_5s_of_a_capacity_step_down() {
        let mut e = LinkSqmEstimator::new(SqmConfig::default());
        e.update(SqmSample { owd_us: 20_000, achieved_bps: 0 });
        let mut link = Bottleneck::new(50_000_000);
        closed_loop(&mut e, &mut link, 20_000, 800);
        let before = e.estimate().est_bw_bps;
        link.cap = 10_000_000;
        assert!(before > link.cap, "sanity: must start above the new capacity, got {before}");
        closed_loop(&mut e, &mut link, 20_000, 10);
        let after = e.estimate().est_bw_bps;
        assert!(after < before, "estimate must decrease within 5s: {after} !< {before}");
    }

    #[test]
    fn residual_is_headroom() {
        let mut e = LinkSqmEstimator::new_with_start(SqmConfig::default(), 10_000_000);
        for _ in 0..30 {
            let offered = e.estimate().est_bw_bps;
            // use only half of the estimate → residual ~ half
            e.update(SqmSample { owd_us: 20_000, achieved_bps: offered / 2 });
        }
        assert!(e.estimate().residual_bps > 0, "residual should be positive with headroom");
    }

    /// A low estimate follows a link that later carries more without a
    /// queue building, though its delay never settles.
    #[test]
    fn a_low_estimate_follows_a_link_that_carries_more() {
        let mut e = LinkSqmEstimator::new_with_start(SqmConfig::default(), DEFAULT_AUTORATE_START_BPS);
        e.update(SqmSample { owd_us: 80_000, achieved_bps: 0 });
        for _ in 0..15 {
            e.update(SqmSample { owd_us: 180_000, achieved_bps: 2_000_000 });
        }
        assert!(e.estimate().est_bw_bps <= 5_000_000, "{:?}", e.estimate());
        for i in 0..40u64 {
            let owd = e.estimate().baseline_owd_us + 3_000 + (i % 2) * 1_000;
            e.update(SqmSample { owd_us: owd, achieved_bps: 6_000_000 });
        }
        assert!(e.estimate().est_bw_bps >= 6_000_000, "{:?}", e.estimate());
    }

    /// `new_with_start` seeds the estimate (MP_SQM_PLAN.md S2.5: "autorate.rs
    /// 起点改为出口上限"), clamped into `[bw_min_bps, bw_max_bps]`.
    #[test]
    fn new_with_start_seeds_the_estimate_instead_of_cold_starting_at_bw_min() {
        let cfg = SqmConfig::default();
        let seeded = LinkSqmEstimator::new_with_start(cfg.clone(), 80_000_000);
        assert_eq!(seeded.estimate().est_bw_bps, 80_000_000);
        let too_low = LinkSqmEstimator::new_with_start(cfg.clone(), 1);
        assert_eq!(too_low.estimate().est_bw_bps, cfg.bw_min_bps);
        let too_high = LinkSqmEstimator::new_with_start(cfg.clone(), u64::MAX);
        assert_eq!(too_high.estimate().est_bw_bps, cfg.bw_max_bps);
    }

    /// A declared capacity lifts a cold estimate, never lowers one, and stops
    /// lifting it once bufferbloat has cut it; a low load then returns the
    /// estimate towards the declared rate.
    #[test]
    fn raise_start_lifts_a_cold_estimate_until_the_link_backs_it_off() {
        let mut e = LinkSqmEstimator::new(SqmConfig::default());
        e.raise_start(50_000_000);
        assert_eq!(e.estimate().est_bw_bps, 50_000_000);
        e.raise_start(20_000_000);
        assert_eq!(e.estimate().est_bw_bps, 50_000_000, "a hint never lowers the estimate");

        e.raise_start(50_000_000);
        e.update(SqmSample { owd_us: 1_000, achieved_bps: 50_000_000 });
        for _ in 0..6 {
            e.update(SqmSample { owd_us: 100_000, achieved_bps: 50_000_000 });
        }
        let backed_off = e.estimate().est_bw_bps;
        assert!(backed_off < 50_000_000, "bloat must cut the estimate, got {backed_off}");
        e.raise_start(50_000_000);
        assert_eq!(e.estimate().est_bw_bps, backed_off);

        e.update(SqmSample { owd_us: 1_000, achieved_bps: 0 });
        assert!(e.estimate().est_bw_bps > backed_off, "an idle link returns towards the base");
    }
}

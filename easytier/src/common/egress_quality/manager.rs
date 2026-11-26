//! Per-physical-egress quality manager (MP_SQM_PLAN.md §4.3, CAKE_SQM_PLAN.md).
//!
//! One [`EgressQualityManager`] belongs to exactly one `GlobalCtx`. It owns
//! exactly one [`LinkSqmEstimator`] and one rate per distinct
//! [`EgressScope`] (`stable_id` + `direction` + `generation`), so any number
//! of sessions/subflows that resolve to the same physical egress share one
//! entry. The send path attaches the egress's single CAKE queue to that
//! entry (`EgressHandle::attached`) and shapes it to `shaping_rate()`.
//!
//! Registry shape mirrors `common::token_bucket::TokenBucketManager`:
//! `DashMap<Key, Arc<T>>` plus `get_or_create`.
//!
//! `common::egress_quality` intentionally has no dependency on
//! `tunnel::mpquic::PathKey` or `connector::mp_path::ResourceGroupId`: every
//! public method here takes/returns only `common::transport_quality` pure
//! types plus `common::egress_inventory::EgressStableId`. `connector::mp_session`
//! is responsible for translating its own path/resource keys into an
//! `EgressScope` at the call site.
//!
//! MP_SQM_PLAN.md S1.1 removed this manager's `EgressAllocator` (it
//! duplicated `connector::mp_optimizer::solve_resource_max_flow` and had no
//! production caller) and `budget_max_age`/`WireBudget::observed_age`
//! (nothing ever let a budget go stale before the next tick, so the `Stale`
//! disposition they fed could never actually trigger).

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;
use tokio_util::task::AbortOnDropHandle;

use crate::common::egress_inventory::EgressStableId;
use crate::common::transport_quality::{
    budget::{EgressDirection, EgressScope},
    rate::WireBitrate,
};

use super::autorate::{
    DEFAULT_AUTORATE_START_BPS, LinkSqmEstimator, SqmConfig, SqmEstimate, SqmSample,
};

#[derive(Clone, Debug)]
pub struct EgressQualityConfig {
    pub estimator: SqmConfig,
    /// Minimal static pre-send ceiling (MP_SQM_PLAN.md §4.4 (b) prelude to
    /// the full §5.2 `TransportQualityConfig` API/CLI/GUI). `None` means no
    /// static ceiling: a freshly-created scope starts `NativeOnly` and stays
    /// that way until something else (the MP control tick's autorate
    /// estimator, or a future RPC) publishes a dynamic budget. `Some(c)` is
    /// an upper bound applied at every scope this config produces -- see
    /// `ScopeEntry::new`, `EgressHandle::set_budget`,
    /// `EgressHandle::publish_sample`. This exists specifically so a
    /// non-MP-managed `mpquic://` connection (which nothing ever calls
    /// `publish_sample` for) still has a real, non-inert budget source.
    pub static_wire_ceiling: Option<WireBitrate>,
}

impl Default for EgressQualityConfig {
    fn default() -> Self {
        Self {
            estimator: SqmConfig::default(),
            static_wire_ceiling: None,
        }
    }
}

/// `requested` clamped down to `ceiling` if one is configured, never allowed
/// to exceed it. `None` (no dynamic decision) with a configured ceiling
/// becomes `Some(ceiling)` rather than staying `NativeOnly` -- once an
/// operator has set a static ceiling, nothing routed through this scope may
/// go unmetered, including the "nobody has published a dynamic budget yet"
/// case that a non-MP-managed connection sits in forever.
fn clamp_to_static_ceiling(
    requested: Option<WireBitrate>,
    ceiling: Option<WireBitrate>,
) -> Option<WireBitrate> {
    match (requested, ceiling) {
        (requested, None) => requested,
        (None, Some(ceiling)) => Some(ceiling),
        (Some(requested), Some(ceiling)) => Some(WireBitrate(requested.0.min(ceiling.0))),
    }
}

/// MP_SQM_PLAN.md S2.6/§9: clamp the autorate estimator's raw output to
/// `MpSqmConfig.autorate_min_bps`/`autorate_max_bps`. `0` means "no bound"
/// for either side, matching the proto convention `common/config.rs::
/// validate_mp_config` already enforces (and that same validation already
/// guarantees `min <= max` whenever both are set, so this never has to
/// choose between a conflicting floor and ceiling). Applied at every point
/// the raw estimate is *read* (status reporting, enforcement), not at the
/// point it's stored -- storing the clamped value instead would make a
/// later bounds change (a live `set_config`) stuck re-clamping an
/// already-clamped number instead of the real raw estimate.
fn clamp_autorate_estimate_bps(estimate_bps: u64, min_bps: u64, max_bps: u64) -> u64 {
    let floored = if min_bps > 0 { estimate_bps.max(min_bps) } else { estimate_bps };
    if max_bps > 0 { floored.min(max_bps) } else { floored }
}

/// Where a scope's currently-effective ceiling comes from
/// (MP_SQM_PLAN.md §9 `MpEgressResourceStatus.ceiling_source`'s
/// none|static|per_device|autorate convention). The static policy
/// (`ceiling_info_for`) only ever yields the first three; `Autorate` is what
/// status reporting shows once the Autorate estimate is below that policy
/// and so is what actually holds the scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CeilingSource {
    None,
    Static,
    PerDevice,
    Autorate,
}

impl CeilingSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            CeilingSource::None => "none",
            CeilingSource::Static => "static",
            CeilingSource::PerDevice => "per_device",
            CeilingSource::Autorate => "autorate",
        }
    }
}

/// A scope's currently-configured ceiling and which policy produced it.
/// MP_SQM_PLAN.md S2.1 GUI status reporting reads this via
/// [`EgressQualityManager::ceiling_info_for`]; it is deliberately about
/// *policy* (what `set_static_ceiling` was last told), not about whatever
/// value a governor happens to have refilled to right now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CeilingInfo {
    pub ceiling_bps: Option<WireBitrate>,
    pub source: CeilingSource,
}

/// The manager's live, mutable ceiling policy: a global fallback plus
/// per-device overrides, keyed by the same [`EgressStableId`] every
/// [`EgressScope`] already carries (MP_SQM_PLAN.md S2.1's per-NIC
/// `MpConfig.egress_limits`, resolved from interface *names* to stable ids
/// by the caller -- see `instance::instance::reapply_egress_ceiling` -- so
/// this module keeps its existing no-`EgressInventory`-dependency rule).
/// Shared (via `Arc<Mutex<_>>`) between the manager and every `ScopeEntry`
/// it has ever handed out, so a live policy change is visible to every
/// existing scope on its very next `set_budget`/`publish_sample` call with
/// zero per-scope bookkeeping to keep in sync, and can also be pushed
/// immediately by `set_static_ceiling` itself (MP_SQM_PLAN.md S2.1's "对全部
/// 现存scope生效": a scope nothing ever calls `publish_sample`/`set_budget`
/// for again must not have to wait for a call that may never come).
#[derive(Default)]
struct CeilingState {
    global: Option<WireBitrate>,
    per_device: HashMap<EgressStableId, WireBitrate>,
    /// MP_SQM_PLAN.md S2.6 (`MpSqmConfig.autorate_min_bps`/`autorate_max_bps`):
    /// bounds on the autorate estimator's own output, applied in
    /// [`clamp_autorate_estimate_bps`] before the result ever reaches the
    /// static-ceiling clamp below. `0` means unset, same convention as the
    /// proto fields themselves (`common/config.rs::validate_mp_config`
    /// already guarantees `min <= max` whenever both are nonzero). Distinct
    /// from `global`/`per_device`: those represent real link-capacity truth
    /// and must always win as the final hard cap; these are an operator's
    /// manual floor/ceiling on the *estimate*, so they are applied first,
    /// with the static ceiling still clamping the result afterward.
    autorate_min_bps: u64,
    autorate_max_bps: u64,
    /// `MpSqmConfig.target_ms`/`interval_ms`: CAKE's `target` and `rtt`; `0`
    /// means CAKE's own default.
    cake_target_ms: u32,
    cake_interval_ms: u32,
}

/// CAKE's defaults (`tc qdisc ... cake`): target 5 ms, interval ("rtt") 100 ms.
pub const CAKE_DEFAULT_TARGET: Duration = Duration::from_millis(5);
pub const CAKE_DEFAULT_INTERVAL: Duration = Duration::from_millis(100);

impl CeilingState {
    fn cake_timing(&self) -> (Duration, Duration) {
        let pick = |ms: u32, default: Duration| {
            if ms == 0 { default } else { Duration::from_millis(ms as u64) }
        };
        (
            pick(self.cake_target_ms, CAKE_DEFAULT_TARGET),
            pick(self.cake_interval_ms, CAKE_DEFAULT_INTERVAL),
        )
    }

    fn info_for(&self, stable_id: &EgressStableId) -> CeilingInfo {
        if let Some(bps) = self.per_device.get(stable_id) {
            CeilingInfo {
                ceiling_bps: Some(*bps),
                source: CeilingSource::PerDevice,
            }
        } else if let Some(bps) = self.global {
            CeilingInfo {
                ceiling_bps: Some(bps),
                source: CeilingSource::Static,
            }
        } else {
            CeilingInfo {
                ceiling_bps: None,
                source: CeilingSource::None,
            }
        }
    }

    /// An autorate estimate as enforcement applies it: first within the
    /// user's `autorate_min_bps`/`autorate_max_bps` (the requested rate),
    /// then under the scope's static ceiling (the wire budget) -- the order
    /// the field docs above explain.
    fn bound_autorate(
        &self,
        stable_id: &EgressStableId,
        estimate_bps: u64,
    ) -> (WireBitrate, Option<WireBitrate>) {
        let requested = WireBitrate(clamp_autorate_estimate_bps(
            estimate_bps,
            self.autorate_min_bps,
            self.autorate_max_bps,
        ));
        let wire_bps = clamp_to_static_ceiling(Some(requested), self.info_for(stable_id).ceiling_bps);
        (requested, wire_bps)
    }
}

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum EgressQualityError {
    /// The physical interface behind this handle's `EgressScope` was
    /// replaced by a new generation (removed/re-added, or a snapshot
    /// reconcile bumped its generation counter). This handle — and any
    /// permit, sample, or demand id minted from it — must never be honored
    /// again; the caller must re-resolve a fresh `EgressHandle`.
    #[error("this egress handle's generation has been retired")]
    Invalidated,
}

/// How long without a one-way delay sample the estimator is held, once this
/// egress has had one, and not fed the round trip (OWD_AUTORATE_PLAN.md 1.2;
/// RFC 6817 Section 2.5: no sample, no update). The round trip contains the
/// peer's queue for our ACKs, which is the very thing the one-way delay is
/// there to leave out (Section 3.1), so it is only for an egress whose peers
/// never sent one. The bound is for a peer that really stopped answering
/// (restarted without the capability, path gone): probes are due every
/// 100 ms while data flows and every second otherwise, and expire after 2 s
/// (`tunnel::mpquic::owd`), so 30 s is fifteen expiry periods with nothing
/// reported, long past any queue; after it the estimator goes on with the
/// round trip, as for a peer without the capability.
pub const OWD_HOLD: Duration = Duration::from_secs(30);

/// Where the delay an Autorate tick was fed came from
/// (`MpEgressResourceStatus.queue_delay_source`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueDelaySource {
    /// The third smallest (the smallest if fewer) of the public reflectors'
    /// upstream delays and the peer's one-way delay
    /// (`common::egress_quality::reflectors`; sqm-autorate
    /// `ratecontroller_ewma.lua:241-245`).
    Reflectors,
    /// Measured one way, in the data direction (`tunnel::mpquic::owd`).
    OneWay,
    /// QUIC's round trip less this egress's own queue: the peer sends no
    /// one-way delay.
    RoundTrip,
    /// No usable sample this tick: the estimator was not updated.
    Held,
}

impl QueueDelaySource {
    pub fn as_str(self) -> &'static str {
        match self {
            QueueDelaySource::Reflectors => "reflectors",
            QueueDelaySource::OneWay => "one-way",
            QueueDelaySource::RoundTrip => "round-trip",
            QueueDelaySource::Held => "held",
        }
    }
}

/// What one Autorate tick did ([`EgressHandle::publish`]).
#[derive(Clone, Copy, Debug)]
pub struct PublishedSample {
    pub estimate: SqmEstimate,
    pub source: QueueDelaySource,
    /// The queueing delay fed to the estimator; the previous one when held.
    pub queue_delay_us: u64,
    /// Public reflectors that took part in this tick's delay.
    pub reflector_count: u32,
}

struct ScopeState {
    /// The rate this egress is held to (wire bits/s): the autorate estimate
    /// within the user's bounds and under the static ceiling, or the static
    /// ceiling alone before the first estimate. `None` only while neither
    /// exists; [`EgressHandle::shaping_rate`] then falls back to the
    /// estimator's start value.
    budget: Option<WireBitrate>,
    estimator: LinkSqmEstimator,
    /// Last value passed to `set_budget`, or derived from the estimator via
    /// `publish_sample`, BEFORE any ceiling clamp is applied. Kept so a live
    /// ceiling change (`EgressQualityManager::set_static_ceiling`,
    /// MP_SQM_PLAN.md S2.1) can re-derive the correctly-clamped budget
    /// immediately, instead of either blindly overwriting whatever the
    /// estimator most recently decided (wrong if that decision was already
    /// *below* the new ceiling) or waiting for the next tick.
    last_requested_wire_bps: Option<WireBitrate>,
    /// The autorate estimator's most recent output before any bound or
    /// ceiling (MP_SQM_PLAN.md S2.5's `MpEgressResourceStatus.
    /// autorate_estimate_bps`), unlike `last_requested_wire_bps`.
    last_autorate_estimate_bps: Option<WireBitrate>,
    /// Time packets waited in this egress's own queue since the last sample
    /// (total µs, packets); see `record_queue_delay`.
    own_queue_delay: (u64, u64),
    /// The average of the last sample that had sends to average: what a
    /// sample with none since takes out. Every session samples its egress,
    /// so a scope gets several samples a period and only the first finds
    /// the period's sends; the round trips the others carry still hold that
    /// wait (no new packet, no new round trip).
    own_queue_delay_us: u64,
    /// The smallest one-way queueing delay reported since the last sample
    /// (OWD_AUTORATE_PLAN.md 1.2); see `record_owd_queue`.
    owd_min_us: Option<u64>,
    /// Each public reflector's smallest upstream delay (µs) in the tick, from
    /// `common::egress_quality::reflectors`; see `record_reflector_deltas`.
    reflector_deltas: Vec<u64>,
    /// When a one-way sample last arrived.
    last_owd_at: Option<Instant>,
    /// The queueing delay the last update was fed.
    last_queue_delay_us: u64,
}

struct ScopeEntry {
    scope: EgressScope,
    invalidated: AtomicBool,
    state: Mutex<ScopeState>,
    /// Shared with `EgressQualityManager` (same `Arc`, not a per-scope
    /// snapshot): see `CeilingState`'s own doc for why. `burst_bytes`/
    /// `control_reserve_bytes` remain baked in from `EgressQualityConfig` at
    /// construction (never live-changeable), unlike this.
    ceiling_state: Arc<Mutex<CeilingState>>,
    /// State a send path keeps per egress next to its ledger (the mpquic
    /// egress queue), typed by the send path itself so this module stays
    /// unaware of it. Lives exactly as long as the ledger it belongs to.
    attached: std::sync::OnceLock<Arc<dyn std::any::Any + Send + Sync>>,
}

impl ScopeEntry {
    fn new(
        scope: EgressScope,
        config: &EgressQualityConfig,
        ceiling_state: Arc<Mutex<CeilingState>>,
    ) -> Self {
        // A configured static ceiling applies from the moment this scope is
        // created, not only once something later calls `set_budget`/
        // `publish_sample`: a non-MP-managed `mpquic://` connection never
        // gets a `publish_sample` call at all (nothing runs its control
        // tick), so without this a static ceiling would only ever reach
        // scopes an MP session happens to also be driving. Reads whatever
        // the manager's ceiling policy is *right now* (global or a
        // per-device override for this exact stable_id), not a config-time
        // constant: a scope created after a live `set_static_ceiling` call
        // must start governed by the new policy, not the manager's original
        // construction-time value.
        let initial_ceiling = ceiling_state.lock().unwrap().info_for(&scope.stable_id).ceiling_bps;
        // MP_SQM_PLAN.md S2.5: start the autorate climb at the already-known
        // static/per-device ceiling instead of always cold-starting at 1
        // Mbps -- when a ceiling is configured, re-discovering a bound
        // that's already known is pure wasted convergence time. No ceiling
        // configured: start at DEFAULT_AUTORATE_START_BPS (the same 50 Mbps
        // Brutal assumes for an undeclared uplink); bloat under our own load
        // pulls it down from there.
        let estimator = LinkSqmEstimator::new_with_start(
            config.estimator.clone(),
            initial_ceiling.map_or(DEFAULT_AUTORATE_START_BPS, |WireBitrate(bps)| bps),
        );
        Self {
            scope,
            invalidated: AtomicBool::new(false),
            state: Mutex::new(ScopeState {
                budget: initial_ceiling,
                estimator,
                last_requested_wire_bps: None,
                last_autorate_estimate_bps: None,
                own_queue_delay: (0, 0),
                own_queue_delay_us: 0,
                owd_min_us: None,
                reflector_deltas: Vec::new(),
                last_owd_at: None,
                last_queue_delay_us: 0,
            }),
            ceiling_state,
            attached: std::sync::OnceLock::new(),
        }
    }
}

/// A cheap-to-clone reference to one physical egress's shared quality state.
/// Every `EgressHandle` obtained for an equal `EgressScope` (same
/// `stable_id`/`direction`/`generation`) wraps the *same* underlying entry:
/// a rate published through one is immediately visible to every other holder.
#[derive(Clone)]
pub struct EgressHandle {
    entry: Arc<ScopeEntry>,
}

impl EgressHandle {
    pub fn scope(&self) -> &EgressScope {
        &self.entry.scope
    }

    /// `false` once the manager has observed this scope's physical interface
    /// move to a new generation. An invalidated handle rejects every
    /// operation instead of silently continuing to grant permits against a
    /// retired interface.
    pub fn is_valid(&self) -> bool {
        !self.entry.invalidated.load(Ordering::SeqCst)
    }

    /// Two handles denote the same shared ledger iff they were resolved from
    /// the same `EgressScope`. Exposed so callers/tests can assert the "one
    /// physical egress, one ledger" property without reaching into private
    /// fields.
    pub fn shares_ledger_with(&self, other: &EgressHandle) -> bool {
        Arc::ptr_eq(&self.entry, &other.entry)
    }

    fn guard(&self) -> Result<std::sync::MutexGuard<'_, ScopeState>, EgressQualityError> {
        if !self.is_valid() {
            return Err(EgressQualityError::Invalidated);
        }
        Ok(self.entry.state.lock().unwrap())
    }

    /// Directly set the wire-bps ceiling for this scope, bypassing the
    /// autorate estimator. This is the external-override injection point:
    /// config/RPC/tests can force a specific low budget (MP_SQM_PLAN.md §3.1's
    /// S1 exit bar needs to be able to set the budget far below link capacity
    /// and then check convergence), independent of any estimator sampling.
    pub fn set_budget(
        &self,
        wire_bps: Option<WireBitrate>,
    ) -> Result<(), EgressQualityError> {
        let mut state = self.guard()?;
        state.last_requested_wire_bps = wire_bps;
        // A configured static ceiling is a hard upper bound regardless of
        // caller: this is the same external-override entry point tests use
        // to force a value, and letting it bypass the ceiling would make
        // "static ceiling" a ceiling in name only. Read live, not a
        // construction-time snapshot -- see `CeilingState`'s doc.
        let ceiling = self
            .entry
            .ceiling_state
            .lock()
            .unwrap()
            .info_for(&self.entry.scope.stable_id)
            .ceiling_bps;
        state.budget = clamp_to_static_ceiling(wire_bps, ceiling);
        Ok(())
    }

    /// Feed one autorate measurement tick. The estimate, within the user's
    /// bounds and under the static ceiling, becomes this scope's budget:
    /// shaping to Autorate is always on (2026-10-10, user decision), so the
    /// backlog sits in our own egress queue (`tunnel::mpquic::egress_cake`)
    /// instead of the modem's. It is also recorded for status reporting
    /// (`autorate_estimate`). The estimator never sends a packet itself
    /// (MP_SQM_PLAN.md §4.3).
    pub fn publish_sample(&self, sample: SqmSample) -> Result<SqmEstimate, EgressQualityError> {
        self.publish(sample.achieved_bps, Some(sample.owd_us))
            .map(|published| published.estimate)
    }

    /// Feed one autorate tick (OWD_AUTORATE_PLAN.md 1.2). `round_trip_us` is
    /// the fallback delay (`SqmSample::owd_us`'s convention), or `None` when
    /// no path gives a fresh round trip. The delay comes, in this order, from:
    ///
    /// 1. the one-way samples since the last tick (`record_owd_queue`): the
    ///    smallest, which is what every session sharing this egress sees. The
    ///    egress's own queue is not taken out: the sample left after it.
    /// 2. nothing, if one arrived less than `OWD_HOLD` ago: no sample, no
    ///    update (RFC 6817 Section 2.5), the estimate stays.
    /// 3. the round trip less this egress's own queue, if any: only for an
    ///    egress that never had a one-way sample, or none for `OWD_HOLD`.
    pub fn publish(
        &self,
        achieved_bps: u64,
        round_trip_us: Option<u64>,
    ) -> Result<PublishedSample, EgressQualityError> {
        self.publish_at(achieved_bps, round_trip_us, Instant::now())
    }

    /// `publish` at a given time.
    pub fn publish_at(
        &self,
        achieved_bps: u64,
        round_trip_us: Option<u64>,
        now: Instant,
    ) -> Result<PublishedSample, EgressQualityError> {
        let mut state = self.guard()?;
        // The round trips include the time a packet waited in this egress's
        // own queue after QUIC sent it. That wait is our shaper's, not the
        // link's: left in, enforcing a rate would read as bufferbloat and cut
        // the rate further, round after round. cake-autorate never sees
        // cake's own backlog either (its pings are a sparse flow cake serves
        // first). Taken every tick, used only for the round trip.
        let (total_us, packets) = std::mem::take(&mut state.own_queue_delay);
        if let Some(average) = total_us.checked_div(packets) {
            state.own_queue_delay_us = average;
        }
        let own_delay_us = state.own_queue_delay_us;
        let peer_queue_us = state.owd_min_us.take();
        let mut delays = std::mem::take(&mut state.reflector_deltas);
        let reflector_count = delays.len() as u32;
        let (source, owd_us) = if !delays.is_empty() {
            // The lower median of the reflectors' delays, with the peer's
            // one-way delay as one more. sqm-autorate takes the fixed third
            // smallest (`ratecontroller_ewma.lua:241-245`), which is the median
            // of its default five reflectors; with only two reflectors left
            // plus the peer it would be the largest and let the far peer alone
            // cut the rate again (incident 2026-10-26). The lower median is the
            // same at five and never lets a minority move the result.
            delays.extend(peer_queue_us);
            delays.sort_unstable();
            let queuing_us = delays[(delays.len() - 1) / 2];
            state.last_owd_at = Some(now);
            (QueueDelaySource::Reflectors, queuing_us.saturating_add(1))
        } else if let Some(queuing_us) = peer_queue_us {
            (QueueDelaySource::OneWay, queuing_us.saturating_add(1))
        } else if state
            .last_owd_at
            .is_some_and(|at| now.saturating_duration_since(at) <= OWD_HOLD)
        {
            (QueueDelaySource::Held, 0)
        } else if let Some(round_trip_us) = round_trip_us {
            (
                QueueDelaySource::RoundTrip,
                round_trip_us.saturating_sub(own_delay_us).max(1),
            )
        } else {
            (QueueDelaySource::Held, 0)
        };
        if source == QueueDelaySource::Held {
            return Ok(PublishedSample {
                estimate: state.estimator.estimate(),
                source,
                queue_delay_us: state.last_queue_delay_us,
                reflector_count: 0,
            });
        }
        state.last_queue_delay_us = owd_us.saturating_sub(1);
        let estimate = state.estimator.update(SqmSample {
            owd_us,
            achieved_bps,
        });
        state.last_autorate_estimate_bps = Some(WireBitrate(estimate.est_bw_bps));
        // MP_SQM_PLAN.md S2.6: `autorate_min_bps`/`autorate_max_bps` bound the
        // estimate itself before it ever reaches the static ceiling. The
        // static ceiling is a ceiling on top of the estimator, not an
        // alternative to it: the estimator can adapt *down* from it (a
        // congested/slow link), it just can never publish a budget *above*
        // it. Read live, not a construction-time snapshot -- see
        // `CeilingState`'s doc.
        let (requested, wire_bps) = self
            .entry
            .ceiling_state
            .lock()
            .unwrap()
            .bound_autorate(&self.entry.scope.stable_id, estimate.est_bw_bps);
        state.last_requested_wire_bps = Some(requested);
        state.budget = wire_bps;
        Ok(PublishedSample {
            estimate,
            source,
            queue_delay_us: state.last_queue_delay_us,
            reflector_count,
        })
    }

    /// The public reflectors' upstream delays (µs) for the next tick, one per
    /// reflector that answered since the last one. `publish` consumes them.
    pub fn record_reflector_deltas(&self, deltas: Vec<u64>) {
        self.entry.state.lock().unwrap().reflector_deltas = deltas;
    }

    /// The one-way queueing delay of a probe that crossed this egress
    /// (`tunnel::mpquic::owd`): its one-way delay less the base. Several
    /// sessions share an egress, and only a delay they all see is the
    /// egress's own, so the smallest since the last tick is kept
    /// (cake-autorate's reflectors likewise).
    pub fn record_owd_queue(&self, queuing_us: u64) {
        self.record_owd_queue_at(queuing_us, Instant::now());
    }

    /// `record_owd_queue` at a given time.
    pub fn record_owd_queue_at(&self, queuing_us: u64, now: Instant) {
        let mut state = self.entry.state.lock().unwrap();
        state.owd_min_us = Some(
            state
                .owd_min_us
                .map_or(queuing_us, |min| min.min(queuing_us)),
        );
        state.last_owd_at = Some(now);
    }

    /// One packet left this egress's own queue after waiting `delay` there.
    /// `publish_sample` takes the average wait since the previous sample out
    /// of the delay it is given (`own_queue_delay_us` when there was none).
    pub fn record_queue_delay(&self, delay: Duration) {
        let mut state = self.entry.state.lock().unwrap();
        let (total_us, packets) = &mut state.own_queue_delay;
        *total_us = total_us.saturating_add(delay.as_micros() as u64);
        *packets += 1;
    }

    /// The rate this egress is currently held to; `None` while nothing
    /// (neither a static ceiling nor an autorate estimate) holds it yet.
    pub fn ceiling(&self) -> Option<WireBitrate> {
        self.entry.state.lock().unwrap().budget
    }

    /// The rate the egress queue (CAKE) shapes to, in wire bits per second:
    /// [`ceiling`](Self::ceiling), or before the first estimate the
    /// estimator's start value within the same bounds. Never "unlimited":
    /// shaping to Autorate is always on.
    pub fn shaping_rate(&self) -> WireBitrate {
        let state = self.entry.state.lock().unwrap();
        state.budget.unwrap_or_else(|| {
            let (requested, wire_bps) = self
                .entry
                .ceiling_state
                .lock()
                .unwrap()
                .bound_autorate(&self.entry.scope.stable_id, state.estimator.estimate().est_bw_bps);
            wire_bps.unwrap_or(requested)
        })
    }

    /// The `T` attached to this egress, created by `init` on first use.
    /// Every handle of the same ledger gets the same `T`. `None` only if a
    /// different type was attached first.
    pub fn attached<T: Send + Sync + 'static>(&self, init: impl FnOnce() -> T) -> Option<Arc<T>> {
        self.entry
            .attached
            .get_or_init(|| Arc::new(init()))
            .clone()
            .downcast::<T>()
            .ok()
    }

    /// CAKE's `(target, interval)` as configured now.
    pub fn cake_timing(&self) -> (Duration, Duration) {
        self.entry.ceiling_state.lock().unwrap().cake_timing()
    }

    /// The `T` attached to this egress, if one was. Never creates it.
    pub fn attached_if_present<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.entry.attached.get()?.clone().downcast::<T>().ok()
    }

    /// The autorate estimator's most recent output for this scope,
    /// regardless of whether it is currently enforced. MP_SQM_PLAN.md §9's
    /// `MpEgressResourceStatus.autorate_estimate_bps`.
    pub fn autorate_estimate(&self) -> Option<WireBitrate> {
        self.entry.state.lock().unwrap().last_autorate_estimate_bps
    }

    /// Whether a measurement ever moved this scope's estimate off its start
    /// value (`MpEgressResourceStatus.autorate_measured`).
    pub fn autorate_measured(&self) -> bool {
        self.entry.state.lock().unwrap().estimator.estimate().measured
    }

    /// See [`LinkSqmEstimator::raise_start`]: a capacity the user declared
    /// for this egress (Brutal's `up_mbps`) starts the estimate there.
    pub fn raise_autorate_start(&self, declared: WireBitrate) -> Result<(), EgressQualityError> {
        self.guard()?.estimator.raise_start(declared.0);
        Ok(())
    }

    /// This egress's budget as the allocator must see it: the autorate
    /// estimate within the user's `autorate_min_bps`/`autorate_max_bps`,
    /// under the static/per-device ceiling -- the same clamps
    /// `publish_sample` applies when enforcing, so what a rate-driven CC is
    /// allocated never exceeds what the governor would let out.
    pub fn budget_for_estimate(&self, estimate: WireBitrate) -> WireBitrate {
        let (requested, wire_bps) = self
            .entry
            .ceiling_state
            .lock()
            .unwrap()
            .bound_autorate(&self.entry.scope.stable_id, estimate.0);
        wire_bps.unwrap_or(requested)
    }
}

pub struct EgressQualityManager {
    config: EgressQualityConfig,
    scopes: Arc<DashMap<EgressScope, Arc<ScopeEntry>>>,
    ceiling_state: Arc<Mutex<CeilingState>>,
    _retain_task: AbortOnDropHandle<()>,
}

impl EgressQualityManager {
    pub fn new(config: EgressQualityConfig) -> Arc<Self> {
        let scopes: Arc<DashMap<EgressScope, Arc<ScopeEntry>>> = Arc::new(DashMap::new());
        let retain_scopes = scopes.clone();
        let retain_task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                retain_scopes.retain(|_, entry| Arc::strong_count(entry) > 1);
                retain_scopes.shrink_to_fit();
            }
        });
        let ceiling_state = Arc::new(Mutex::new(CeilingState {
            global: config.static_wire_ceiling,
            per_device: HashMap::new(),
            autorate_min_bps: 0,
            autorate_max_bps: 0,
            cake_target_ms: 0,
            cake_interval_ms: 0,
        }));
        Arc::new(Self {
            config,
            scopes,
            ceiling_state,
            _retain_task: AbortOnDropHandle::new(retain_task),
        })
    }

    /// The estimator's `active_thr_bps`: below it a card counts as idle, which
    /// is also when its reflector probing may sleep.
    pub fn active_thr_bps(&self) -> u64 {
        self.config.estimator.active_thr_bps
    }

    /// Get or create the shared handle for `scope`. Two calls with an equal
    /// `EgressScope` always return handles over the same underlying state —
    /// this is the manager's core "one physical egress, one rate" contract.
    pub fn handle_for(&self, scope: EgressScope) -> EgressHandle {
        let entry = self
            .scopes
            .entry(scope.clone())
            .or_insert_with(|| {
                Arc::new(ScopeEntry::new(
                    scope,
                    &self.config,
                    self.ceiling_state.clone(),
                ))
            })
            .clone();
        EgressHandle { entry }
    }

    /// MP_SQM_PLAN.md S2.1: live re-cap. Replaces the manager's ceiling
    /// policy (global fallback + per-device overrides, keyed by
    /// [`EgressStableId`] -- callers resolve `MpConfig.egress_limits`'
    /// interface *names* against `EgressInventory` themselves, this module
    /// stays decoupled from that lookup) and immediately re-applies the
    /// newly-effective ceiling to every scope that already exists, not just
    /// ones created from now on -- a scope nothing ever calls `set_budget`/
    /// `publish_sample` for again (the common non-MP-managed case) would
    /// otherwise never pick up the change. `per_device` fully replaces the
    /// previous override map (a device missing from it falls back to
    /// `global`, even if it had an override before this call).
    pub fn set_static_ceiling(
        &self,
        global: Option<WireBitrate>,
        per_device: HashMap<EgressStableId, WireBitrate>,
    ) {
        {
            let mut state = self.ceiling_state.lock().unwrap();
            state.global = global;
            state.per_device = per_device;
        }
        for kv in self.scopes.iter() {
            let entry = kv.value();
            if entry.invalidated.load(Ordering::SeqCst) {
                continue;
            }
            let ceiling = self
                .ceiling_state
                .lock()
                .unwrap()
                .info_for(&entry.scope.stable_id)
                .ceiling_bps;
            let mut state = entry.state.lock().unwrap();
            state.budget = clamp_to_static_ceiling(state.last_requested_wire_bps, ceiling);
        }
    }

    /// MP_SQM_PLAN.md §9 GUI status reporting: which ceiling policy
    /// currently governs `stable_id`, and its value. Mirrors exactly what
    /// `handle_for`'s construction-time lookup and `set_static_ceiling`'s
    /// live re-apply already compute internally -- this is a read-only
    /// window onto the same `CeilingState`, not a separate decision.
    pub fn ceiling_info_for(&self, stable_id: &EgressStableId) -> CeilingInfo {
        self.ceiling_state.lock().unwrap().info_for(stable_id)
    }

    /// `MpSqmConfig.target_ms`/`interval_ms`, hot: the egress queues pick them
    /// up on their next packet. `0` means CAKE's default.
    pub fn set_cake_timing(&self, target_ms: u32, interval_ms: u32) {
        let mut state = self.ceiling_state.lock().unwrap();
        state.cake_target_ms = target_ms;
        state.cake_interval_ms = interval_ms;
    }

    /// The live `(target, interval)` of CAKE and of the AQM on reliable streams.
    pub fn cake_timing(&self) -> (Duration, Duration) {
        self.ceiling_state.lock().unwrap().cake_timing()
    }

    /// The live `(autorate_min_bps, autorate_max_bps)`; `0` means unset.
    pub fn autorate_bounds(&self) -> (u64, u64) {
        let state = self.ceiling_state.lock().unwrap();
        (state.autorate_min_bps, state.autorate_max_bps)
    }

    /// MP_SQM_PLAN.md S2.6: live re-apply of `MpSqmConfig.autorate_min_bps`/
    /// `autorate_max_bps`: flips the shared bounds, then immediately
    /// re-derives every existing scope's budget from its last recorded
    /// estimate rather than waiting for the next `publish_sample` tick. `0`
    /// means unset, the same convention `clamp_autorate_estimate_bps` and the
    /// proto fields themselves use.
    pub fn set_autorate_bounds(&self, min_bps: u64, max_bps: u64) {
        {
            let mut state = self.ceiling_state.lock().unwrap();
            state.autorate_min_bps = min_bps;
            state.autorate_max_bps = max_bps;
        }
        self.reapply_autorate_to_every_scope();
    }

    /// Push every existing scope's last recorded estimate, through the
    /// current bounds and ceiling, into its rate right now -- a scope
    /// might not get another `publish_sample` tick for a while (same
    /// reasoning `set_static_ceiling`'s own doc gives), and the clamps must
    /// stay in `publish_sample`'s own order.
    fn reapply_autorate_to_every_scope(&self) {
        for kv in self.scopes.iter() {
            let entry = kv.value();
            if entry.invalidated.load(Ordering::SeqCst) {
                continue;
            }
            let mut state = entry.state.lock().unwrap();
            let Some(estimate) = state.last_autorate_estimate_bps else {
                continue;
            };
            let (requested, wire_bps) = self
                .ceiling_state
                .lock()
                .unwrap()
                .bound_autorate(&entry.scope.stable_id, estimate.0);
            state.last_requested_wire_bps = Some(requested);
            state.budget = wire_bps;
        }
    }

    /// A NIC remove/re-add (or any inventory reconcile that bumps the
    /// interface's own generation counter) must retire every scope entry for
    /// `(stable_id, direction)` whose generation is not `current_generation`.
    /// Every `EgressHandle` still held against a retired entry immediately
    /// starts rejecting every operation; the map slot itself is dropped so a
    /// later `handle_for` with the same stale scope creates a fresh entry
    /// instead of resurrecting the retired one.
    pub fn invalidate_stale_generations(
        &self,
        stable_id: &EgressStableId,
        direction: EgressDirection,
        current_generation: u64,
    ) -> usize {
        let stale: Vec<EgressScope> = self
            .scopes
            .iter()
            .filter(|kv| {
                let scope = kv.key();
                &scope.stable_id == stable_id
                    && scope.direction == direction
                    && scope.generation != current_generation
            })
            .map(|kv| kv.key().clone())
            .collect();
        let mut retired = 0;
        for scope in stale {
            if let Some((_, entry)) = self.scopes.remove(&scope) {
                entry.invalidated.store(true, Ordering::SeqCst);
                retired += 1;
            }
        }
        retired
    }

    #[cfg(test)]
    fn scope_count(&self) -> usize {
        self.scopes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::transport_quality::budget::EgressDirection;

    fn scope(ifindex: u32, generation: u64) -> EgressScope {
        EgressScope {
            stable_id: EgressStableId::Linux {
                netns_inode: 1,
                ifindex,
            },
            direction: EgressDirection::Egress,
            generation,
        }
    }

    fn config_with_ceiling(ceiling: Option<u64>) -> EgressQualityConfig {
        EgressQualityConfig {
            estimator: SqmConfig::default(),
            static_wire_ceiling: ceiling.map(WireBitrate),
        }
    }

    /// Two independently resolved handles for the same `EgressScope` share
    /// one entry, so a rate set through one is visible through the other and
    /// the per-egress attachment (the cake queue) exists once.
    #[tokio::test]
    async fn handles_for_the_same_scope_share_one_entry() {
        let manager = EgressQualityManager::new(config_with_ceiling(None));
        let a = manager.handle_for(scope(7, 1));
        let b = manager.handle_for(scope(7, 1));
        let other = manager.handle_for(scope(8, 1));
        assert!(a.shares_ledger_with(&b));
        assert!(!a.shares_ledger_with(&other));
        a.set_budget(Some(WireBitrate(8_000_000))).unwrap();
        assert_eq!(b.ceiling(), Some(WireBitrate(8_000_000)));
        assert_eq!(other.ceiling(), None);
        let first = a.attached(|| 41u32).unwrap();
        let second = b.attached(|| 99u32).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(manager.scope_count(), 2);
    }

    /// A NIC down/re-add is a generation bump on the same stable id: the old
    /// handle rejects every operation, a fresh handle starts independent.
    #[tokio::test]
    async fn nic_generation_bump_invalidates_the_old_handle_and_starts_fresh() {
        let manager = EgressQualityManager::new(config_with_ceiling(None));
        let old = manager.handle_for(scope(9, 1));
        old.set_budget(Some(WireBitrate(1_000_000))).unwrap();
        let stable_id = old.scope().stable_id.clone();
        let retired =
            manager.invalidate_stale_generations(&stable_id, EgressDirection::Egress, 2);
        assert_eq!(retired, 1);
        assert!(!old.is_valid());
        assert!(matches!(
            old.set_budget(Some(WireBitrate(1))),
            Err(EgressQualityError::Invalidated)
        ));
        let new = manager.handle_for(scope(9, 2));
        assert!(new.is_valid());
        assert!(!new.shares_ledger_with(&old));
        assert_eq!(new.ceiling(), None);
    }

    /// Pure white-box: every branch of the clamp `set_budget`/`publish_sample`
    /// both apply. No ceiling configured is a no-op passthrough; `None`
    /// requested with a ceiling configured falls back to the ceiling instead
    /// of staying unmetered; `Some` above the ceiling is capped, `Some` below
    /// it is left alone.
    #[test]
    fn clamp_to_static_ceiling_covers_every_branch() {
        let ceiling = WireBitrate(1_000);
        assert_eq!(clamp_to_static_ceiling(Some(WireBitrate(500)), None), Some(WireBitrate(500)));
        assert_eq!(clamp_to_static_ceiling(None, None), None);
        assert_eq!(clamp_to_static_ceiling(None, Some(ceiling)), Some(ceiling));
        assert_eq!(
            clamp_to_static_ceiling(Some(WireBitrate(2_000)), Some(ceiling)),
            Some(ceiling)
        );
        assert_eq!(
            clamp_to_static_ceiling(Some(WireBitrate(500)), Some(ceiling)),
            Some(WireBitrate(500))
        );
    }

    /// Pure white-box: every branch of `clamp_autorate_estimate_bps`
    /// (MP_SQM_PLAN.md S2.6's `autorate_min_bps`/`autorate_max_bps`). `0`
    /// means unset on either side; an estimate strictly between a nonzero
    /// min and max passes through unchanged.
    #[test]
    fn clamp_autorate_estimate_bps_covers_every_branch() {
        // No bounds set at all: passthrough.
        assert_eq!(clamp_autorate_estimate_bps(5_000, 0, 0), 5_000);
        // Only a floor: below it gets raised, above it is untouched.
        assert_eq!(clamp_autorate_estimate_bps(500, 1_000, 0), 1_000);
        assert_eq!(clamp_autorate_estimate_bps(5_000, 1_000, 0), 5_000);
        // Only a ceiling: above it gets lowered, below it is untouched.
        assert_eq!(clamp_autorate_estimate_bps(5_000, 0, 2_000), 2_000);
        assert_eq!(clamp_autorate_estimate_bps(500, 0, 2_000), 500);
        // Both set, estimate inside the band: unchanged.
        assert_eq!(clamp_autorate_estimate_bps(1_500, 1_000, 2_000), 1_500);
        // Both set, estimate outside on either side.
        assert_eq!(clamp_autorate_estimate_bps(500, 1_000, 2_000), 1_000);
        assert_eq!(clamp_autorate_estimate_bps(5_000, 1_000, 2_000), 2_000);
    }

    /// A static ceiling governs a scope from construction (a non-MP-managed
    /// `mpquic://` connection never gets a `publish_sample`) and caps a later
    /// `set_budget` that asks for more.
    #[tokio::test]
    async fn static_wire_ceiling_governs_from_construction_and_caps_set_budget() {
        let manager = EgressQualityManager::new(config_with_ceiling(Some(800)));
        let handle = manager.handle_for(scope(30, 1));
        assert_eq!(handle.ceiling(), Some(WireBitrate(800)));
        assert_eq!(handle.shaping_rate(), WireBitrate(800));
        handle.set_budget(Some(WireBitrate(8_000))).unwrap();
        assert_eq!(handle.ceiling(), Some(WireBitrate(800)));
        handle.set_budget(Some(WireBitrate(400))).unwrap();
        assert_eq!(handle.ceiling(), Some(WireBitrate(400)));
    }

    /// `set_static_ceiling` re-caps an already running scope with no further
    /// call, down and back up.
    #[tokio::test]
    async fn set_static_ceiling_re_caps_an_already_running_scope_with_no_further_calls() {
        let manager = EgressQualityManager::new(config_with_ceiling(Some(800)));
        let handle = manager.handle_for(scope(40, 1));
        assert_eq!(handle.ceiling(), Some(WireBitrate(800)));
        manager.set_static_ceiling(Some(WireBitrate(400)), HashMap::new());
        assert_eq!(handle.ceiling(), Some(WireBitrate(400)));
        manager.set_static_ceiling(Some(WireBitrate(8_000)), HashMap::new());
        assert_eq!(handle.ceiling(), Some(WireBitrate(8_000)));
    }

    /// A scope created after `set_static_ceiling` starts under the new policy.
    #[tokio::test]
    async fn set_static_ceiling_governs_scopes_created_after_the_call() {
        let manager = EgressQualityManager::new(config_with_ceiling(None));
        manager.set_static_ceiling(Some(WireBitrate(800)), HashMap::new());
        let handle = manager.handle_for(scope(41, 1));
        assert_eq!(handle.ceiling(), Some(WireBitrate(800)));
    }

    /// `egress_limits` overrides the global ceiling for the NIC it names only.
    #[tokio::test]
    async fn per_device_ceiling_overrides_global_for_its_own_stable_id_only() {
        let manager = EgressQualityManager::new(config_with_ceiling(None));
        let overridden = EgressStableId::Linux { netns_inode: 1, ifindex: 50 };
        let not_overridden = EgressStableId::Linux { netns_inode: 1, ifindex: 51 };
        let mut per_device = HashMap::new();
        per_device.insert(overridden.clone(), WireBitrate(400));
        manager.set_static_ceiling(Some(WireBitrate(8_000)), per_device);
        assert_eq!(
            manager.ceiling_info_for(&overridden),
            CeilingInfo {
                ceiling_bps: Some(WireBitrate(400)),
                source: CeilingSource::PerDevice,
            }
        );
        assert_eq!(
            manager.ceiling_info_for(&not_overridden),
            CeilingInfo {
                ceiling_bps: Some(WireBitrate(8_000)),
                source: CeilingSource::Static,
            }
        );
        let a = manager.handle_for(EgressScope {
            stable_id: overridden,
            direction: EgressDirection::Egress,
            generation: 1,
        });
        let b = manager.handle_for(EgressScope {
            stable_id: not_overridden,
            direction: EgressDirection::Egress,
            generation: 1,
        });
        assert_eq!(a.ceiling(), Some(WireBitrate(400)));
        assert_eq!(b.ceiling(), Some(WireBitrate(8_000)));
    }

    /// `mp.sqm.target_ms`/`interval_ms` reach every egress live; 0 is CAKE's default.
    #[tokio::test]
    async fn cake_timing_follows_the_sqm_config_and_defaults_to_cakes_own() {
        let manager = EgressQualityManager::new(EgressQualityConfig::default());
        let handle = manager.handle_for(scope(70, 1));
        assert_eq!(
            handle.cake_timing(),
            (Duration::from_millis(5), Duration::from_millis(100))
        );
        manager.set_cake_timing(20, 300);
        assert_eq!(
            handle.cake_timing(),
            (Duration::from_millis(20), Duration::from_millis(300))
        );
        manager.set_cake_timing(0, 0);
        assert_eq!(manager.cake_timing(), (CAKE_DEFAULT_TARGET, CAKE_DEFAULT_INTERVAL));
    }

    #[tokio::test]
    async fn ceiling_info_for_reports_none_with_nothing_configured() {
        let manager = EgressQualityManager::new(EgressQualityConfig::default());
        let stable_id = EgressStableId::Linux { netns_inode: 1, ifindex: 60 };
        assert_eq!(
            manager.ceiling_info_for(&stable_id),
            CeilingInfo {
                ceiling_bps: None,
                source: CeilingSource::None,
            }
        );
    }

    /// A live re-cap must not overwrite an estimate already below the new
    /// ceiling with the ceiling itself.
    #[tokio::test]
    async fn set_static_ceiling_preserves_an_estimate_already_below_the_new_ceiling() {
        let manager = EgressQualityManager::new(EgressQualityConfig {
            estimator: SqmConfig {
                bw_max_bps: 1_000_000,
                ..SqmConfig::default()
            },
            static_wire_ceiling: None,
        });
        let handle = manager.handle_for(scope(42, 1));
        let estimate = handle
            .publish_sample(SqmSample { owd_us: 1, achieved_bps: 200 })
            .unwrap();
        let new_ceiling_bps = estimate.est_bw_bps.saturating_mul(10).max(1);
        manager.set_static_ceiling(Some(WireBitrate(new_ceiling_bps)), HashMap::new());
        assert_eq!(handle.ceiling(), Some(WireBitrate(estimate.est_bw_bps)));
    }

    /// Shaping to Autorate is always on: before any estimate the shaping rate
    /// is the estimator's start value, afterwards the estimate itself.
    #[tokio::test]
    async fn publish_sample_holds_the_scope_to_the_estimate() {
        let manager = EgressQualityManager::new(EgressQualityConfig {
            estimator: SqmConfig {
                bw_max_bps: 1_000_000,
                ..SqmConfig::default()
            },
            static_wire_ceiling: None,
        });
        let handle = manager.handle_for(scope(51, 1));
        assert_eq!(handle.ceiling(), None, "unshaped before any estimate");
        assert!(handle.shaping_rate().0 > 0, "the shaping rate is never unlimited");
        let estimate = handle
            .publish_sample(SqmSample { owd_us: 1, achieved_bps: 200 })
            .unwrap();
        assert_eq!(handle.autorate_estimate(), Some(WireBitrate(estimate.est_bw_bps)));
        assert_eq!(handle.ceiling(), Some(WireBitrate(estimate.est_bw_bps)));
        assert_eq!(handle.shaping_rate(), WireBitrate(estimate.est_bw_bps));
    }

    /// Every session's driver samples its own egress, so one scope gets
    /// several samples per period; each must have this egress's own queue
    /// wait taken out, not only the first.
    #[tokio::test]
    async fn every_sampler_of_a_scope_has_the_own_queue_wait_taken_out() {
        const MAX_BPS: u64 = 1_000_000;
        let manager = EgressQualityManager::new(EgressQualityConfig {
            estimator: SqmConfig {
                bw_max_bps: MAX_BPS,
                ..SqmConfig::default()
            },
            ..EgressQualityConfig::default()
        });
        let handle = manager.handle_for(scope(55, 1));
        let wait = Duration::from_millis(100);
        for _ in 0..30 {
            for _ in 0..4 {
                handle.record_queue_delay(wait);
            }
            for _ in 0..2 {
                handle
                    .publish_sample(SqmSample {
                        owd_us: wait.as_micros() as u64 + 1,
                        achieved_bps: MAX_BPS,
                    })
                    .unwrap();
            }
        }
        assert_eq!(
            handle.autorate_estimate(),
            Some(WireBitrate(MAX_BPS)),
            "our own queue wait was read as bufferbloat"
        );
    }

    /// OWD_AUTORATE_PLAN.md 1.2 (R6): a one-way sample is the delay, with
    /// none of this egress's own queue taken out; a gap of up to `OWD_HOLD`
    /// (30 s) leaves the estimate as it is, whatever the round trip says; a
    /// longer gap falls back to the round trip (less the own queue), or holds
    /// when there is none; an egress that never had a one-way sample uses the
    /// round trip at once.
    #[tokio::test]
    async fn one_way_samples_win_and_a_gap_holds_the_estimate() {
        let manager = EgressQualityManager::new(EgressQualityConfig::default());
        let handle = manager.handle_for(scope(56, 1));
        let t0 = Instant::now();
        let busy = 4_000_000;

        // Our own queue wait must not be taken out of a one-way delay.
        for _ in 0..4 {
            handle.record_queue_delay(Duration::from_millis(100));
        }
        for us in [90_000, 40_000, 70_000] {
            handle.record_owd_queue_at(us, t0);
        }
        let first = handle.publish_at(busy, Some(500_000), t0).unwrap();
        assert_eq!(first.source, QueueDelaySource::OneWay);
        assert_eq!(
            first.queue_delay_us, 40_000,
            "the smallest one-way sample, own queue not deducted"
        );
        assert_eq!(
            first.estimate.delta_us, 0,
            "the first sample is its own baseline"
        );

        // No new sample for 1.5 s: held, nothing moves, the status keeps the last delay.
        let before = handle.autorate_estimate();
        let budget = handle.ceiling();
        let held = handle
            .publish_at(busy, Some(500_000), t0 + Duration::from_millis(1_500))
            .unwrap();
        assert_eq!(held.source, QueueDelaySource::Held);
        assert_eq!(held.queue_delay_us, 40_000);
        assert_eq!(held.estimate, first.estimate);
        assert_eq!(handle.autorate_estimate(), before);
        assert_eq!(handle.ceiling(), budget);

        // 25 s without a one-way sample: still held. The round trip holds the
        // peer's queue for our ACKs, not the link's (RFC 6817 Section 3.1).
        let long = handle
            .publish_at(busy, Some(500_000), t0 + Duration::from_secs(25))
            .unwrap();
        assert_eq!(long.source, QueueDelaySource::Held);
        assert_eq!(long.estimate, first.estimate);

        // 31 s: the peer stopped answering. The round trip, less our own queue (100 ms).
        let fallback = handle
            .publish_at(busy, Some(500_000), t0 + Duration::from_secs(31))
            .unwrap();
        assert_eq!(fallback.source, QueueDelaySource::RoundTrip);
        assert_eq!(fallback.queue_delay_us, 399_999);

        // ...and with no round trip either (every path stale), nothing to feed.
        let none = handle
            .publish_at(busy, None, t0 + Duration::from_secs(33))
            .unwrap();
        assert_eq!(none.source, QueueDelaySource::Held);
        assert_eq!(none.estimate, fallback.estimate);

        // A fresh one-way sample wins again.
        handle.record_owd_queue_at(1_000, t0 + Duration::from_millis(33_100));
        let again = handle
            .publish_at(busy, Some(500_000), t0 + Duration::from_millis(33_200))
            .unwrap();
        assert_eq!(again.source, QueueDelaySource::OneWay);
        assert_eq!(again.queue_delay_us, 1_000);
    }

    /// An egress that never had a one-way sample (a peer without
    /// `CAP_OWD_PROBE`) is fed the round trip at once.
    #[tokio::test]
    async fn an_egress_without_one_way_samples_uses_the_round_trip() {
        let manager = EgressQualityManager::new(EgressQualityConfig::default());
        let handle = manager.handle_for(scope(57, 1));
        let sample = handle.publish_at(4_000_000, Some(500_000), Instant::now()).unwrap();
        assert_eq!(sample.source, QueueDelaySource::RoundTrip);
    }

    /// Setting `autorate_max_bps` live clamps an already enforced estimate at
    /// once.
    #[tokio::test]
    async fn setting_autorate_max_bound_live_clamps_an_already_enforced_estimate() {
        let manager = EgressQualityManager::new(config_with_ceiling(None));
        let handle = manager.handle_for(scope(53, 1));
        let estimate = handle
            .publish_sample(SqmSample { owd_us: 1, achieved_bps: 200 })
            .unwrap();
        assert_eq!(estimate.est_bw_bps, DEFAULT_AUTORATE_START_BPS);
        manager.set_autorate_bounds(0, 200_000);
        assert_eq!(handle.ceiling(), Some(WireBitrate(200_000)));
        assert_eq!(handle.shaping_rate(), WireBitrate(200_000));
    }

    /// 2026-10-26 08:25 incident, replayed: the local instance's only MP peer
    /// showed 16-93 ms of one-way queueing while the link itself was idle and
    /// the estimate fell from 4.5 to 0.29 Mbit/s. Each recorded row stands for
    /// two 0.5 s ticks. `reflectors` is what the public reflectors report each
    /// tick, if any; returns the lowest estimate of the run.
    fn replay_20261026_0825(reflectors: Option<&[u64]>) -> u64 {
        const START_BPS: u64 = 4_500_000;
        let replay: serde_json::Value =
            serde_json::from_str(include_str!("testdata/replay-20261026-0825.json")).unwrap();
        let manager = EgressQualityManager::new(config_with_ceiling(Some(START_BPS)));
        let handle = manager.handle_for(scope(60, 1));
        let t0 = Instant::now();
        let mut tick = 0u32;
        let mut lowest = u64::MAX;
        for row in replay["rows"].as_array().unwrap() {
            let achieved = row["achieved_bps"].as_u64().unwrap();
            let queue_us = row["queue_delay_us"].as_u64().unwrap();
            for _ in 0..2 {
                let now = t0 + Duration::from_millis(500 * tick as u64);
                tick += 1;
                handle.record_owd_queue_at(queue_us, now);
                if let Some(reflectors) = reflectors {
                    handle.record_reflector_deltas(reflectors.to_vec());
                }
                let published = handle.publish_at(achieved, None, now).unwrap();
                lowest = lowest.min(published.estimate.est_bw_bps);
            }
        }
        lowest
    }

    /// R1 (red on the code before reflectors, green after): the peer alone
    /// drove the estimate to 0.3 Mbit/s; with five reflectors at 0-2 ms the
    /// estimate never falls below 0.9 of its start.
    #[tokio::test]
    async fn replay_20261026_0825_keeps_the_estimate_with_reflectors() {
        let lowest = replay_20261026_0825(Some(&[0, 1_000, 0, 2_000, 1_000]));
        assert!(
            lowest as f64 >= 0.9 * 4_500_000.0,
            "estimate fell to {lowest} bit/s from 4500000"
        );
    }

    /// R1 control: with no reflector (nothing to take the third smallest of)
    /// the peer alone still drives the old behaviour, which is unchanged for an
    /// egress without reflectors.
    #[tokio::test]
    async fn replay_20261026_0825_peer_only_is_unchanged_without_reflectors() {
        let lowest = replay_20261026_0825(None);
        assert!(lowest < 1_000_000, "{lowest}");
    }

    /// R2: a real upstream inflation seen by the peer and by every reflector
    /// at once (60 ms) still brings the estimate below half its start.
    #[tokio::test]
    async fn replay_with_real_upstream_inflation_still_cuts() {
        const START_BPS: u64 = 4_500_000;
        let manager = EgressQualityManager::new(config_with_ceiling(Some(START_BPS)));
        let handle = manager.handle_for(scope(61, 1));
        let t0 = Instant::now();
        let mut lowest = u64::MAX;
        for tick in 0..120u64 {
            let now = t0 + Duration::from_millis(500 * tick);
            // Four seconds of calm so the baseline is the idle one, then 60 ms.
            let delay = if tick < 8 { 1_000 } else { 60_000 };
            handle.record_owd_queue_at(delay, now);
            handle.record_reflector_deltas(vec![delay; 5]);
            let published = handle.publish_at(4_000_000, None, now).unwrap();
            assert_eq!(published.source, QueueDelaySource::Reflectors);
            assert_eq!(published.reflector_count, 5);
            lowest = lowest.min(published.estimate.est_bw_bps);
        }
        assert!(lowest as f64 <= 0.5 * START_BPS as f64, "{lowest}");
    }

    /// T5: the delay a tick is fed: the lower median of the reflectors and the
    /// peer's one-way delay (as one more). One value: itself. Two: the smaller.
    /// No reflector leaves the old sources alone.
    #[tokio::test]
    async fn t5_reflector_delay_composition() {
        let manager = EgressQualityManager::new(config_with_ceiling(None));
        let handle = manager.handle_for(scope(62, 1));
        let t0 = Instant::now();
        let mut at = t0;
        let mut fed = |reflectors: Vec<u64>, peer: Option<u64>| {
            at += Duration::from_millis(500);
            if let Some(peer) = peer {
                handle.record_owd_queue_at(peer, at);
            }
            handle.record_reflector_deltas(reflectors);
            handle.publish_at(1_000_000, Some(9_999), at).unwrap()
        };
        let one = fed(vec![7_000], None);
        assert_eq!((one.source, one.queue_delay_us, one.reflector_count), (QueueDelaySource::Reflectors, 7_000, 1));
        let two = fed(vec![9_000, 4_000], None);
        assert_eq!((two.queue_delay_us, two.reflector_count), (4_000, 2));
        let five = fed(vec![50_000, 3_000, 90_000, 1_000, 2_000], None);
        assert_eq!((five.queue_delay_us, five.reflector_count), (3_000, 5));
        // The peer is one more: one reflector + peer is two -> the smaller.
        let with_peer = fed(vec![8_000], Some(2_000));
        assert_eq!((with_peer.queue_delay_us, with_peer.reflector_count), (2_000, 1));
        // Two quiet reflectors + a high peer: three values, the median is a
        // reflector's, so the far peer alone cannot cut the rate.
        let peer_high = fed(vec![1_000, 2_000], Some(90_000));
        assert_eq!(peer_high.queue_delay_us, 2_000);
        // A majority high (real upstream congestion) still reads high: five
        // reflectors, three of them at 50-70 ms.
        let majority_5 = fed(vec![50_000, 60_000, 70_000, 1_000, 2_000], None);
        assert_eq!((majority_5.queue_delay_us, majority_5.reflector_count), (50_000, 5));
        // Six values (five reflectors + the peer), the lower median is the third.
        let majority_6 = fed(vec![50_000, 60_000, 70_000, 1_000, 2_000], Some(55_000));
        assert_eq!(majority_6.queue_delay_us, 50_000);
        // No reflector: the peer's one-way delay as before.
        let old = fed(Vec::new(), Some(5_000));
        assert_eq!((old.source, old.queue_delay_us, old.reflector_count), (QueueDelaySource::OneWay, 5_000, 0));
        // Consumed: the next tick without any is held (a one-way sample is recent).
        let held = fed(Vec::new(), None);
        assert_eq!((held.source, held.reflector_count), (QueueDelaySource::Held, 0));
        assert_eq!(QueueDelaySource::Reflectors.as_str(), "reflectors");
    }
}

//! Physical-egress-scoped quality service (MP_SQM_PLAN.md §4.3).
//!
//! `L1 EgressQualityManager (inventory/autorate/governor)` in the PLAN's
//! layering. This module intentionally exposes only the
//! manager/handle/snapshot/capability surface; the platform-specific
//! estimator implementation stays in its submodule.
//! `common::egress_quality` never imports `connector::mp_*` or
//! `tunnel::mpquic`: higher layers translate their own path/resource keys
//! into the pure `common::transport_quality` types this module consumes.
//!
//! The send queue itself is the `cake-sqm` crate (Linux CAKE, unchanged),
//! one instance per egress, owned by `tunnel::mpquic::egress_cake`; this
//! module only holds each egress's rate and its Autorate estimator.

pub mod autorate;
pub mod manager;
pub mod reflectors;

pub use autorate::{LinkSqmEstimator, SqmConfig, SqmEstimate, SqmSample};
pub use manager::{
    CeilingInfo, CeilingSource, EgressHandle, EgressQualityConfig, EgressQualityError,
    EgressQualityManager, OWD_HOLD, PublishedSample, QueueDelaySource,
};

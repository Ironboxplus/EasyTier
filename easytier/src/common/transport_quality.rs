//! Stable, engine-neutral transport-quality contracts.
//!
//! Dependency direction is intentionally one way: platform/egress discovery
//! and engines may use these pure values, while this module never imports ET
//! config, RPC, `Tunnel`, or a concrete QUIC implementation.
//!
//! This file is a facade (MP_SQM_PLAN.md §4.2): the actual contracts live in
//! the sibling `transport_quality/` submodules, split by concern so each can
//! be read and tested independently.
//! Every previously public type keeps the same path through this facade, so
//! existing callers compile unmodified.
//!
//! MP_SQM_PLAN.md S1.1 removed the `allocator` submodule: it duplicated
//! `connector::mp_optimizer::solve_resource_max_flow` and had no production
//! caller (`EgressHandle::register_demand`/`update_demand`/`remove_demand`/
//! `allocation` were only ever exercised by `allocator.rs`'s own tests).
//!
//! CAKE_SQM_PLAN.md B4 removed the token-bucket ledger/governor and the
//! telemetry submodule: shaping is a CAKE queue per egress now
//! (`tunnel::mpquic::egress_cake`).

pub mod budget;
pub mod profile;
pub mod rate;

pub use budget::{EgressDirection, EgressScope};
pub use profile::{CongestionControlProfile, QualityConfigError, SchedulerState};
pub use rate::{TransportByteRate, WireBitrate};

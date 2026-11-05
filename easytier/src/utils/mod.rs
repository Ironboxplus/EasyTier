pub mod error;
pub mod panic;
pub mod string;
pub mod task;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::{Arc, Weak};

pub type PeerRoutePair = crate::proto::api::instance::PeerRoutePair;

pub fn check_tcp_available(port: u16) -> bool {
    let s = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    TcpListener::bind(s).is_ok()
}

pub fn find_free_tcp_port(mut range: std::ops::Range<u16>) -> Option<u16> {
    range.find(|&port| check_tcp_available(port))
}

pub fn weak_upgrade<T>(weak: &Weak<T>) -> anyhow::Result<Arc<T>> {
    weak.upgrade()
        .ok_or_else(|| anyhow::anyhow!("{} not available", std::any::type_name::<T>()))
}

/// `Debug`'s `PascalCase` variant name, converted to `kebab-case`. MP status
/// mapping (`instance.rs`) uses this for every enum-shaped proto string
/// field (`carrier_kind`, `lifecycle_state`, ...) so the wire string always
/// matches the Rust variant name mechanically, with one Rust-side
/// implementation instead of a hand-written match arm per variant per enum.
pub fn debug_name_to_kebab(value: impl std::fmt::Debug) -> String {
    let value = format!("{value:?}");
    let mut output = String::with_capacity(value.len());
    for (index, ch) in value.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if index > 0 {
                output.push('-');
            }
            output.push(ch.to_ascii_lowercase());
        } else {
            output.push(ch);
        }
    }
    output
}

/// A monotonic clock in milliseconds, anchored at this process's first call
/// (not the Unix epoch or any wall clock). MP_SQM_PLAN.md S2.2's
/// `MpRuntimeInfo.sample_time_ms`: the GUI differences its counters against
/// this value between two samples, so it must never jump backward the way a
/// wall clock can (NTP step, DST, user changing the clock) -- unlike
/// `SystemTime::now()` (see `proto::common::TimestampExt`, used for wire
/// timestamps elsewhere), `Instant` is documented as monotonic on every
/// platform this crate supports.
pub fn monotonic_now_ms() -> u64 {
    static PROCESS_EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let epoch = PROCESS_EPOCH.get_or_init(std::time::Instant::now);
    epoch.elapsed().as_millis() as u64
}

pub trait BoxExt: Sized {
    fn boxed(self) -> Box<Self> {
        Box::new(self)
    }
}

impl<T> BoxExt for T {}

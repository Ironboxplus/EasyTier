//! Hand-written mirror of `csrc/cake_glue.h`.

#![allow(non_camel_case_types)]

use std::os::raw::c_int;

pub const MAX_TINS: usize = 8;

/// Opaque handle of one compiled cake instance.
#[repr(C)]
pub struct cake_glue {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct cake_glue_tin_stats {
    pub threshold_rate: u64,
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
    pub sparse_flows: u32,
    pub bulk_flows: u32,
    pub unresponsive_flows: u32,
    pub max_skblen: u32,
    pub flow_quantum: u32,
    pub drop_overlimit: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct cake_glue_stats {
    pub capacity_estimate: u64,
    pub memory_limit: u32,
    pub memory_used: u32,
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
    pub tin_cnt: u32,
    pub dequeued_bytes: u64,
    pub dequeued_packets: u64,
    pub tin: [cake_glue_tin_stats; MAX_TINS],
}

/// Opaque handle of a stand-alone COBALT state.
#[repr(C)]
pub struct cake_glue_cobalt {
    _private: [u8; 0],
}

unsafe extern "C" {
    pub fn cake_glue_cobalt_new(
        rate_bytes_per_sec: u64,
        mtu: u32,
        target_ns: u64,
        rtt_ns: u64,
    ) -> *mut cake_glue_cobalt;
    pub fn cake_glue_cobalt_set_rate(
        c: *mut cake_glue_cobalt,
        rate_bytes_per_sec: u64,
        mtu: u32,
        target_ns: u64,
        rtt_ns: u64,
    ) -> bool;
    pub fn cake_glue_cobalt_should_drop(
        c: *mut cake_glue_cobalt,
        now_ns: u64,
        enqueued_ns: u64,
        bulk_flows: u32,
    ) -> bool;
    pub fn cake_glue_cobalt_queue_empty(c: *mut cake_glue_cobalt, now_ns: u64);
    pub fn cake_glue_cobalt_queue_full(c: *mut cake_glue_cobalt, now_ns: u64);
    pub fn cake_glue_cobalt_free(c: *mut cake_glue_cobalt);

    pub fn cake_glue_new(
        seed: u64,
        mtu: u32,
        attrs: *const u8,
        attrs_len: u32,
        now_ns: u64,
        err: *mut c_int,
    ) -> *mut cake_glue;
    pub fn cake_glue_change(
        g: *mut cake_glue,
        mtu: u32,
        attrs: *const u8,
        attrs_len: u32,
        now_ns: u64,
    ) -> c_int;
    pub fn cake_glue_enqueue(
        g: *mut cake_glue,
        cookie: u64,
        len: u32,
        hdr: *const u8,
        hdr_len: u32,
        protocol: u16,
        hash: u32,
        l4_hash: bool,
        mark: u32,
        now_ns: u64,
    ) -> c_int;
    pub fn cake_glue_dequeue(
        g: *mut cake_glue,
        now_ns: u64,
        cookie: *mut u64,
        enqueue_ns: *mut u64,
    ) -> bool;
    pub fn cake_glue_wake_ns(g: *const cake_glue) -> u64;
    pub fn cake_glue_take_dropped(g: *mut cake_glue, out: *mut u64, cap: u32) -> u32;
    pub fn cake_glue_stats(g: *const cake_glue, out: *mut cake_glue_stats);
    pub fn cake_glue_qlen(g: *const cake_glue) -> u32;
    pub fn cake_glue_backlog(g: *const cake_glue) -> u32;
    pub fn cake_glue_dump_config(g: *mut cake_glue, buf: *mut u8, cap: u32) -> c_int;
    pub fn cake_glue_free(g: *mut cake_glue);
}

/* cake_glue.h - the C ABI between the Rust crate and the compiled sch_cake.c. Plain integer
 * types only, no kernel headers, so that src/ffi.rs can mirror it by hand. */
#ifndef CAKE_GLUE_H
#define CAKE_GLUE_H

#include <stdint.h>
#include <stdbool.h>

#define CAKE_GLUE_MAX_TINS 8

struct cake_glue;

/* One tin, in the order `tc -s qdisc show` prints them (q->tin_order). Same names and meaning as
 * the TCA_CAKE_TIN_STATS_* attributes that cake_dump_stats() emits. */
struct cake_glue_tin_stats {
	uint64_t threshold_rate;
	uint64_t sent_bytes; /* accepted into the queue, as cake counts them */
	uint32_t sent_packets;
	uint32_t backlog_bytes;
	uint32_t target_us;
	uint32_t interval_us;
	uint32_t dropped_packets;
	uint32_t ecn_marked;
	uint32_t ack_drops;
	uint32_t peak_delay_us;
	uint32_t avg_delay_us;
	uint32_t base_delay_us;
	uint32_t way_hits;
	uint32_t way_misses;
	uint32_t way_collisions;
	uint32_t sparse_flows; /* sparse + decaying, as cake_dump_stats() reports it */
	uint32_t bulk_flows;
	uint32_t unresponsive_flows;
	uint32_t max_skblen;
	uint32_t flow_quantum;
	uint32_t drop_overlimit;
};

struct cake_glue_stats {
	uint64_t capacity_estimate;
	uint32_t memory_limit;
	uint32_t memory_used; /* peak, as cake_dump_stats() reports it */
	uint32_t memory_now;  /* bytes accounted right now */
	uint32_t avg_netoff;
	uint32_t min_netlen;
	uint32_t max_netlen;
	uint32_t min_adjlen;
	uint32_t max_adjlen;
	uint32_t active_queues;
	uint32_t qlen;
	uint32_t backlog;
	uint32_t overlimits;
	uint32_t drops;
	uint32_t tin_cnt;
	uint64_t dequeued_bytes; /* handed out by dequeue (the qdisc's bstats) */
	uint64_t dequeued_packets;
	struct cake_glue_tin_stats tin[CAKE_GLUE_MAX_TINS];
};

/* `attrs` is a sequence of netlink attributes (TCA_CAKE_*), without the outer TCA_OPTIONS
 * nest; the glue wraps it. Returns NULL and sets *err (negative errno) on failure. */
struct cake_glue *cake_glue_new(uint64_t seed, uint32_t mtu, const void *attrs, uint32_t attrs_len,
				uint64_t now_ns, int *err);
/* `mtu` replaces the egress MTU first (0 keeps it); cake reads it again while reconfiguring. */
int cake_glue_change(struct cake_glue *g, uint32_t mtu, const void *attrs, uint32_t attrs_len, uint64_t now_ns);
/* Returns the NET_XMIT_* code of cake_enqueue(). Packets cake discards (the new one or others)
 * are reported through cake_glue_take_dropped(). */
int cake_glue_enqueue(struct cake_glue *g, uint64_t cookie, uint32_t len, const uint8_t *hdr, uint32_t hdr_len,
		      uint16_t protocol, uint32_t hash, bool l4_hash, uint32_t mark, uint64_t now_ns);
bool cake_glue_dequeue(struct cake_glue *g, uint64_t now_ns, uint64_t *cookie, uint64_t *enqueue_ns);
uint64_t cake_glue_wake_ns(const struct cake_glue *g); /* 0 = no timer armed */
uint32_t cake_glue_take_dropped(struct cake_glue *g, uint64_t *out, uint32_t cap);
void cake_glue_stats(const struct cake_glue *g, struct cake_glue_stats *out);
uint32_t cake_glue_qlen(const struct cake_glue *g);
uint32_t cake_glue_backlog(const struct cake_glue *g);
/* cake_dump(): the current configuration as netlink attributes. Returns the length or <0. */
int cake_glue_dump_config(struct cake_glue *g, uint8_t *buf, uint32_t cap);
void cake_glue_free(struct cake_glue *g);


/* A stand-alone COBALT (CoDel + BLUE) state, the one every cake flow carries, for queues that are
 * not cake's own. Parameters come from cake_set_rate() for a tin at `rate_bytes_per_sec`. */
struct cake_glue_cobalt;
struct cake_glue_cobalt *cake_glue_cobalt_new(uint64_t rate_bytes_per_sec, uint32_t mtu, uint64_t target_ns,
					      uint64_t rtt_ns);
/* New parameters for a new rate; the CoDel/BLUE state is kept. */
bool cake_glue_cobalt_set_rate(struct cake_glue_cobalt *c, uint64_t rate_bytes_per_sec, uint32_t mtu,
			       uint64_t target_ns, uint64_t rtt_ns);
/* cobalt_should_drop() for a packet that waited since `enqueued_ns`. */
bool cake_glue_cobalt_should_drop(struct cake_glue_cobalt *c, uint64_t now_ns, uint64_t enqueued_ns,
				  uint32_t bulk_flows);
/* cobalt_queue_empty(): the queue ran empty. */
void cake_glue_cobalt_queue_empty(struct cake_glue_cobalt *c, uint64_t now_ns);
/* cobalt_queue_full(): a packet was dropped because the memory was full. */
void cake_glue_cobalt_queue_full(struct cake_glue_cobalt *c, uint64_t now_ns);
void cake_glue_cobalt_free(struct cake_glue_cobalt *c);

#endif

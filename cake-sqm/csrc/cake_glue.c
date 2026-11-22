/* cake_glue.c - includes the unmodified sch_cake.c so that its static functions and structures
 * are reachable, and exports the small C ABI of cake_glue.h on top of them. */
#include "kshim.h"
#include "linux/sch_cake.c"
#include "cake_glue.h"

struct cake_glue {
	struct kshim_ctx ctx; /* must stay first: kshim_cur points here */
	struct kshim_netdev nd;
	struct Qdisc *sch;
	uint64_t *dropped;
	uint32_t n_dropped;
	uint32_t cap_dropped;
	struct sk_buff *pool; /* recycled sk_buffs, chained through ->next */
};

static struct cake_sched_data *glue_priv(const struct cake_glue *g)
{
	return (struct cake_sched_data *)qdisc_priv(g->sch);
}

static void glue_enter(struct cake_glue *g, uint64_t now_ns)
{
	g->ctx.now_ns = (s64)now_ns;
	kshim_cur = &g->ctx;
}

static void glue_leave(void)
{
	kshim_cur = NULL;
}

static struct sk_buff *glue_skb_alloc(struct cake_glue *g)
{
	struct sk_buff *skb = g->pool;

	if (skb)
		g->pool = skb->next;
	else
		skb = (struct sk_buff *)malloc(sizeof(*skb));
	if (!skb)
		return NULL;
	memset(skb, 0, sizeof(*skb));
	skb->data = skb->hdr;
	return skb;
}

static void glue_skb_recycle(struct cake_glue *g, struct sk_buff *skb)
{
	skb->next = g->pool;
	g->pool = skb;
}

/* A packet leaves cake without being dequeued (dropped, or consumed by the ACK filter): hand its
 * cookie to the Rust side and recycle the descriptor. */
void kshim_packet_gone(struct sk_buff *skb)
{
	struct cake_glue *g = (struct cake_glue *)kshim_cur;

	if (g->n_dropped == g->cap_dropped) {
		uint32_t cap = g->cap_dropped ? g->cap_dropped * 2 : 64;
		uint64_t *p = (uint64_t *)realloc(g->dropped, sizeof(uint64_t) * cap);

		if (!p) {
			/* Out of memory: the cookie is lost. The Rust side notices through its count of
			 * live packets, and the process is about to fail anyway. */
			glue_skb_recycle(g, skb);
			return;
		}
		g->dropped = p;
		g->cap_dropped = cap;
	}
	g->dropped[g->n_dropped++] = skb->cookie;
	glue_skb_recycle(g, skb);
}

static uint64_t splitmix64(uint64_t *x)
{
	uint64_t z = (*x += 0x9E3779B97F4A7C15ULL);

	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
	return z ^ (z >> 31);
}

/* TCA_OPTIONS nest around the caller's attributes; cake_init()/cake_change() take the nest. */
static struct nlattr *glue_make_opts(const void *attrs, uint32_t len)
{
	struct nlattr *opt = (struct nlattr *)malloc(NLA_HDRLEN + len);

	if (!opt)
		return NULL;
	opt->nla_type = TCA_OPTIONS;
	opt->nla_len = (u16)(NLA_HDRLEN + len);
	if (len)
		memcpy((char *)opt + NLA_HDRLEN, attrs, len);
	return opt;
}

struct cake_glue *cake_glue_new(uint64_t seed, uint32_t mtu, const void *attrs, uint32_t attrs_len,
				uint64_t now_ns, int *err)
{
	struct cake_glue *g = (struct cake_glue *)calloc(1, sizeof(*g));
	struct nlattr *opt;
	uint64_t s = seed;
	int rc;

	if (!g) {
		*err = -ENOMEM;
		return NULL;
	}
	g->sch = (struct Qdisc *)calloc(1, sizeof(struct Qdisc) + sizeof(struct cake_sched_data));
	opt = glue_make_opts(attrs, attrs_len);
	if (!g->sch || !opt) {
		free(g->sch);
		free(opt);
		free(g);
		*err = -ENOMEM;
		return NULL;
	}

	g->ctx.rng = splitmix64(&s) | 1;
	g->ctx.hashrnd = (u32)splitmix64(&s);
	g->nd.dev.mtu = mtu;
	g->nd.dev.hard_header_len = 0;
	g->nd.dev.num_tx_queues = 1;
	g->nd.txq.qdisc_sleeping = g->sch;
	g->sch->dev = &g->nd.dev;
	g->sch->dev_queue = &g->nd.txq;
	g->sch->handle = 0x00010000;

	glue_enter(g, now_ns);
	rc = cake_init(g->sch, opt, NULL);
	if (rc) {
		cake_destroy(g->sch);
		glue_leave();
		free(opt);
		free(g->sch);
		free(g);
		*err = rc;
		return NULL;
	}
	glue_leave();
	free(opt);
	*err = 0;
	return g;
}

int cake_glue_change(struct cake_glue *g, uint32_t mtu, const void *attrs, uint32_t attrs_len, uint64_t now_ns)
{
	struct nlattr *opt = glue_make_opts(attrs, attrs_len);
	int rc;

	if (!opt)
		return -ENOMEM;
	if (mtu)
		g->nd.dev.mtu = mtu;
	glue_enter(g, now_ns);
	rc = cake_change(g->sch, opt, NULL);
	glue_leave();
	free(opt);
	return rc;
}

int cake_glue_enqueue(struct cake_glue *g, uint64_t cookie, uint32_t len, const uint8_t *hdr, uint32_t hdr_len,
		      uint16_t protocol, uint32_t hash, bool l4_hash, uint32_t mark, uint64_t now_ns)
{
	struct sk_buff *to_free = NULL;
	struct sk_buff *skb;
	int rc;

	glue_enter(g, now_ns);
	skb = glue_skb_alloc(g);
	if (!skb) {
		glue_leave();
		return NET_XMIT_DROP;
	}
	if (hdr_len > KSHIM_HDR_MAX)
		hdr_len = KSHIM_HDR_MAX;
	if (hdr_len)
		memcpy(skb->hdr, hdr, hdr_len);
	skb->hdr_len = hdr_len;
	skb->cookie = cookie;
	skb->len = len;
	skb->truesize = len + 256; /* the kernel's per-skb overhead, roughly */
	skb->hash = hash;
	skb->l4_hash = l4_hash;
	skb->mark = mark;
	skb->protocol = htons(protocol);
	qdisc_skb_cb(skb)->pkt_len = len;
	qdisc_skb_cb(skb)->pkt_segs = 1;

	rc = cake_enqueue(skb, g->sch, &to_free);
	glue_leave();
	return rc;
}

bool cake_glue_dequeue(struct cake_glue *g, uint64_t now_ns, uint64_t *cookie, uint64_t *enqueue_ns)
{
	struct cake_sched_data *q = glue_priv(g);
	struct sk_buff *skb;

	glue_enter(g, now_ns);
	/* The watchdog "fires" once the caller comes back at or after its expiry. */
	if (q->watchdog.queued && now_ns >= q->watchdog.expires)
		q->watchdog.queued = false;
	skb = cake_dequeue(g->sch);
	if (skb) {
		*cookie = skb->cookie;
		*enqueue_ns = (uint64_t)cobalt_get_enqueue_time(skb);
		glue_skb_recycle(g, skb);
	}
	glue_leave();
	return skb != NULL;
}

uint64_t cake_glue_wake_ns(const struct cake_glue *g)
{
	const struct cake_sched_data *q = glue_priv(g);

	return q->watchdog.queued ? q->watchdog.expires : 0;
}

uint32_t cake_glue_take_dropped(struct cake_glue *g, uint64_t *out, uint32_t cap)
{
	uint32_t n = g->n_dropped < cap ? g->n_dropped : cap;

	memcpy(out, g->dropped, sizeof(uint64_t) * n);
	memmove(g->dropped, g->dropped + n, sizeof(uint64_t) * (g->n_dropped - n));
	g->n_dropped -= n;
	return n;
}

uint32_t cake_glue_qlen(const struct cake_glue *g)
{
	return g->sch->q.qlen;
}

uint32_t cake_glue_backlog(const struct cake_glue *g)
{
	return g->sch->qstats.backlog;
}

static uint32_t ns_to_us32(u64 ns)
{
	return (uint32_t)(ns / 1000);
}

void cake_glue_stats(const struct cake_glue *g, struct cake_glue_stats *out)
{
	const struct cake_sched_data *q = glue_priv(g);
	uint32_t i;

	memset(out, 0, sizeof(*out));
	out->capacity_estimate = q->avg_peak_bandwidth;
	out->memory_limit = q->buffer_limit;
	out->memory_used = q->buffer_max_used;
	out->memory_now = q->buffer_used;
	out->avg_netoff = (q->avg_netoff + 0x8000) >> 16;
	out->min_netlen = q->min_netlen;
	out->max_netlen = q->max_netlen;
	out->min_adjlen = q->min_adjlen;
	out->max_adjlen = q->max_adjlen;
	out->active_queues = q->active_queues;
	out->qlen = g->sch->q.qlen;
	out->backlog = g->sch->qstats.backlog;
	out->overlimits = g->sch->qstats.overlimits;
	out->drops = g->sch->qstats.drops;
	out->tin_cnt = q->tin_cnt;
	out->dequeued_bytes = g->sch->bstats.bytes;
	out->dequeued_packets = g->sch->bstats.packets;

	/* Same selection and arithmetic as cake_dump_stats(). */
	for (i = 0; i < q->tin_cnt && i < CAKE_GLUE_MAX_TINS; i++) {
		const struct cake_tin_data *b = &q->tins[q->tin_order[i]];
		struct cake_glue_tin_stats *t = &out->tin[i];

		t->threshold_rate = b->tin_rate_bps;
		t->sent_bytes = b->bytes;
		t->sent_packets = b->packets;
		t->backlog_bytes = b->tin_backlog;
		t->target_us = ns_to_us32(b->cparams.target);
		t->interval_us = ns_to_us32(b->cparams.interval);
		t->dropped_packets = b->tin_dropped;
		t->ecn_marked = b->tin_ecn_mark;
		t->ack_drops = b->ack_drops;
		t->peak_delay_us = ns_to_us32(b->peak_delay);
		t->avg_delay_us = ns_to_us32(b->avge_delay);
		t->base_delay_us = ns_to_us32(b->base_delay);
		t->way_hits = b->way_hits;
		t->way_misses = b->way_misses;
		t->way_collisions = b->way_collisions;
		t->sparse_flows = (uint32_t)b->sparse_flow_count + b->decaying_flow_count;
		t->bulk_flows = b->bulk_flow_count;
		t->unresponsive_flows = b->unresponsive_flow_count;
		t->max_skblen = b->max_skblen;
		t->flow_quantum = b->flow_quantum;
		t->drop_overlimit = b->drop_overlimit;
	}
}

int cake_glue_dump_config(struct cake_glue *g, uint8_t *buf, uint32_t cap)
{
	struct sk_buff *skb = (struct sk_buff *)calloc(1, sizeof(*skb));
	int rc;

	if (!skb)
		return -ENOMEM;
	skb->data = buf;
	skb->nl_cap = cap;
	skb->len = 0;
	glue_enter(g, 0);
	rc = cake_dump(g->sch, skb);
	glue_leave();
	if (rc < 0) {
		free(skb);
		return -EMSGSIZE;
	}
	rc = (int)skb->len;
	free(skb);
	return rc;
}

void cake_glue_free(struct cake_glue *g)
{
	struct sk_buff *skb;

	if (!g)
		return;
	glue_enter(g, 0);
	cake_reset(g->sch); /* leftover packets go through kshim_packet_gone() */
	cake_destroy(g->sch);
	glue_leave();
	while ((skb = g->pool) != NULL) {
		g->pool = skb->next;
		free(skb);
	}
	free(g->dropped);
	free(g->sch);
	free(g);
}

struct cake_glue_cobalt {
	/* kshim_cur while CAKE's code runs: BLUE draws its random numbers from it. */
	struct kshim_ctx ctx;
	struct cobalt_vars vars;
	struct cobalt_params params;
};

/* Makes c's context the current one; returns the one to restore. */
static struct kshim_ctx *cobalt_enter(struct cake_glue_cobalt *c, uint64_t now_ns)
{
	struct kshim_ctx *prev = kshim_cur;

	c->ctx.now_ns = (s64)now_ns;
	kshim_cur = &c->ctx;
	return prev;
}

/* The cparams cake_set_rate() gives a tin of this rate. */
static bool cobalt_params_for(struct cobalt_params *out, uint64_t rate_bytes_per_sec, uint32_t mtu,
			      uint64_t target_ns, uint64_t rtt_ns)
{
	/* A tin is large (it holds every flow queue): keep it off the stack. */
	struct cake_tin_data *tin = (struct cake_tin_data *)calloc(1, sizeof(*tin));

	if (!tin)
		return false;
	cake_set_rate(tin, rate_bytes_per_sec, mtu, target_ns, rtt_ns);
	*out = tin->cparams;
	free(tin);
	return true;
}

struct cake_glue_cobalt *cake_glue_cobalt_new(uint64_t rate_bytes_per_sec, uint32_t mtu, uint64_t target_ns,
					      uint64_t rtt_ns)
{
	struct cake_glue_cobalt *c = (struct cake_glue_cobalt *)calloc(1, sizeof(*c));
	uint64_t s;

	if (!c)
		return NULL;
	if (!cobalt_params_for(&c->params, rate_bytes_per_sec, mtu, target_ns, rtt_ns)) {
		free(c);
		return NULL;
	}
	s = (uint64_t)(uintptr_t)c;
	c->ctx.rng = splitmix64(&s) | 1;
	cobalt_vars_init(&c->vars);
	return c;
}

/* A new rate keeps the CoDel/BLUE state, as cake_set_rate() keeps every
 * flow's cobalt_vars when a tin's rate changes. */
bool cake_glue_cobalt_set_rate(struct cake_glue_cobalt *c, uint64_t rate_bytes_per_sec, uint32_t mtu,
			       uint64_t target_ns, uint64_t rtt_ns)
{
	return cobalt_params_for(&c->params, rate_bytes_per_sec, mtu, target_ns, rtt_ns);
}

bool cake_glue_cobalt_should_drop(struct cake_glue_cobalt *c, uint64_t now_ns, uint64_t enqueued_ns,
				  uint32_t bulk_flows)
{
	struct kshim_ctx *prev = cobalt_enter(c, now_ns);
	struct sk_buff skb;
	bool drop;

	memset(&skb, 0, sizeof(skb));
	cobalt_set_enqueue_time(&skb, (ktime_t)enqueued_ns);
	drop = cobalt_should_drop(&c->vars, &c->params, (ktime_t)now_ns, &skb, bulk_flows) != QDISC_DROP_UNSPEC;
	kshim_cur = prev;
	return drop;
}

void cake_glue_cobalt_queue_empty(struct cake_glue_cobalt *c, uint64_t now_ns)
{
	struct kshim_ctx *prev = cobalt_enter(c, now_ns);

	cobalt_queue_empty(&c->vars, &c->params, (ktime_t)now_ns);
	kshim_cur = prev;
}

void cake_glue_cobalt_queue_full(struct cake_glue_cobalt *c, uint64_t now_ns)
{
	struct kshim_ctx *prev = cobalt_enter(c, now_ns);

	cobalt_queue_full(&c->vars, &c->params, (ktime_t)now_ns);
	kshim_cur = prev;
}

void cake_glue_cobalt_free(struct cake_glue_cobalt *c)
{
	free(c);
}

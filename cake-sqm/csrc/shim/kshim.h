/* kshim.h - a thin stand-in for the Linux kernel API that net/sched/sch_cake.c uses.
 *
 * sch_cake.c is compiled UNCHANGED (build.rs verifies its SHA-256). Everything it needs from the
 * kernel is provided here, in plain C11 so that MSVC (/std:c11), gcc and clang can all build it.
 * Each of sch_cake.c's #include lines resolves to a file in this directory that only includes this
 * header. Where a kernel function has real behaviour, the comment names the kernel file/function
 * whose semantics it follows.
 *
 * Packets are never copied: an sk_buff here is a small descriptor with a snapshot of the first
 * bytes of the packet (an IP header, real or synthesised from the UDP endpoints) and a 64-bit
 * cookie that the Rust side uses as the handle of the real packet.
 *
 * Only little-endian targets are supported (the bit-field header structs and the byte-order
 * macros below assume it).
 */
#ifndef KSHIM_H
#define KSHIM_H

/* While the libc headers are read, <linux/...> must still mean the real kernel headers some of
 * them include (see the other files in this directory). */
#define KSHIM_IN_LIBC 1
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#undef KSHIM_IN_LIBC

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "cake-sqm shim supports little-endian targets only"
#endif
#endif

#ifdef _MSC_VER
#define KSHIM_TLS __declspec(thread)
#define KSHIM_FALLTHROUGH ((void)0)
#define likely(x) (x)
#define unlikely(x) (x)
#else
#define KSHIM_TLS _Thread_local
#define KSHIM_FALLTHROUGH __attribute__((fallthrough))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

struct Qdisc;

/* ---- basic types ------------------------------------------------------------------------ */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef u16 __be16;
typedef u32 __be32;
typedef u64 netdev_features_t;
typedef s64 ktime_t;

#define fallthrough KSHIM_FALLTHROUGH
#define __rcu
#define __read_mostly
#define __init
#define __exit
#define __force
#define __aligned(x)
#define BIT(nr) (1UL << (nr))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, val) ((x) = (val))
#define IS_ENABLED(option) 0
#define IS_ERR_OR_NULL(p) ((p) == NULL)
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))

#ifndef EOPNOTSUPP
#define EOPNOTSUPP 95
#endif
#ifndef ENOMEM
#define ENOMEM 12
#endif
#ifndef ERANGE
#define ERANGE 34
#endif
#ifndef EMSGSIZE
#define EMSGSIZE 90
#endif

#define USEC_PER_SEC 1000000UL
#define NSEC_PER_USEC 1000LL
#define NSEC_PER_MSEC 1000000LL
#define NSEC_PER_SEC 1000000000LL

/* min/max: the kernel versions only add type checking. */
#undef min
#undef max
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
#define max_t(type, a, b) ((type)(a) > (type)(b) ? (type)(a) : (type)(b))

/* ---- byte order (constant expressions: sch_cake.c uses htons() in case labels) ----------- */
#define KSHIM_BSWAP32(x)                                                                         \
	((u32)((((u32)(x) & 0xffu) << 24) | (((u32)(x) & 0xff00u) << 8) |                            \
	       (((u32)(x) >> 8) & 0xff00u) | (((u32)(x) >> 24) & 0xffu)))
#define htons(x) ((__be16)((((x) & 0xffu) << 8) | (((x) >> 8) & 0xffu)))
#define ntohs(x) htons(x)
#define ntohl(x) KSHIM_BSWAP32(x)
#define htonl(x) KSHIM_BSWAP32(x)
#define cpu_to_be32(x) ((__be32)KSHIM_BSWAP32(x))

static inline u32 rol32(u32 word, unsigned int shift)
{
	return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

static inline u32 get_unaligned_be32(const void *p)
{
	u32 v;

	memcpy(&v, p, sizeof(v));
	return KSHIM_BSWAP32(v);
}

/* jhash.h only ever uses get_unaligned() on u32 pointers. */
static inline u32 kshim_get_unaligned_u32(const void *p)
{
	u32 v;

	memcpy(&v, p, sizeof(v));
	return v;
}
#define get_unaligned(ptr) kshim_get_unaligned_u32(ptr)

/* include/linux/kernel.h */
static inline u32 reciprocal_scale(u32 val, u32 ep_ro)
{
	return (u32)(((u64)val * ep_ro) >> 32);
}

#define do_div(n, base) ((n) /= (base))
static inline u64 div64_u64(u64 a, u64 b)
{
	return a / b;
}

/* include/asm-generic/bitops/__ffs.h: index of the lowest set bit. */
static inline unsigned long __ffs(unsigned long word)
{
	unsigned long num = 0;

	while (!(word & 1UL)) {
		word >>= 1;
		num++;
	}
	return num;
}

/* ---- list.h ----------------------------------------------------------------------------- */
struct list_head {
	struct list_head *next, *prev;
};

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}
static inline void __list_add(struct list_head *entry, struct list_head *prev, struct list_head *next)
{
	next->prev = entry;
	entry->next = next;
	entry->prev = prev;
	prev->next = entry;
}
static inline void list_add_tail(struct list_head *entry, struct list_head *head)
{
	__list_add(entry, head->prev, head);
}
static inline void __list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}
static inline void list_del_init(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	INIT_LIST_HEAD(entry);
}
static inline void list_move_tail(struct list_head *list, struct list_head *head)
{
	__list_del(list->prev, list->next);
	list_add_tail(list, head);
}
static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}
#define list_first_entry(ptr, type, member) container_of((ptr)->next, type, member)

/* ---- time (include/linux/ktime.h) -------------------------------------------------------- */
/* The clock is whatever the glue wrote into the current context before the call: a virtual
 * clock that the Rust side derives from the caller's Instant. */
struct kshim_ctx {
	s64 now_ns;
	u32 hashrnd; /* seed of flow_hash_from_keys() */
	u64 rng;     /* xorshift64* state of get_random_u*() */
};
extern KSHIM_TLS struct kshim_ctx *kshim_cur;

#define KTIME_MAX INT64_MAX
static inline ktime_t ktime_get(void)
{
	return kshim_cur->now_ns;
}
static inline ktime_t ns_to_ktime(u64 ns)
{
	return (ktime_t)ns;
}
static inline s64 ktime_to_ns(ktime_t kt)
{
	return kt;
}
static inline s64 ktime_to_us(ktime_t kt)
{
	return kt / NSEC_PER_USEC;
}
static inline ktime_t ktime_add_ns(ktime_t kt, u64 ns)
{
	return kt + (s64)ns;
}
static inline ktime_t ktime_add_ms(ktime_t kt, u64 ms)
{
	return kt + (s64)ms * NSEC_PER_MSEC;
}
static inline ktime_t ktime_sub(ktime_t a, ktime_t b)
{
	return a - b;
}
static inline int ktime_compare(ktime_t a, ktime_t b)
{
	return a < b ? -1 : (a > b ? 1 : 0);
}
static inline bool ktime_before(ktime_t a, ktime_t b)
{
	return ktime_compare(a, b) < 0;
}
static inline bool ktime_after(ktime_t a, ktime_t b)
{
	return ktime_compare(a, b) > 0;
}

u32 kshim_random_u32(void);
static inline u32 get_random_u32(void)
{
	return kshim_random_u32();
}
static inline u16 get_random_u16(void)
{
	return (u16)(kshim_random_u32() >> 16);
}

/* ---- memory ----------------------------------------------------------------------------- */
#define kvzalloc_objs(type, n) ((type *)calloc((n), sizeof(type)))
#define kvfree(p) free(p)

/* ---- module boilerplate (all no-ops: the file is used as a library, not a module) ------- */
#define THIS_MODULE NULL
#define MODULE_ALIAS_NET_SCH(name)
#define MODULE_AUTHOR(s)
#define MODULE_LICENSE(s)
#define MODULE_DESCRIPTION(s)
#define MODULE_IMPORT_NS(s)
#define module_init(fn) static void *kshim_keep_init_##fn(void) { return (void *)fn; }
#define module_exit(fn) static void *kshim_keep_exit_##fn(void) { return (void *)fn; }

/* ---- protocol numbers and headers -------------------------------------------------------- */
#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_IPV6 41
#define IPPROTO_SCTP 132
#define IPPROTO_UDPLITE 136
#define INET_ECN_MASK 3

struct in6_addr {
	u8 s6_addr[16];
};

struct iphdr {
	u8 ihl : 4, version : 4;
	u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	u8 ttl;
	u8 protocol;
	__be16 check;
	__be32 saddr;
	__be32 daddr;
};

struct ipv6hdr {
	u8 priority : 4, version : 4;
	u8 flow_lbl[3];
	__be16 payload_len;
	u8 nexthdr;
	u8 hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
};

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__be16 check;
};

struct tcphdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	u16 res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
	__be16 window;
	u16 check;
	__be16 urg_ptr;
};

_Static_assert(sizeof(struct iphdr) == 20, "iphdr layout");
_Static_assert(sizeof(struct ipv6hdr) == 40, "ipv6hdr layout");
_Static_assert(sizeof(struct udphdr) == 8, "udphdr layout");
_Static_assert(sizeof(struct tcphdr) == 20, "tcphdr layout");

union tcp_word_hdr {
	struct tcphdr hdr;
	__be32 words[5];
};
#define tcp_flag_word(tp) (((union tcp_word_hdr *)(tp))->words[3])
#define TCP_FLAG_CWR cpu_to_be32(0x00800000)
#define TCP_FLAG_ECE cpu_to_be32(0x00400000)
#define TCP_FLAG_SYN cpu_to_be32(0x00020000)
#define TCP_FLAG_ACK cpu_to_be32(0x00100000)

#define TCPOPT_EOL 0
#define TCPOPT_NOP 1
#define TCPOPT_MSS 2
#define TCPOPT_WINDOW 3
#define TCPOPT_SACK_PERM 4
#define TCPOPT_SACK 5
#define TCPOPT_TIMESTAMP 8
#define TCPOPT_MD5SIG 19
#define TCPOPT_FASTOPEN 34
#define TCPOPT_EXP 254
#define TCPOLEN_TIMESTAMP 10
#define TCPOLEN_SACK_BASE 2

struct tcp_sack_block_wire {
	__be32 start_seq;
	__be32 end_seq;
};

static inline unsigned int __tcp_hdrlen(const struct tcphdr *th)
{
	return th->doff * 4;
}
/* include/net/tcp.h */
static inline bool before(u32 seq1, u32 seq2)
{
	return (s32)(seq1 - seq2) < 0;
}
#define after(seq2, seq1) before(seq1, seq2)

static inline int ipv6_addr_cmp(const struct in6_addr *a1, const struct in6_addr *a2)
{
	return memcmp(a1, a2, sizeof(struct in6_addr));
}

/* include/net/dsfield.h */
static inline u8 ipv4_get_dsfield(const struct iphdr *iph)
{
	return iph->tos;
}
static inline u8 ipv6_get_dsfield(const struct ipv6hdr *ipv6h)
{
	u16 w;

	memcpy(&w, ipv6h, sizeof(w));
	return (u8)((ntohs(w) >> 4) & 0xff);
}
/* The kernel versions also patch the checksum; the header here is a snapshot nobody checks. */
static inline void ipv4_change_dsfield(struct iphdr *iph, u8 mask, u8 value)
{
	iph->tos = (u8)((iph->tos & mask) | value);
}
static inline void ipv6_change_dsfield(struct ipv6hdr *ipv6h, u8 mask, u8 value)
{
	u16 w;

	memcpy(&w, ipv6h, sizeof(w));
	w = htons((ntohs(w) & (u16)~(((u16)mask) << 4)) | ((u16)value << 4));
	memcpy(ipv6h, &w, sizeof(w));
}

/* ---- sk_buff ---------------------------------------------------------------------------- */
#define KSHIM_HDR_MAX 128
#define SKB_GSO_TCPV4 (1 << 1)
#define SKB_GSO_TCPV6 (1 << 4)
#define NETIF_F_GSO_MASK 0

struct skb_shared_info {
	u16 gso_size;
	u16 gso_segs;
	u32 gso_type;
};

/* include/net/sch_generic.h: struct qdisc_skb_cb. The private area is 8-byte aligned here
 * (u64 array) because struct cobalt_skb_cb holds a 64-bit time. */
#define QDISC_CB_PRIV_LEN 24
struct qdisc_skb_cb {
	u32 pkt_len;
	u16 slave_dev_queue_mapping;
	u16 tc_classid;
	u16 pkt_segs;
	u16 pad[3];
	u64 data[QDISC_CB_PRIV_LEN / 8];
};

struct sk_buff {
	struct sk_buff *next;
	u32 len;
	u32 truesize;
	u32 hash;
	u32 mark;
	u32 priority;
	bool l4_hash;
	bool encapsulation;
	__be16 protocol;
	u16 transport_header;
	u8 *data; /* the header snapshot (hdr), or the output buffer of a netlink dump skb */
	u32 hdr_len;
	u32 nl_cap; /* capacity of data when this skb is a netlink dump buffer */
	u64 cookie; /* the Rust side's handle of the real packet */
	struct skb_shared_info shinfo;
	union {
		char cb[48];
		u64 cb_align[6];
	};
	u8 hdr[KSHIM_HDR_MAX];
};
_Static_assert(sizeof(struct qdisc_skb_cb) <= 48, "qdisc_skb_cb must fit sk_buff.cb");

#define qdisc_skb_cb(skb) ((struct qdisc_skb_cb *)(skb)->cb)
#define qdisc_cb_private_validate(skb, sz)                                                       \
	_Static_assert((sz) <= QDISC_CB_PRIV_LEN, "qdisc cb private area too small")
#define qdisc_pkt_len(skb) (qdisc_skb_cb(skb)->pkt_len)
#define qdisc_pkt_segs(skb) (qdisc_skb_cb(skb)->pkt_segs)

static inline void skb_mark_not_on_list(struct sk_buff *skb)
{
	skb->next = NULL;
}
#define skb_list_walk_safe(first, skb, next_skb)                                                 \
	for ((skb) = (first), (next_skb) = (skb) ? (skb)->next : NULL; (skb);                        \
	     (skb) = (next_skb), (next_skb) = (skb) ? (skb)->next : NULL)

static inline unsigned int skb_network_offset(const struct sk_buff *skb)
{
	(void)skb;
	return 0;
}
static inline int skb_transport_offset(const struct sk_buff *skb)
{
	return skb->transport_header;
}
static inline int skb_inner_transport_offset(const struct sk_buff *skb)
{
	return skb->transport_header;
}
/* include/linux/skbuff.h skb_header_pointer(): the snapshot is the whole linear area; reads
 * past it behave as if the packet ended there. */
static inline void *skb_header_pointer(const struct sk_buff *skb, int offset, int len, void *buffer)
{
	(void)buffer;
	if (offset < 0 || len < 0 || (u32)offset + (u32)len > skb->hdr_len)
		return NULL;
	return (void *)(skb->data + offset);
}
static inline __be16 skb_protocol(const struct sk_buff *skb, bool skip_vlan)
{
	(void)skip_vlan;
	return skb->protocol;
}
static inline bool pskb_may_pull(struct sk_buff *skb, unsigned int len)
{
	return len <= skb->hdr_len;
}
static inline int skb_try_make_writable(struct sk_buff *skb, unsigned int write_len)
{
	return write_len <= skb->hdr_len ? 0 : -ENOMEM;
}
static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
	return (struct iphdr *)(skb->data + skb_network_offset(skb));
}
static inline struct ipv6hdr *ipv6_hdr(const struct sk_buff *skb)
{
	return (struct ipv6hdr *)(skb->data + skb_network_offset(skb));
}
static inline u32 iph_totlen(const struct sk_buff *skb, const struct iphdr *iph)
{
	(void)skb;
	return ntohs(iph->tot_len);
}
static inline u32 ipv6_payload_len(const struct sk_buff *skb, const struct ipv6hdr *ip6h)
{
	(void)skb;
	return ntohs(ip6h->payload_len);
}
static inline struct skb_shared_info *skb_shinfo(const struct sk_buff *skb)
{
	return (struct skb_shared_info *)&skb->shinfo;
}
/* Packets are never GSO here (pkt_segs is always 1), so these are only compiled, not reached. */
static inline netdev_features_t netif_skb_features(struct sk_buff *skb)
{
	(void)skb;
	return 0;
}
static inline struct sk_buff *skb_gso_segment(struct sk_buff *skb, netdev_features_t features)
{
	(void)skb;
	(void)features;
	return NULL;
}
/* The outer packets are UDP, never ECN-capable: returning 0 makes cake drop instead of mark
 * (include/net/inet_ecn.h INET_ECN_set_ce() returns 0 for a not-ECT packet). */
static inline int INET_ECN_set_ce(struct sk_buff *skb)
{
	(void)skb;
	return 0;
}

/* ---- flow dissector (include/net/flow_dissector.h, net/core/flow_dissector.c) ------------- */
#define FLOW_DISSECTOR_KEY_IPV4_ADDRS 2
#define FLOW_DISSECTOR_KEY_IPV6_ADDRS 3
#define FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL 4

struct flow_dissector_key_control {
	u16 thoff;
	u16 addr_type;
	u32 flags;
};
struct flow_dissector_key_basic {
	__be16 n_proto;
	u8 ip_proto;
	u8 padding;
};
struct flow_dissector_key_tags {
	u32 flow_label;
};
struct flow_dissector_key_keyid {
	__be32 keyid;
};
struct flow_dissector_key_ports {
	union {
		__be32 ports;
		struct {
			__be16 src;
			__be16 dst;
		};
	};
};
struct flow_dissector_key_ipv4_addrs {
	__be32 src;
	__be32 dst;
};
struct flow_dissector_key_ipv6_addrs {
	struct in6_addr src;
	struct in6_addr dst;
};
struct flow_keys {
	struct flow_dissector_key_control control;
	struct flow_dissector_key_basic basic;
	struct flow_dissector_key_tags tags;
	struct flow_dissector_key_keyid keyid;
	struct flow_dissector_key_ports ports;
	union {
		struct flow_dissector_key_ipv4_addrs v4addrs;
		struct flow_dissector_key_ipv6_addrs v6addrs;
	} addrs;
};

bool skb_flow_dissect_flow_keys(const struct sk_buff *skb, struct flow_keys *flow, unsigned int flags);
u32 flow_hash_from_keys(struct flow_keys *keys);

/* ---- netlink (include/net/netlink.h, lib/nlattr.c) ---------------------------------------- */
#define NLA_ALIGNTO 4
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN ((int)NLA_ALIGN(sizeof(struct nlattr)))
#define NLA_TYPE_MASK 0x3fff
#define TCA_OPTIONS 2
#define TCA_STATS_APP 4

struct nlattr {
	u16 nla_len;
	u16 nla_type;
};
enum { NLA_UNSPEC, NLA_U8, NLA_U16, NLA_U32, NLA_U64, NLA_S32 };
struct nla_policy {
	u8 type;
	u16 len;
};
struct netlink_ext_ack {
	const char *msg;
};
#define NL_SET_ERR_MSG(extack, msg) ((void)(extack))
#define NL_SET_ERR_MSG_ATTR(extack, attr, msg) ((void)(extack), (void)(attr))

int nla_parse_nested_deprecated(struct nlattr *tb[], int maxtype, const struct nlattr *nla,
				const struct nla_policy *policy, struct netlink_ext_ack *extack);
static inline void *nla_data(const struct nlattr *nla)
{
	return (void *)((char *)nla + NLA_HDRLEN);
}
static inline int nla_len(const struct nlattr *nla)
{
	return (int)nla->nla_len - NLA_HDRLEN;
}
static inline u32 nla_get_u32(const struct nlattr *nla)
{
	u32 v;

	memcpy(&v, nla_data(nla), sizeof(v));
	return v;
}
static inline s32 nla_get_s32(const struct nlattr *nla)
{
	s32 v;

	memcpy(&v, nla_data(nla), sizeof(v));
	return v;
}
static inline u64 nla_get_u64(const struct nlattr *nla)
{
	u64 v;

	memcpy(&v, nla_data(nla), sizeof(v));
	return v;
}
int nla_put(struct sk_buff *skb, int attrtype, int attrlen, const void *data);
static inline int nla_put_u32(struct sk_buff *skb, int attrtype, u32 value)
{
	return nla_put(skb, attrtype, sizeof(u32), &value);
}
static inline int nla_put_s32(struct sk_buff *skb, int attrtype, s32 value)
{
	return nla_put(skb, attrtype, sizeof(s32), &value);
}
static inline int nla_put_u64_64bit(struct sk_buff *skb, int attrtype, u64 value, int padattr)
{
	(void)padattr; /* the buffer is 4-byte aligned only; the pad attribute is not needed here */
	return nla_put(skb, attrtype, sizeof(u64), &value);
}
struct nlattr *nla_nest_start_noflag(struct sk_buff *skb, int attrtype);
int nla_nest_end(struct sk_buff *skb, struct nlattr *start);
void nla_nest_cancel(struct sk_buff *skb, struct nlattr *start);

/* ---- qdisc (include/net/sch_generic.h, pkt_sched.h) --------------------------------------- */
#define NET_XMIT_SUCCESS 0x00
#define NET_XMIT_DROP 0x01
#define NET_XMIT_CN 0x02
#define __NET_XMIT_STOLEN 0x00010000
#define __NET_XMIT_BYPASS 0x00020000
#define TC_H_MAJ(h) ((h) & 0xFFFF0000U)
#define TC_H_MIN(h) ((h) & 0x0000FFFFU)
#define TCQ_F_CAN_BYPASS 1
#define TCQ_F_DEQUEUE_DROPS 0x10

enum qdisc_drop_reason {
	QDISC_DROP_UNSPEC = 0,
	QDISC_DROP_GENERIC,
	QDISC_DROP_OVERLIMIT,
	QDISC_DROP_CONGESTED,
	QDISC_DROP_FLOOD_PROTECTION,
};
#define SKB_DROP_REASON_QUEUE_PURGE 1

struct gnet_stats_queue {
	u32 qlen;
	u32 backlog;
	u32 drops;
	u32 requeues;
	u32 overlimits;
};
struct gnet_stats_basic {
	u64 bytes;
	u64 packets;
};
struct gnet_dump {
	struct sk_buff *skb;
};
struct tcmsg {
	u32 tcm_handle;
};
struct qdisc_walker {
	int stop;
	int skip;
	int count;
	int (*fn)(struct Qdisc *, unsigned long cl, struct qdisc_walker *);
};

struct net_device {
	u32 mtu;
	u32 hard_header_len;
	unsigned int num_tx_queues;
};
struct netdev_queue {
	struct Qdisc *qdisc_sleeping;
};
/* The glue allocates a device together with its single tx queue. */
struct kshim_netdev {
	struct net_device dev;
	struct netdev_queue txq;
};

struct Qdisc {
	struct {
		u32 qlen;
	} q;
	struct gnet_stats_queue qstats;
	struct gnet_stats_basic bstats;
	u32 limit;
	u32 flags;
	u32 handle;
	u32 pad;
	struct net_device *dev;
	struct netdev_queue *dev_queue;
};
_Static_assert(sizeof(struct Qdisc) % 8 == 0, "qdisc_priv() must stay 8-byte aligned");

/* The private area follows the Qdisc in one allocation (cake_glue_new). */
static inline void *qdisc_priv(struct Qdisc *q)
{
	return (void *)(q + 1);
}
static inline struct net_device *qdisc_dev(const struct Qdisc *q)
{
	return q->dev;
}
static inline u32 psched_mtu(const struct net_device *dev)
{
	return dev->mtu + dev->hard_header_len;
}
static inline struct netdev_queue *netdev_get_tx_queue(const struct net_device *dev, unsigned int index)
{
	(void)index;
	return &container_of(dev, struct kshim_netdev, dev)->txq;
}
#define rcu_dereference(p) (p)
#define rcu_dereference_bh(p) (p)
#define rtnl_dereference(p) (p)
#define sch_tree_lock(sch) ((void)(sch))
#define sch_tree_unlock(sch) ((void)(sch))

static inline void qdisc_qstats_drop(struct Qdisc *sch)
{
	sch->qstats.drops++;
}
static inline void qstats_backlog_add(struct Qdisc *sch, u32 len)
{
	sch->qstats.backlog += len;
}
static inline void qstats_backlog_sub(struct Qdisc *sch, u32 len)
{
	sch->qstats.backlog -= len;
}
static inline void qdisc_qlen_inc(struct Qdisc *sch)
{
	sch->q.qlen++;
}
static inline void qdisc_qlen_dec(struct Qdisc *sch)
{
	sch->q.qlen--;
}
static inline void qdisc_bstats_update(struct Qdisc *sch, const struct sk_buff *skb)
{
	sch->bstats.bytes += qdisc_pkt_len(skb);
	sch->bstats.packets += qdisc_pkt_segs(skb) > 1 ? qdisc_pkt_segs(skb) : 1;
}
/* There is no parent qdisc to tell (include/net/sch_generic.h qdisc_tree_reduce_backlog()). */
static inline void qdisc_tree_reduce_backlog(struct Qdisc *sch, int n, int len)
{
	(void)sch;
	(void)n;
	(void)len;
}

/* Dropped or consumed packets are reported to the Rust side by cookie; the kernel version
 * chains them on a to_free list instead. */
void kshim_packet_gone(struct sk_buff *skb);
static inline void __qdisc_drop(struct sk_buff *skb, struct sk_buff **to_free)
{
	(void)to_free;
	kshim_packet_gone(skb);
}
static inline int qdisc_drop(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
	__qdisc_drop(skb, to_free);
	qdisc_qstats_drop(sch);
	return NET_XMIT_DROP;
}
static inline int qdisc_drop_reason(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free,
				    enum qdisc_drop_reason reason)
{
	(void)reason;
	return qdisc_drop(skb, sch, to_free);
}
static inline void qdisc_dequeue_drop(struct Qdisc *sch, struct sk_buff *skb, enum qdisc_drop_reason reason)
{
	(void)sch;
	(void)reason;
	kshim_packet_gone(skb);
}
static inline void kfree_skb_reason(struct sk_buff *skb, int reason)
{
	(void)reason;
	kshim_packet_gone(skb);
}
static inline void consume_skb(struct sk_buff *skb)
{
	kshim_packet_gone(skb);
}

/* include/net/pkt_sched.h qdisc_watchdog: an hrtimer that only ever moves earlier until it
 * fires. "Fires" here means the glue sees a dequeue call at or after `expires`. */
struct qdisc_watchdog {
	u64 expires;
	bool queued;
};
static inline void qdisc_watchdog_init(struct qdisc_watchdog *wd, struct Qdisc *qdisc)
{
	(void)qdisc;
	wd->expires = 0;
	wd->queued = false;
}
static inline void qdisc_watchdog_schedule_ns(struct qdisc_watchdog *wd, u64 expires)
{
	if (wd->queued && wd->expires <= expires)
		return;
	wd->expires = expires;
	wd->queued = true;
}
static inline void qdisc_watchdog_cancel(struct qdisc_watchdog *wd)
{
	wd->queued = false;
}

/* Classifier filters are never attached. */
struct tcf_proto;
struct tcf_block;
struct tcf_result {
	u32 classid;
};
static inline int tcf_block_get(struct tcf_block **p_block, struct tcf_proto **p_filter_chain,
				struct Qdisc *q, struct netlink_ext_ack *extack)
{
	(void)q;
	(void)extack;
	*p_block = NULL;
	*p_filter_chain = NULL;
	return 0;
}
static inline void tcf_block_put(struct tcf_block *block)
{
	(void)block;
}
static inline int tcf_classify_qdisc(struct sk_buff *skb, const struct tcf_proto *tp, struct tcf_result *res,
				     bool compat_mode)
{
	(void)skb;
	(void)tp;
	(void)res;
	(void)compat_mode;
	return -1;
}

/* Statistics dumping for `tc -s`: compiled for completeness, the Rust side reads the structs. */
static inline int gnet_stats_copy_queue(struct gnet_dump *d, void *cpu_q, struct gnet_stats_queue *q, u32 qlen)
{
	(void)d;
	(void)cpu_q;
	(void)q;
	(void)qlen;
	return 0;
}
static inline bool tc_qdisc_stats_dump(struct Qdisc *sch, unsigned long cl, struct qdisc_walker *arg)
{
	(void)sch;
	(void)cl;
	(void)arg;
	return true;
}
static inline struct sk_buff *qdisc_peek_dequeued(struct Qdisc *sch)
{
	(void)sch;
	return NULL;
}

/* cake_mq (a multi-queue wrapper) and module registration: never used, so only stubs. */
struct mq_sched {
	struct Qdisc **qdiscs;
};
struct Qdisc_class_ops {
	struct netdev_queue *(*select_queue)(struct Qdisc *, struct tcmsg *);
	int (*graft)(struct Qdisc *, unsigned long cl, struct Qdisc *, struct Qdisc **, struct netlink_ext_ack *extack);
	struct Qdisc *(*leaf)(struct Qdisc *, unsigned long cl);
	unsigned long (*find)(struct Qdisc *, u32 classid);
	struct tcf_block *(*tcf_block)(struct Qdisc *sch, unsigned long cl, struct netlink_ext_ack *extack);
	unsigned long (*bind_tcf)(struct Qdisc *, unsigned long parent, u32 classid);
	void (*unbind_tcf)(struct Qdisc *, unsigned long cl);
	int (*dump)(struct Qdisc *, unsigned long cl, struct sk_buff *skb, struct tcmsg *);
	int (*dump_stats)(struct Qdisc *, unsigned long cl, struct gnet_dump *);
	void (*walk)(struct Qdisc *, struct qdisc_walker *arg);
};
struct Qdisc_ops {
	const struct Qdisc_class_ops *cl_ops;
	char id[16];
	int priv_size;
	s32 (*enqueue)(struct sk_buff *, struct Qdisc *, struct sk_buff **to_free);
	struct sk_buff *(*dequeue)(struct Qdisc *);
	struct sk_buff *(*peek)(struct Qdisc *);
	int (*init)(struct Qdisc *sch, struct nlattr *arg, struct netlink_ext_ack *extack);
	void (*reset)(struct Qdisc *);
	void (*destroy)(struct Qdisc *);
	int (*change)(struct Qdisc *sch, struct nlattr *arg, struct netlink_ext_ack *extack);
	void (*attach)(struct Qdisc *sch);
	int (*change_real_num_tx)(struct Qdisc *sch, unsigned int new_real_tx);
	int (*dump)(struct Qdisc *, struct sk_buff *);
	int (*dump_stats)(struct Qdisc *, struct gnet_dump *);
	void *owner;
};
static inline int register_qdisc(struct Qdisc_ops *ops)
{
	(void)ops;
	return 0;
}
static inline int unregister_qdisc(struct Qdisc_ops *ops)
{
	(void)ops;
	return 0;
}
static inline void mq_destroy_common(struct Qdisc *sch)
{
	(void)sch;
}
static inline int mq_init_common(struct Qdisc *sch, struct nlattr *opt, struct netlink_ext_ack *extack,
				 const struct Qdisc_ops *ops)
{
	(void)sch;
	(void)opt;
	(void)extack;
	(void)ops;
	return -EOPNOTSUPP;
}
static inline void mq_attach(struct Qdisc *sch)
{
	(void)sch;
}
static inline int mq_change_real_num_tx(struct Qdisc *sch, unsigned int new_real_tx)
{
	(void)sch;
	(void)new_real_tx;
	return 0;
}
static inline int mq_dump_common(struct Qdisc *sch, struct sk_buff *skb)
{
	(void)sch;
	(void)skb;
	return 0;
}
static inline struct netdev_queue *mq_select_queue(struct Qdisc *sch, struct tcmsg *tcm)
{
	(void)sch;
	(void)tcm;
	return NULL;
}
static inline struct Qdisc *mq_leaf(struct Qdisc *sch, unsigned long cl)
{
	(void)sch;
	(void)cl;
	return NULL;
}
static inline unsigned long mq_find(struct Qdisc *sch, u32 classid)
{
	(void)sch;
	(void)classid;
	return 0;
}
static inline void mq_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	(void)sch;
	(void)arg;
}
static inline int mq_dump_class(struct Qdisc *sch, unsigned long cl, struct sk_buff *skb, struct tcmsg *tcm)
{
	(void)sch;
	(void)cl;
	(void)skb;
	(void)tcm;
	return 0;
}
static inline int mq_dump_class_stats(struct Qdisc *sch, unsigned long cl, struct gnet_dump *d)
{
	(void)sch;
	(void)cl;
	(void)d;
	return 0;
}

#include "pkt_sched_cake.h" /* from csrc/linux, see build.rs include paths */

#endif /* KSHIM_H */

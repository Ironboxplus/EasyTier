/* kshim.c - the parts of the kernel API that need real code (see kshim.h). */
#include "kshim.h"
#include "linux/jhash.h"

KSHIM_TLS struct kshim_ctx *kshim_cur;

/* xorshift64* (Vigna): small, fast, good enough for BLUE drop decisions and dithering. The
 * seed comes from the Rust side so that tests are reproducible. */
u32 kshim_random_u32(void)
{
	u64 x = kshim_cur->rng;

	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	kshim_cur->rng = x;
	return (u32)((x * 0x2545F4914F6CDD1DULL) >> 32);
}

/* ---- flow dissector ---------------------------------------------------------------------- */

static bool l4_has_ports(u8 ip_proto)
{
	return ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP || ip_proto == IPPROTO_UDPLITE ||
	       ip_proto == IPPROTO_SCTP;
}

/* net/core/flow_dissector.c __skb_flow_dissect(), reduced to what cake asks for: the IPv4 or
 * IPv6 addresses, the L4 protocol and the TCP/UDP ports of the packet in the header snapshot.
 * Like the kernel with FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL, an IPv6 packet with a non-zero
 * flow label stops after the IP header (the label then stands in for the ports). */
bool skb_flow_dissect_flow_keys(const struct sk_buff *skb, struct flow_keys *flow, unsigned int flags)
{
	const u8 *p = skb->data + skb_network_offset(skb);
	u32 avail = skb->hdr_len - skb_network_offset(skb);
	u32 thoff;
	u8 ip_proto;

	memset(flow, 0, sizeof(*flow));

	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr iph;
		u32 ihl;

		if (avail < sizeof(iph))
			return false;
		memcpy(&iph, p, sizeof(iph));
		ihl = (u32)iph.ihl * 4;
		if (iph.version != 4 || ihl < sizeof(iph))
			return false;

		flow->basic.n_proto = skb->protocol;
		flow->basic.ip_proto = iph.protocol;
		flow->control.addr_type = FLOW_DISSECTOR_KEY_IPV4_ADDRS;
		flow->addrs.v4addrs.src = iph.saddr;
		flow->addrs.v4addrs.dst = iph.daddr;
		thoff = ihl;
		flow->control.thoff = (u16)thoff;
		ip_proto = iph.protocol;
		/* A fragment (more-fragments bit or non-zero offset) carries no ports we can trust. */
		if (ntohs(iph.frag_off) & 0x3fff)
			return true;
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct ipv6hdr ip6;

		if (avail < sizeof(ip6))
			return false;
		memcpy(&ip6, p, sizeof(ip6));
		if (ip6.version != 6)
			return false;

		flow->basic.n_proto = skb->protocol;
		flow->basic.ip_proto = ip6.nexthdr;
		flow->control.addr_type = FLOW_DISSECTOR_KEY_IPV6_ADDRS;
		flow->addrs.v6addrs.src = ip6.saddr;
		flow->addrs.v6addrs.dst = ip6.daddr;
		flow->tags.flow_label = ((u32)(ip6.flow_lbl[0] & 0x0f) << 16) | ((u32)ip6.flow_lbl[1] << 8) |
					ip6.flow_lbl[2];
		thoff = sizeof(ip6);
		flow->control.thoff = (u16)thoff;
		ip_proto = ip6.nexthdr;
		if ((flags & FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL) && flow->tags.flow_label)
			return true;
	} else {
		return false;
	}

	if (l4_has_ports(ip_proto) && avail >= thoff + 4) {
		__be32 ports;

		memcpy(&ports, p + thoff, sizeof(ports));
		flow->ports.ports = ports;
	}
	return true;
}

/* include/net/flow_dissector.h __flow_hash_consistentify(): order the addresses and ports so
 * that both directions of a connection hash alike. */
static void flow_hash_consistentify(struct flow_keys *keys)
{
	switch (keys->control.addr_type) {
	case FLOW_DISSECTOR_KEY_IPV4_ADDRS:
		if (keys->addrs.v4addrs.dst < keys->addrs.v4addrs.src) {
			__be32 tmp = keys->addrs.v4addrs.dst;

			keys->addrs.v4addrs.dst = keys->addrs.v4addrs.src;
			keys->addrs.v4addrs.src = tmp;
		}
		break;
	case FLOW_DISSECTOR_KEY_IPV6_ADDRS:
		if (memcmp(&keys->addrs.v6addrs.dst, &keys->addrs.v6addrs.src, sizeof(struct in6_addr)) < 0) {
			struct in6_addr tmp = keys->addrs.v6addrs.dst;

			keys->addrs.v6addrs.dst = keys->addrs.v6addrs.src;
			keys->addrs.v6addrs.src = tmp;
		}
		break;
	default:
		break;
	}
	if (keys->ports.dst < keys->ports.src) {
		__be16 tmp = keys->ports.dst;

		keys->ports.dst = keys->ports.src;
		keys->ports.src = tmp;
	}
}

/* include/net/flow_dissector.h flow_hash_from_keys(): jhash2 over the key fields with a
 * per-instance random seed (the kernel uses a boot-time random and siphash since 4.x; only
 * the distribution matters to cake). Never returns 0, as in the kernel. */
u32 flow_hash_from_keys(struct flow_keys *keys)
{
	u32 words[16];
	u32 n = 0;
	u32 hash;

	flow_hash_consistentify(keys);

	words[n++] = ((u32)keys->basic.n_proto << 16) | keys->basic.ip_proto;
	words[n++] = keys->tags.flow_label;
	words[n++] = keys->keyid.keyid;
	words[n++] = keys->ports.ports;
	if (keys->control.addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		words[n++] = keys->addrs.v4addrs.src;
		words[n++] = keys->addrs.v4addrs.dst;
	} else if (keys->control.addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		memcpy(&words[n], &keys->addrs.v6addrs, sizeof(keys->addrs.v6addrs));
		n += sizeof(keys->addrs.v6addrs) / sizeof(u32);
	}

	hash = jhash2(words, n, kshim_cur->hashrnd);
	return hash ? hash : 1;
}

/* ---- netlink ----------------------------------------------------------------------------- */

static int nla_minlen(int type)
{
	switch (type) {
	case NLA_U8:
		return 1;
	case NLA_U16:
		return 2;
	case NLA_U32:
	case NLA_S32:
		return 4;
	case NLA_U64:
		return 8;
	default:
		return 0;
	}
}

/* lib/nlattr.c nla_parse_nested_deprecated(): walk the attributes inside `nla`, check each
 * against the policy's minimum length and store the first of every known type in tb[]. */
int nla_parse_nested_deprecated(struct nlattr *tb[], int maxtype, const struct nlattr *nla,
				const struct nla_policy *policy, struct netlink_ext_ack *extack)
{
	const struct nlattr *pos = (const struct nlattr *)nla_data(nla);
	int rem = nla_len(nla);

	(void)extack;
	memset(tb, 0, sizeof(struct nlattr *) * (size_t)(maxtype + 1));

	while (rem >= NLA_HDRLEN && pos->nla_len >= NLA_HDRLEN && pos->nla_len <= rem) {
		int type = pos->nla_type & NLA_TYPE_MASK;
		int attrlen = nla_len(pos);

		if (type > 0 && type <= maxtype) {
			if (policy && attrlen < nla_minlen(policy[type].type))
				return -ERANGE;
			if (!tb[type])
				tb[type] = (struct nlattr *)pos;
		}
		rem -= (int)NLA_ALIGN(pos->nla_len);
		pos = (const struct nlattr *)((const char *)pos + NLA_ALIGN(pos->nla_len));
	}
	return 0;
}

/* The dump buffer is skb->data, nl_cap bytes, with skb->len bytes used. */
int nla_put(struct sk_buff *skb, int attrtype, int attrlen, const void *data)
{
	u32 total = (u32)NLA_ALIGN(NLA_HDRLEN + attrlen);
	struct nlattr *nla;

	if (skb->len + total > skb->nl_cap)
		return -EMSGSIZE;
	nla = (struct nlattr *)(skb->data + skb->len);
	nla->nla_type = (u16)attrtype;
	nla->nla_len = (u16)(NLA_HDRLEN + attrlen);
	memset((u8 *)nla + NLA_HDRLEN, 0, total - NLA_HDRLEN);
	memcpy((u8 *)nla + NLA_HDRLEN, data, (size_t)attrlen);
	skb->len += total;
	return 0;
}

struct nlattr *nla_nest_start_noflag(struct sk_buff *skb, int attrtype)
{
	struct nlattr *start = (struct nlattr *)(skb->data + skb->len);

	if (nla_put(skb, attrtype, 0, NULL) < 0)
		return NULL;
	return start;
}

int nla_nest_end(struct sk_buff *skb, struct nlattr *start)
{
	start->nla_len = (u16)((skb->data + skb->len) - (u8 *)start);
	return (int)skb->len;
}

void nla_nest_cancel(struct sk_buff *skb, struct nlattr *start)
{
	skb->len = (u32)((u8 *)start - skb->data);
}

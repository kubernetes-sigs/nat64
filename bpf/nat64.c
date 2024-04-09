
/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "headers/vmlinux.h"
#include "headers/bpf_endian.h"
#include "headers/bpf_helpers.h"
#include "headers/bpf_tracing.h"

#define TC_ACT_OK  0
#define TC_ACT_SHOT		2

#define PACKET_HOST		0		/* To us		*/

#define ETH_P_IP   0x0800 /* Internet Protocol packet	*/
#define ETH_P_IPV6 0x86DD
#define ETH_HLEN	14		/* Total octets in header.	 */

// From kernel:include/net/ip.h
#define IP_DF 0x4000  // Flag: "Don't Fragment"

#define TCP4_CSUM_OFF  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define UDP4_CSUM_OFF  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))
#define ICMP4_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define TCP6_CSUM_OFF  (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check))
#define UDP6_CSUM_OFF  (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct udphdr, check))
#define ICMP6_CSUM_OFF (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct icmp6hdr, icmp6_cksum))

// rfc6052
# define NAT64_PREFIX_0 0x64
# define NAT64_PREFIX_1 0xff
# define NAT64_PREFIX_2 0x9b
# define NAT64_PREFIX_3 0

// From kernel:include/uapi/asm/errno.h
#define ENOTSUP		252	/* Function not implemented (POSIX.4 / HPUX) */

// From kernel:include/uapi/linux/icmpv6.h
#define icmp6_identifier	icmp6_dataun.u_echo.identifier
#define icmp6_sequence		icmp6_dataun.u_echo.sequence
#define icmp6_pointer		icmp6_dataun.un_data32[0]
#define icmp6_mtu		icmp6_dataun.un_data32[0]
#define icmp6_unused		icmp6_dataun.un_data32[0]
#define icmp6_maxdelay		icmp6_dataun.un_data16[0]
#define icmp6_router		icmp6_dataun.u_nd_advt.router
#define icmp6_solicited		icmp6_dataun.u_nd_advt.solicited
#define icmp6_override		icmp6_dataun.u_nd_advt.override
#define icmp6_ndiscreserved	icmp6_dataun.u_nd_advt.reserved
#define icmp6_hop_limit		icmp6_dataun.u_nd_ra.hop_limit
#define icmp6_addrconf_managed	icmp6_dataun.u_nd_ra.managed
#define icmp6_addrconf_other	icmp6_dataun.u_nd_ra.other
#define icmp6_rt_lifetime	icmp6_dataun.u_nd_ra.rt_lifetime
#define icmp6_router_pref	icmp6_dataun.u_nd_ra.router_pref

#define ICMPV6_ROUTER_PREF_LOW		0x3
#define ICMPV6_ROUTER_PREF_MEDIUM	0x0
#define ICMPV6_ROUTER_PREF_HIGH		0x1
#define ICMPV6_ROUTER_PREF_INVALID	0x2

#define ICMPV6_DEST_UNREACH		1
#define ICMPV6_PKT_TOOBIG		2
#define ICMPV6_TIME_EXCEED		3
#define ICMPV6_PARAMPROB		4

#define ICMPV6_INFOMSG_MASK		0x80

#define ICMPV6_ECHO_REQUEST		128
#define ICMPV6_ECHO_REPLY		129
#define ICMPV6_MGM_QUERY		130
#define ICMPV6_MGM_REPORT       	131
#define ICMPV6_MGM_REDUCTION    	132

#define ICMPV6_NI_QUERY			139
#define ICMPV6_NI_REPLY			140

#define ICMPV6_MLD2_REPORT		143

#define ICMPV6_DHAAD_REQUEST		144
#define ICMPV6_DHAAD_REPLY		145
#define ICMPV6_MOBILE_PREFIX_SOL	146
#define ICMPV6_MOBILE_PREFIX_ADV	147

/*
 *	Codes for Destination Unreachable
 */
#define ICMPV6_NOROUTE			0
#define ICMPV6_ADM_PROHIBITED		1
#define ICMPV6_NOT_NEIGHBOUR		2
#define ICMPV6_ADDR_UNREACH		3
#define ICMPV6_PORT_UNREACH		4
#define ICMPV6_POLICY_FAIL		5
#define ICMPV6_REJECT_ROUTE		6

/*
 *	Codes for Time Exceeded
 */
#define ICMPV6_EXC_HOPLIMIT		0
#define ICMPV6_EXC_FRAGTIME		1

/*
 *	Codes for Parameter Problem
 */
#define ICMPV6_HDR_FIELD		0
#define ICMPV6_UNK_NEXTHDR		1
#define ICMPV6_UNK_OPTION		2

// From kernel:include/uapi/linux/icmp.h
#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench		*/
#define ICMP_REDIRECT		5	/* Redirect (change route)	*/
#define ICMP_ECHO		8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		*/
#define ICMP_INFO_REQUEST	15	/* Information Request		*/
#define ICMP_INFO_REPLY		16	/* Information Reply		*/
#define ICMP_ADDRESS		17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/
#define NR_ICMP_TYPES		18


/* Codes for UNREACH. */
#define ICMP_NET_UNREACH	0	/* Network Unreachable		*/
#define ICMP_HOST_UNREACH	1	/* Host Unreachable		*/
#define ICMP_PROT_UNREACH	2	/* Protocol Unreachable		*/
#define ICMP_PORT_UNREACH	3	/* Port Unreachable		*/
#define ICMP_FRAG_NEEDED	4	/* Fragmentation Needed/DF set	*/
#define ICMP_SR_FAILED		5	/* Source Route failed		*/
#define ICMP_NET_UNKNOWN	6
#define ICMP_HOST_UNKNOWN	7
#define ICMP_HOST_ISOLATED	8
#define ICMP_NET_ANO		9
#define ICMP_HOST_ANO		10
#define ICMP_NET_UNR_TOS	11
#define ICMP_HOST_UNR_TOS	12
#define ICMP_PKT_FILTERED	13	/* Packet filtered */
#define ICMP_PREC_VIOLATION	14	/* Precedence violation */
#define ICMP_PREC_CUTOFF	15	/* Precedence cut off */
#define NR_ICMP_UNREACH		15	/* instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET		0	/* Redirect Net			*/
#define ICMP_REDIR_HOST		1	/* Redirect Host		*/
#define ICMP_REDIR_NETTOS	2	/* Redirect Net for TOS		*/
#define ICMP_REDIR_HOSTTOS	3	/* Redirect Host for TOS	*/

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL		0	/* TTL count exceeded		*/
#define ICMP_EXC_FRAGTIME	1	/* Fragment Reass time exceeded	*/

/* Declare BPF maps */

// Helper forward declarations, so that we can have the most
// important functions code first
static __always_inline bool nat46_valid(const struct __sk_buff *skb);
static __always_inline bool nat64_valid(const struct __sk_buff *skb);
static __always_inline __wsum csum_add(__wsum csum, __wsum addend);
static __always_inline __wsum csum_sub(__wsum csum, __wsum addend);

// Create an IPv4 packets using as destination address the last 4 bytes the
// dst IPv6 address with the NAT64 prefix.
// Use as source address the last digit of the soucre address with the 169.254.64.x prefix
// Assume there are less than 254 pods always in the node and that range is empty
SEC("tc/nat64")
int nat64(struct __sk_buff* skb)
{
	void *data = (void *)(long)skb->data;
	const void *data_end = (void *)(long)skb->data_end;
	const struct ethhdr *const eth = data;
	const struct ipv6hdr *const ip6 = (void *)(eth + 1);

	bpf_printk("NAT64: starting");

	// Forward packet if we can't handle it.
	if (!nat64_valid(skb)) {
		bpf_printk("NAT64 packet forwarded: not valid for nat64");
		return TC_ACT_OK;
	}

	bpf_printk("NAT64 IPv6 packet: saddr: %pI6, daddr: %pI6", &ip6->saddr, &ip6->daddr);

	// Build source ip, last byte of the ipv6 address plus the prefix.
	// 169.254.64.xxx
	__u32 new_src = bpf_htonl(0xA9FE4000 + (bpf_ntohl(ip6->saddr.in6_u.u6_addr32[3]) & 0x000000FF));

	// Extract IPv4 address from the last 4 bytes of IPv6 address.
	__u32 new_dst = ip6->daddr.in6_u.u6_addr32[3];

	// Crafting IPv4 packet out of IPv6 start here. Most of it can be
	// derived from IPv6 packet rather easily. Replacing addresses
	// is the least trivial part.
	__be16 tot_len = bpf_htons(bpf_ntohs(ip6->payload_len) + sizeof(struct iphdr));
	struct iphdr ip4 = {
		.version = 4,                                           // u4
		.ihl = sizeof(struct iphdr) / sizeof(__u32),            // u4
		.tos = (ip6->priority << 4) + (ip6->flow_lbl[0] >> 4),  // u8
		.tot_len = tot_len,                                     // u16
		.id = 0,                                                // u16
		.check = 0,                                             // u16
		.frag_off = 0,                                          // u16
	};

	// For whatever cursed reason, verifier is unhappy if these are part
	// of initializer list above, so I guess we need to set values
	// separately.
	ip4.ttl = ip6->hop_limit;
	ip4.protocol = (ip6->nexthdr == IPPROTO_ICMPV6) ? IPPROTO_ICMP : ip6->nexthdr;
	ip4.saddr = new_src;
	ip4.daddr = new_dst;

	// https://mailarchive.ietf.org/arch/msg/behave/JfxCt1fGT66pEtfXKuEDJ8rdd7w/
	if (bpf_ntohs(ip4.tot_len) > 1280)
		ip4.frag_off = bpf_htons(IP_DF);

	// Calculate the IPv4 one's complement checksum of the IPv4 header.
	__wsum sum4 = 0;
	for (int i = 0; i < sizeof(struct iphdr) / sizeof(__u16); ++i) {
		sum4 += ((__u16*)&ip4)[i];
	}
	// Note that sum4 is guaranteed to be non-zero by virtue of ip.version == 4
	sum4 = (sum4 & 0xFFFF) + (sum4 >> 16);  // collapse u32 into range 1 .. 0x1FFFE
	sum4 = (sum4 & 0xFFFF) + (sum4 >> 16);  // collapse any potential carry into u16
	ip4.check = (__u16)~sum4;               // sum4 cannot be zero, so this is never 0xFFFF

	struct icmphdr icmp4;
	__wsum icmp_csum_diff = 0;
	// Initialize header to all zeroes.
	__u16 *p = (void *)&icmp4;
	for (int i = 0; i < sizeof(struct icmphdr) / sizeof(__u16); ++i) {
		p[i] = 0;
	}
	if (ip4.protocol == IPPROTO_ICMP) {
		struct icmp6hdr *icmp6 = (void *)(ip6 + 1);
		__u32 mtu;

		switch (icmp6->icmp6_type) {
		case ICMPV6_ECHO_REQUEST:
			icmp4.type = ICMP_ECHO;
			icmp4.un.echo.id = icmp6->icmp6_identifier;
			icmp4.un.echo.sequence = icmp6->icmp6_sequence;
			break;
		case ICMPV6_ECHO_REPLY:
			icmp4.type = ICMP_ECHOREPLY;
			icmp4.un.echo.id = icmp6->icmp6_identifier;
			icmp4.un.echo.sequence = icmp6->icmp6_sequence;
			break;
		case ICMPV6_DEST_UNREACH:
			icmp4.type = ICMP_DEST_UNREACH;
			switch (icmp6->icmp6_code) {
			case ICMPV6_NOROUTE:
			case ICMPV6_NOT_NEIGHBOUR:
			case ICMPV6_ADDR_UNREACH:
				icmp4.code = ICMP_HOST_UNREACH;
				break;
			case ICMPV6_ADM_PROHIBITED:
				icmp4.code = ICMP_HOST_ANO;
				break;
			case ICMPV6_PORT_UNREACH:
				icmp4.code = ICMP_PORT_UNREACH;
				break;
			default:
				// We don't recognize this ICMPv6 code, forward packet.
				return TC_ACT_OK;
			}
			break;
		case ICMPV6_PKT_TOOBIG:
			icmp4.type = ICMP_DEST_UNREACH;
			icmp4.code = ICMP_FRAG_NEEDED;
			/* FIXME */
			if (icmp6->icmp6_mtu) {
				mtu = bpf_ntohl(icmp6->icmp6_mtu);
				icmp4.un.frag.mtu = bpf_htons((__u16)mtu);
			} else {
				icmp4.un.frag.mtu = bpf_htons(1500);
			}
			break;
		case ICMPV6_TIME_EXCEED:
			icmp4.type = ICMP_TIME_EXCEEDED;
			icmp4.code = icmp6->icmp6_code;
			break;
		case ICMPV6_PARAMPROB:
			switch (icmp6->icmp6_code) {
			case ICMPV6_HDR_FIELD:
				icmp4.type = ICMP_PARAMETERPROB;
				icmp4.code = 0;
				break;
			case ICMPV6_UNK_NEXTHDR:
				icmp4.type = ICMP_DEST_UNREACH;
				icmp4.code = ICMP_PROT_UNREACH;
				break;
			default:
				// We don't recognize this ICMPv6 code, forward packet.
				return TC_ACT_OK;
			}
			break;
		default:
			// We don't recognize this ICMPv6 type, forward packet
			return TC_ACT_OK;
		}

		// Checksum calculations for ICMP start here. ICMP calculates checksum
		// over its header and payload. Convincing BPF verifier to access
		// packet payload is tricky, so it might prove hard to recalculate
		// checksum directly, hence we use the previous checksum for calculations
		// and apply a bunch of bpf_csum_diff to calculate checksum difference.
		// Besides, this is probably quicker than direct calculation.
		// But oh boi, is it way harder to understand.
		//
		// ICMPv6 calculates checksum over pseudo-header as well,
		// whereas ICMPv4 does not. When calculated this difference,
		// we need to subtract diff that comes from pseudo-header.

		// Internet checksum calculations assume that checksum field in
		// header is 0. Save the old checksum value and set checksum to 0.
		__sum16 old_csum = icmp6->icmp6_cksum;
		icmp6->icmp6_cksum = 0;

		// Calculate checksum difference between headers.
		icmp_csum_diff = bpf_csum_diff((void *)icmp6, sizeof(struct icmp6hdr), (void *)&icmp4, sizeof(struct icmphdr), 0);

		// bpf_csum_diff expects that sizes are multiples of 4,
		// use variables of size >= 4, and also change endianness.
		__be32 payload_len = bpf_htonl((__u32)bpf_ntohs(ip6->payload_len));
		__be32 nexthdr = bpf_htonl((__u32)ip6->nexthdr);

		// Calculate checksum difference from pseudo-header.
		__wsum pseudohdr_csum = bpf_csum_diff(NULL, 0, (void *)&(ip6->saddr), sizeof(struct in6_addr), 0);
		pseudohdr_csum = bpf_csum_diff(NULL, 0, (void *)&(ip6->daddr), sizeof(struct in6_addr), pseudohdr_csum);
		pseudohdr_csum = bpf_csum_diff(NULL, 0, (void *)&nexthdr, sizeof(__be32), pseudohdr_csum);
		pseudohdr_csum = bpf_csum_diff(NULL, 0, (void *)&payload_len, sizeof(__be32), pseudohdr_csum);

		icmp_csum_diff = csum_sub(icmp_csum_diff, pseudohdr_csum);

		// For now, populate new packet with the old checksum. It's needed
		// for later for bpf_l4_csum_replace to correctly apply diffs
		// calculated above.
		icmp4.checksum = old_csum;
	}

	// Calculate checksum difference for L4 packet inside IP packet before any helpers
	// that modify packet's data are called, because verifier will invalidate all packet pointers.
	__u64 l4_csum_diff = 0;
	switch (ip4.protocol) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		// Both UDP and TCP use pseudo header for checksum
		// calculation, see https://www.rfc-editor.org/rfc/rfc2460.html#section-8.1.

		// This is non-trivial, so some background on TCP/UDP
		// checksum calculation. Checksum is calculated over
		// pseudo-header, which contains some bits from L3
		// header, and L4 payload. L4 payload does not change
		// between input IPv6 packet and output IPv4 packet, but
		// pseudo-header does indeed change. We could feed
		// bpf_csum_diff with the entire pseudo-headers both from
		// input and output packets and calculate checksum
		// difference this way, but we can afford to be a
		// bit smarter here.
		//
		// TCP / UDP pseudo-header for IPv4
		// (see https://www.rfc-editor.org/rfc/rfc793.html#section-3.1)
		// and for IPv6
		// (see https://www.rfc-editor.org/rfc/rfc2460.html#section-8.1)
		// contain the same information for TCP / UDP (protocol
		// is 6 for TCP, 17 for UDP for both IPv4 and IPv6), but
		// structure of pseudo-header differs - fields are
		// ordered differently and have different sizes. For checksum
		// calculation, this does not matter - all bytes of
		// pseudo-header apart from IP addresses contribute the
		// same value to checksum (first step of calculation is
		// summing all bytes, zeroes does not matter),
		// meaning we only need to run bpf_csum_diff over IP
		// addresses instead of the entire pseudo-header.
		//
		// Last neat piece of info that makes it a one-liner is that both
		// ipv6hdr and iphdr structs have src and dst addresses
		// next to each other in memory. That means we can
		// calculate checksum difference with one bpf_csum_diff
		// call using 2 * size of IP address.
		l4_csum_diff = bpf_csum_diff((void *)&(ip6->saddr), 2*sizeof(struct in6_addr), (void *)&(ip4.saddr), 2*sizeof(__u32), 0);
		break;
	}

	// Save L2 header we got from the input packet before any packet
	// modifications. We will copy it later to the output packet.
	struct ethhdr old_eth;
	old_eth = *eth;
	// Replace the ethertype for a correct one for IPv4 packet.
	old_eth.h_proto = bpf_htons(ETH_P_IP);

	// Packet mutations begin - point of no return, but if this first modification fails
	// the packet is probably still pristine, so let clatd handle it.
	// This also takes care of resizing socket buffer to handle different IP
	// header size.
	if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IP), 0)) {
		bpf_printk("NAT64 packet forwarded: bpf_skb_change_proto failed");
		return TC_ACT_OK;
	}

	// Update checksum of the packet inside IP packet.
	int ret = 0;
	switch (ip4.protocol) {
	case IPPROTO_UDP:
		ret = bpf_l4_csum_replace(skb, UDP4_CSUM_OFF, 0, l4_csum_diff, BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0);
		break;
	case IPPROTO_TCP:
		ret = bpf_l4_csum_replace(skb, TCP4_CSUM_OFF, 0, l4_csum_diff, BPF_F_PSEUDO_HDR);
		break;
	}

	// If true, updating packet's UDP / TCP checksum failed.
	if (ret < 0) {
		bpf_printk("NAT64 packet dropped: L4 checksum update failed");
		return TC_ACT_SHOT;
	}

	// bpf_skb_change_proto() invalidates all pointers - reload them.
	data = (void*)(long)skb->data;
	data_end = (void*)(long)skb->data_end;
	// I cannot think of any valid way for this error condition to trigger, however I do
	// believe the explicit check is required to keep the in kernel ebpf verifier happy.
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
		return TC_ACT_SHOT;

	// Copy over the old ethernet header with updated ethertype.
	ret = bpf_skb_store_bytes(skb, 0, &old_eth, sizeof(struct ethhdr), 0);
	if (ret < 0) {
		bpf_printk("NAT64 packet dropped: copy eth header");
		return TC_ACT_SHOT;
	}
	// Copy over the new ipv4 header.
	ret = bpf_skb_store_bytes(skb, sizeof(struct ethhdr), &ip4, sizeof(struct iphdr), 0);
	if (ret < 0) {
		bpf_printk("NAT64 packet dropped: copy ipv4 header");
		return TC_ACT_SHOT;
	}

	if (ip4.protocol == IPPROTO_ICMP) {
		// Copy over the new icmp header
		ret = bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr),
                                          &icmp4, sizeof(struct icmphdr), 0);
		if (ret < 0) {
			bpf_printk("NAT64 packet dropped: copy icmp header");
			return TC_ACT_SHOT;
		}

		ret = bpf_l4_csum_replace(skb, ICMP4_CSUM_OFF, 0, icmp_csum_diff, BPF_F_PSEUDO_HDR);
		if (ret < 0) {
			bpf_printk("NAT64 packet dropped: replace icmp checksum");
			return TC_ACT_SHOT;
		}
	}

	bpf_printk("NAT64 IPv4 packet: saddr: %pI4, daddr: %pI4", &ip4.saddr, &ip4.daddr);
	return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}

// Build an IPv6 packet from an IPv4 packet
// destination address is pod prefix plus last digit from 169.254.64.x
// source address is the IPv4 src address embedded on the well known NAT64 prefix
SEC("tc/nat46")
static __always_inline int nat46(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	const void *data_end = (void *)(long)skb->data_end;
	const struct ethhdr *const eth = data;
	const struct iphdr *const ip4 = (void *)(eth + 1);

	bpf_printk("NAT46 IPv4 packet: saddr: %pI4, daddr: %pI4", &ip4->saddr, &ip4->daddr);

	// Forward packet if we can't handle it.
	if (!nat46_valid(skb)) {
		bpf_printk("NAT46 packet forwarded: not valid for nat46");
		return TC_ACT_OK;
	}

	// Build dest ip, last byte of the ipv6 address plus the pod prefix
	// pod_prefix::xxx.
	 __u32 dst_addr = bpf_ntohl(ip4->daddr) & 0x000000FF;

	struct ipv6hdr ip6 = {
		.version = 6,                                            // __u8:4
		.priority = ip4->tos >> 4,                               // __u8:4
		.flow_lbl = {(ip4->tos & 0xF) << 4, 0, 0},               // __u8[3]
		.payload_len = bpf_htons(bpf_ntohs(ip4->tot_len) - 20),  // __be16
		.hop_limit = ip4->ttl,                                   // __u8
	};

	ip6.nexthdr = (ip4->protocol == IPPROTO_ICMP) ? IPPROTO_ICMPV6 : ip4->protocol;
	ip6.saddr.in6_u.u6_addr32[0] = bpf_htonl(0x0064ff9b);
	ip6.saddr.in6_u.u6_addr32[1] = 0;
	ip6.saddr.in6_u.u6_addr32[2] = 0;
	ip6.saddr.in6_u.u6_addr32[3] = ip4->saddr;
	ip6.daddr.in6_u.u6_addr32[0] = bpf_htonl(0xfd000010);  // containers subnet
	ip6.daddr.in6_u.u6_addr32[1] = bpf_htonl(0x02440001);  // containers subnet
	ip6.daddr.in6_u.u6_addr32[2] = 0;
	ip6.daddr.in6_u.u6_addr32[3] = bpf_htonl(dst_addr);

	struct icmp6hdr icmp6;
	__wsum icmp6_csum_diff = 0;
	// Initialize header to all zeroes.
	__u16 *p = (void *)&icmp6;
	for (int i = 0; i < sizeof(struct icmp6hdr) / sizeof(__u16); ++i) {
		p[i] = 0;
	}
	if (ip6.nexthdr == IPPROTO_ICMPV6) {
		struct icmphdr *icmp4 = (void *)(ip4 + 1);

		switch (icmp4->type) {
		case ICMP_ECHO:
			icmp6.icmp6_type = ICMPV6_ECHO_REQUEST;
			icmp6.icmp6_identifier = icmp4->un.echo.id;
			icmp6.icmp6_sequence = icmp4->un.echo.sequence;
		break;
		case ICMP_ECHOREPLY:
			icmp6.icmp6_type = ICMPV6_ECHO_REPLY;
			icmp6.icmp6_identifier = icmp4->un.echo.id;
			icmp6.icmp6_sequence = icmp4->un.echo.sequence;
			break;
		case ICMP_DEST_UNREACH:
			icmp6.icmp6_type = ICMPV6_DEST_UNREACH;
			switch (icmp4->code) {
			case ICMP_NET_UNREACH:
			case ICMP_HOST_UNREACH:
				icmp6.icmp6_code = ICMPV6_NOROUTE;
				break;
			case ICMP_PROT_UNREACH:
				icmp6.icmp6_type = ICMPV6_PARAMPROB;
				icmp6.icmp6_code = ICMPV6_UNK_NEXTHDR;
				icmp6.icmp6_pointer = 6;
				break;
			case ICMP_PORT_UNREACH:
				icmp6.icmp6_code = ICMPV6_PORT_UNREACH;
				break;
			case ICMP_FRAG_NEEDED:
				icmp6.icmp6_type = ICMPV6_PKT_TOOBIG;
				icmp6.icmp6_code = 0;
				/* FIXME */
				if (icmp4->un.frag.mtu)
					icmp6.icmp6_mtu = bpf_htonl(bpf_ntohs(icmp4->un.frag.mtu));
				else
					icmp6.icmp6_mtu = bpf_htonl(1500);
				break;
			case ICMP_SR_FAILED:
				icmp6.icmp6_code = ICMPV6_NOROUTE;
				break;
			case ICMP_NET_UNKNOWN:
			case ICMP_HOST_UNKNOWN:
			case ICMP_HOST_ISOLATED:
			case ICMP_NET_UNR_TOS:
			case ICMP_HOST_UNR_TOS:
				icmp6.icmp6_code = 0;
				break;
			case ICMP_NET_ANO:
			case ICMP_HOST_ANO:
			case ICMP_PKT_FILTERED:
				icmp6.icmp6_code = ICMPV6_ADM_PROHIBITED;
				break;
			default:
				// We don't recognize this ICMP code, forward packet.
				return TC_ACT_OK;
			}
			break;
		case ICMP_TIME_EXCEEDED:
			icmp6.icmp6_type = ICMPV6_TIME_EXCEED;
			break;
		case ICMP_PARAMETERPROB:
			icmp6.icmp6_type = ICMPV6_PARAMPROB;
			/* FIXME */
			icmp6.icmp6_pointer = 6;
			break;
		default:
			// We don't recognize this ICMP type, forward packet.
			return TC_ACT_OK;
		}

		// Checksum calculations for ICMP start here. ICMP calculates checksum
		// over its header and payload. Convincing BPF verifier to access
		// packet payload is tricky, so it might prove hard to recalculate
		// checksum directly, hence we use the previous checksum for calculations
		// and apply a bunch of bpf_csum_diff to calculate checksum difference.
		// Besides, this is probably quicker than direct calculation.
		// But oh boi, is it way harder to understand.
		//
		// ICMPv6 calculates checksum over pseudo-header as well,
		// whereas ICMPv4 does not. When calculated this difference,
		// we need to subtract diff that comes from pseudo-header.

		// Internet checksum calculations assume that checksum field in
		// header is 0. Save the old checksum value and set checksum to 0.
		__sum16 old_csum = icmp4->checksum;
		icmp4->checksum = 0;

		// Calculate checksum difference between headers.
		icmp6_csum_diff = bpf_csum_diff((void *)icmp4, sizeof(struct icmphdr), (void *)&icmp6, sizeof(struct icmp6hdr), 0);

		// bpf_csum_diff expects that sizes are multiples of 4,
		// use variables of size >= 4, and also change endianness.
		__be32 payload_len = bpf_htonl((__u32)bpf_ntohs(ip6.payload_len));
		__be32 nexthdr = bpf_htonl((__u32)ip6.nexthdr);

		// Calculate checksum difference from pseudo-header.
		__wsum pseudohdr_csum = bpf_csum_diff(NULL, 0, (void *)&(ip6.saddr), sizeof(struct in6_addr), 0);
		pseudohdr_csum = bpf_csum_diff(NULL, 0, (void *)&(ip6.daddr), sizeof(struct in6_addr), pseudohdr_csum);
		pseudohdr_csum = bpf_csum_diff(NULL, 0, (void *)&nexthdr, sizeof(__be32), pseudohdr_csum);
		pseudohdr_csum = bpf_csum_diff(NULL, 0, (void *)&payload_len, sizeof(__be32), pseudohdr_csum);

		icmp6_csum_diff = csum_add(icmp6_csum_diff, pseudohdr_csum);

		// For now, populate new packet with the old checksum. It's needed
		// for later for bpf_l4_csum_replace to correctly apply diffs
		// calculated above.
		icmp6.icmp6_cksum = old_csum;
	}

	// Calculate checksum difference for L4 packet inside IP packet before any helpers
	// that modify packet's data are called, because verifier will invalidate all packet pointers.
	__u64 l4_csum_diff = 0;
	switch (ip6.nexthdr) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		// See comment for nat64 direction to see reasoning behind this.
		l4_csum_diff = bpf_csum_diff((void *)&(ip4->saddr), 2*sizeof(__u32), (void *)&(ip6.saddr), 2*sizeof(struct in6_addr), 0);
		break;
	}

	// Save L2 header we got from the input packet before any packet
	// modifications. We will copy it later to the output packet.
	struct ethhdr old_eth;
	old_eth = *eth;
	// Replace the ethertype for a correct one for IPv6 packet.
	old_eth.h_proto = bpf_htons(ETH_P_IPV6);

	// Packet mutations begin - point of no return, but if this first modification fails
	// the packet is probably still pristine, so let clatd handle it.
	// This also takes care of resizing socket buffer to handle different IP
	// header size.
	if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IPV6), 0)) {
		bpf_printk("NAT46 packet forwarded: bpf_skb_change_proto failed");
		return TC_ACT_OK;
	}

	// Update L4 checksum using the checksum difference we calculated before.
	int ret = 0;
	switch (ip6.nexthdr) {
	case IPPROTO_UDP:
		ret = bpf_l4_csum_replace(skb, UDP6_CSUM_OFF, 0, l4_csum_diff, BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0);
		break;
	case IPPROTO_TCP:
		ret = bpf_l4_csum_replace(skb, TCP6_CSUM_OFF, 0, l4_csum_diff, BPF_F_PSEUDO_HDR);
		break;
	}

	// If true, updating packet's UDP / TCP checksum failed.
	if (ret < 0) {
		bpf_printk("NAT46 packet dropped: L4 checksum update failed");
		return TC_ACT_SHOT;
	}

	// bpf_skb_change_proto() invalidates all pointers - reload them.
	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;

	// I cannot think of any valid way for this error condition to trigger, however I do
	// believe the explicit check is required to keep the in kernel ebpf verifier happy.
	if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end)
		return TC_ACT_SHOT;

	// Copy over the old ethernet header with updated ethertype.
	ret = bpf_skb_store_bytes(skb, 0, &old_eth, sizeof(struct ethhdr), 0);
	if (ret < 0) {
		bpf_printk("NAT46 packet dropped: copy eth header");
		return TC_ACT_SHOT;
	}
	// Copy over the new ipv6 header.
	// This takes care of updating the skb->csum field for a CHECKSUM_COMPLETE packet.
	ret = bpf_skb_store_bytes(skb, sizeof(struct ethhdr), &ip6, sizeof(struct ipv6hdr), BPF_F_RECOMPUTE_CSUM);
	if (ret < 0) {
		bpf_printk("NAT46 packet dropped: copy ipv6 header + csum recompute");
		return TC_ACT_SHOT;
	}

	if (ip6.nexthdr == IPPROTO_ICMPV6) {
		// Copy over the new icmpv6 header
		ret = bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr),
                                          &icmp6, sizeof(struct icmp6hdr), 0);
		if (ret < 0) {
			bpf_printk("NAT46 packet dropped: copy icmpv6 header");
			return TC_ACT_SHOT;
		}

		ret = bpf_l4_csum_replace(skb, ICMP6_CSUM_OFF, 0, icmp6_csum_diff, BPF_F_PSEUDO_HDR);
		if (ret < 0) {
			bpf_printk("NAT46 packet dropped: replace icmpv6 checksum");
			return TC_ACT_SHOT;
		}
	}

	bpf_printk("NAT46 IPv6 packet: saddr: %pI6, daddr: %pI6", &ip6.saddr, &ip6.daddr);
	return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}

static __always_inline bool
nat64_valid(const struct __sk_buff *skb) {
	const void *data = (void *)(long)skb->data;
	const void *data_end = (void *)(long)skb->data_end;

	// Require ethernet dst mac address to be our unicast address.
	if (skb->pkt_type != PACKET_HOST)
		return false;

	// Must be meta-ethernet IPv6 frame.
	if (skb->protocol != bpf_htons(ETH_P_IPV6))
		return false;

	// Must have (ethernet and) ipv6 header.
	if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end)
		return false;

	const struct ethhdr *eth = data;

	// Ethertype - if present - must be IPv6.
	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return false;

	const struct ipv6hdr *ip6 = (void *)(eth + 1);

	// IP version must be 6.
	if (ip6->version != 6)
		return false;

	// Maximum IPv6 payload length that can be translated to IPv4.
	if (bpf_ntohs(ip6->payload_len) > 0xFFFF - sizeof(struct iphdr))
		return false;

	// Must be inner protocol we can support.
	// TODO: Check what's with IPPROTO_GRE, IPPROTO_ESP, I'm not even sure
	//       what those are.
	switch (ip6->nexthdr) {
	case IPPROTO_TCP:
		// Must have TCP header.
		if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct tcphdr) > data_end)
			return false;
		break;
	case IPPROTO_UDP:
		// Must have UDP header.
		if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr) > data_end)
			return false;
		break;
	case IPPROTO_ICMPV6:
		// Must have ICMPv6 header.
		if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr) > data_end)
			return false;
		break;
	default:  // Do not know how to handle anything else.
		return false;
	}

	return true;
}

static __always_inline bool
nat46_valid(const struct __sk_buff *skb) {
	const void *data = (void *)(long)skb->data;
	const void *data_end = (void *)(long)skb->data_end;

	// Must be meta-ethernet IPv4 frame.
	if (skb->protocol != bpf_htons(ETH_P_IP))
		return false;

	// Must have IPv4 header.
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
		return false;

	const struct ethhdr *eth = data;

	// Ethertype - if present - must be IPv4.
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return false;

	const struct iphdr *ip4 = (void *)(eth + 1);

	// IP version must be 4.
	if (ip4->version != 4)
		return false;

	// We cannot handle IP options, just standard 20 byte == 5 dword minimal IPv4 header.
	if (ip4->ihl != 5)
		return false;

	// Maximum IPv4 payload length that can be translated to IPv6.
	if (bpf_htons(ip4->tot_len) > 0xFFFF - sizeof(struct ipv6hdr))
		return false;

	// Calculate the IPv4 one's complement checksum of the IPv4 header.
	__wsum sum4 = 0;
	for (uint i = 0; i < sizeof(*ip4) / sizeof(__u16); ++i)
		sum4 += ((__u16 *)ip4)[i];

	// Note that sum4 is guaranteed to be non-zero by virtue of ip4->version == 4
	sum4 = (sum4 & 0xFFFF) + (sum4 >> 16);  // collapse u32 into range 1 .. 0x1FFFE
	sum4 = (sum4 & 0xFFFF) + (sum4 >> 16);  // collapse any potential carry into u16

	// For a correct checksum we should get *a* zero, but sum4 must be positive, ie 0xFFFF
	if (sum4 != 0xFFFF)
		return false;

	// Minimum IPv4 total length is the size of the header
	if (bpf_ntohs(ip4->tot_len) < sizeof(*ip4))
		return false;

	// We are incapable of dealing with IPv4 fragments
	if (ip4->frag_off & ~bpf_htons(IP_DF))
		return false;

	// Must be L4 protocol we can support.
	// TODO: Check what's with IPPROTO_GRE, IPPROTO_ESP, I'm not even sure
	//       what those are.
	switch (ip4->protocol) {
	case IPPROTO_TCP:
		// Must have TCP header.
		if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
			return false;
		break;
	case IPPROTO_UDP:
		// Must have UDP header.
		if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
			return false;
		break;
	case IPPROTO_ICMP:
		// Must have ICMP header.
		if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end)
			return false;
		break;
	default:  // do not know how to handle anything else
		return false;
	}

	return true;
}

static __always_inline __wsum
csum_add(__wsum csum, __wsum addend) {
	csum += addend;
	return csum + (csum < addend);
}

static __always_inline __wsum
csum_sub(__wsum csum, __wsum addend) {
	return csum_add(csum, ~addend);
}

char __license[] SEC("license") = "GPL";

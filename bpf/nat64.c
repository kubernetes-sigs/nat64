/*
Copyright 2025 The Kubernetes Authors, The Android Open Source Project.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <linux/types.h>
#include <linux/byteorder.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ip6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


// all constants here are overriden from user-space level
volatile const uint32_t IPV4_SNAT_PREFIX;
volatile const uint32_t IPV4_SNAT_MASK;

volatile const uint32_t IPV6_NAT64_PREFIX_0;
volatile const uint32_t IPV6_NAT64_PREFIX_1;
volatile const uint32_t IPV6_NAT64_PREFIX_2;

volatile const uint32_t IPV6_NAT64_MASK_0;
volatile const uint32_t IPV6_NAT64_MASK_1;
volatile const uint32_t IPV6_NAT64_MASK_2;

volatile const uint32_t POD_PREFIX_0;
volatile const uint32_t POD_PREFIX_1;
volatile const uint32_t POD_PREFIX_2;
volatile const uint32_t POD_PREFIX_3;

volatile const uint32_t POD_MASK_0;
volatile const uint32_t POD_MASK_1;
volatile const uint32_t POD_MASK_2;
volatile const uint32_t POD_MASK_3;

// Success error codes >= 0
#define IP_NAT_OK             0
// Failure error codes < 0
#define IP_NAT_NOT_SUPPORTED  -1
// TODO: differentiate errors between drop and forward?
#define IP_NAT_ERROR          -2
#define IP_NAT_UNDEFINED      -127

// Success error codes >= 0
#define ICMP_NAT_OK		0
// Failure error codes < 0
#define ICMP_NAT_NOT_SUPPORTED  -1
// TODO: differentiate errors between drop and forward?
#define ICMP_NAT_ERROR		-2

#define TC_ACT_OK	0
#define TC_ACT_SHOT	2

#define PACKET_HOST	0
#define DEFAULT_MTU 1500

#define DEBUG 1 // Define DEBUG as 1 for debug mode, 0 for production


static __always_inline __wsum csum_add(__wsum csum, __wsum addend) {
	csum += addend;
	return csum + (csum < addend);
}

static __always_inline __wsum csum_sub(__wsum csum, __wsum addend) {
	return csum_add(csum, ~addend);
}

// TODO: this works only because of how k8s assigns IP to pods on nodes.
//       This naive approach works with max limit of 256 pods deployed
//       on the node. Future work would be to remove this limit by supporting
//       stateful src IP assignment.
static __always_inline __u32 ip4_new_saddr(struct ipv6hdr *ip6) {
	// The upper bytes of the IPv4 NATed address
	__u32 upper_addr = IPV4_SNAT_PREFIX & IPV4_SNAT_MASK;
	// The lower bytes are the remaining ones masked
	// with the original IPv6 address
	__u32 lower_addr = (~IPV4_SNAT_MASK) & ip6->saddr.in6_u.u6_addr32[3];
	__u32 new_src = bpf_htonl(upper_addr | lower_addr);

	#ifdef DEBUG
	bpf_printk("IP4 saddr: %pI4", new_src);
	#endif
	
	return new_src;
}

static __always_inline __wsum ip6_pseudohdr_csum(struct ipv6hdr *ip6) {
	__be32 payload_len = bpf_htonl((__u32)bpf_ntohs(ip6->payload_len));
	__be32 nexthdr = bpf_htonl((__u32)ip6->nexthdr);

	__wsum pseudohdr_csum = bpf_csum_diff(NULL, 0, (void *)&(ip6->saddr), sizeof(struct in6_addr), 0);
	pseudohdr_csum = bpf_csum_diff(NULL, 0, (void *)&(ip6->daddr), sizeof(struct in6_addr), pseudohdr_csum);
	pseudohdr_csum = bpf_csum_diff(NULL, 0, (void *)&nexthdr, sizeof(__be32), pseudohdr_csum);
	pseudohdr_csum = bpf_csum_diff(NULL, 0, (void *)&payload_len, sizeof(__be32), pseudohdr_csum);

	return pseudohdr_csum;
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
	#ifdef DEBUG
	bpf_printk("NAT64 packet: saddr: %pI6, daddr: %pI6", &ip6->saddr, &ip6->daddr);
	#endif

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
	// Must have IPv4 header.
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
	// Must have IPv4 header.
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
		return false;

	const struct ethhdr *eth = data;

	// Ethertype - if present - must be IPv4.
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return false;

	const struct iphdr *ip4 = (void *)(eth + 1);
	#ifdef DEBUG
	bpf_printk("NAT46 packet: saddr: %pI4, daddr: %pI4", &ip4->saddr, &ip4->daddr);
	#endif

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
	for (size_t i = 0; i < sizeof(*ip4) / sizeof(__u16); ++i)
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

static __always_inline int icmp6_to_icmp4(struct __sk_buff *skb, int icmp_offset,
	__wsum pseudohdr_csum) {
struct icmp6hdr icmp6 = {};
struct icmphdr icmp4 = {};
int ret = 0;
int icmp_csum_offset = icmp_offset + offsetof(struct icmphdr, checksum);
__u16 *p = (void *)&icmp4;
__u32 mtu = 0;
__sum16 old_csum = 0;
__wsum icmp_csum_diff = 0;

// Initialize header to all zeroes.
for (size_t i = 0; i < sizeof(struct icmphdr) / sizeof(__u16); ++i) {
p[i] = 0;
}

ret = bpf_skb_load_bytes(skb, icmp_offset, &icmp6, sizeof(struct icmp6hdr));
if (ret < 0) {
#ifdef DEBUG
bpf_printk("ICMP6->ICMP4: bpf_skb_load_bytes failed with code: %d", ret);
#endif
return ICMP_NAT_ERROR;
}

switch (icmp6.icmp6_type) {
case ICMPV6_ECHO_REQUEST:
icmp4.type = ICMP_ECHO;
icmp4.un.echo.id = icmp6.icmp6_identifier;
icmp4.un.echo.sequence = icmp6.icmp6_sequence;
break;
case ICMPV6_ECHO_REPLY:
icmp4.type = ICMP_ECHOREPLY;
icmp4.un.echo.id = icmp6.icmp6_identifier;
icmp4.un.echo.sequence = icmp6.icmp6_sequence;
break;
case ICMPV6_DEST_UNREACH:
icmp4.type = ICMP_DEST_UNREACH;
switch (icmp6.icmp6_code) {
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
return ICMP_NAT_NOT_SUPPORTED;
}
break;
case ICMPV6_PKT_TOOBIG:
icmp4.type = ICMP_DEST_UNREACH;
icmp4.code = ICMP_FRAG_NEEDED;
/* FIXME */
if (icmp6.icmp6_mtu) {
mtu = bpf_ntohl(icmp6.icmp6_mtu);
icmp4.un.frag.mtu = bpf_htons((__u16)mtu);
} else {
icmp4.un.frag.mtu = bpf_htons(DEFAULT_MTU);
}
break;
case ICMPV6_TIME_EXCEED:
icmp4.type = ICMP_TIME_EXCEEDED;
icmp4.code = icmp6.icmp6_code;
break;
case ICMPV6_PARAMPROB:
switch (icmp6.icmp6_code) {
case ICMPV6_HDR_FIELD:
icmp4.type = ICMP_PARAMETERPROB;
icmp4.code = 0;
break;
case ICMPV6_UNK_NEXTHDR:
icmp4.type = ICMP_DEST_UNREACH;
icmp4.code = ICMP_PROT_UNREACH;
break;
default:
return ICMP_NAT_NOT_SUPPORTED;
}
break;
default:
return ICMP_NAT_NOT_SUPPORTED;
}

// Internet checksum calculations assume that checksum field in
// header is 0. Save the old checksum value and set checksum to 0.
old_csum = icmp6.icmp6_cksum;
icmp6.icmp6_cksum = 0;

// Calculate checksum difference between headers.
icmp_csum_diff = bpf_csum_diff((void *)&icmp6, sizeof(struct icmp6hdr), (void *)&icmp4, sizeof(struct icmphdr), 0);
icmp_csum_diff = csum_sub(icmp_csum_diff, pseudohdr_csum);

// Populate new packet with the old checksum, so that
// bpf_l4_csum_replace to correctly apply calculated diffs.
icmp4.checksum = old_csum;

ret = bpf_skb_store_bytes(skb, icmp_offset, &icmp4, sizeof(struct icmphdr), 0);
if (ret < 0) {
#ifdef DEBUG
bpf_printk("ICMP6->ICMP4: bpf_skb_store_bytes failed with code: %d", ret);
#endif
return ICMP_NAT_ERROR;
}

ret = bpf_l4_csum_replace(skb, icmp_csum_offset, 0, icmp_csum_diff, BPF_F_PSEUDO_HDR);
if (ret < 0) {
#ifdef DEBUG
bpf_printk("ICMP6->ICMP4: bpf_l4_csum_replace failed with code: %d", ret);
#endif
return ICMP_NAT_ERROR;
}

return ICMP_NAT_OK;
}

static __always_inline int icmp4_to_icmp6(struct __sk_buff *skb, int icmp_offset,
	__wsum pseudohdr_csum) {
struct icmphdr icmp4 = {};
struct icmp6hdr icmp6 = {};
int ret = 0;
int icmp6_csum_offset = icmp_offset + offsetof(struct icmp6hdr, icmp6_cksum);
__u16 *p = (void *)&icmp6;
__sum16 old_csum = 0;
__wsum icmp6_csum_diff = 0;

// Initialize header to all zeroes.
for (size_t i = 0; i < sizeof(struct icmp6hdr) / sizeof(__u16); ++i) {
p[i] = 0;
}

ret = bpf_skb_load_bytes(skb, icmp_offset, &icmp4, sizeof(struct icmphdr));
if (ret < 0) {
#ifdef DEBUG
bpf_printk("ICMP4->ICMP6: bpf_skb_load_bytes failed with code: %d", ret);
#endif
return ICMP_NAT_ERROR;
}

switch (icmp4.type) {
case ICMP_ECHO:
icmp6.icmp6_type = ICMPV6_ECHO_REQUEST;
icmp6.icmp6_identifier = icmp4.un.echo.id;
icmp6.icmp6_sequence = icmp4.un.echo.sequence;
break;
case ICMP_ECHOREPLY:
icmp6.icmp6_type = ICMPV6_ECHO_REPLY;
icmp6.icmp6_identifier = icmp4.un.echo.id;
icmp6.icmp6_sequence = icmp4.un.echo.sequence;
break;
case ICMP_DEST_UNREACH:
icmp6.icmp6_type = ICMPV6_DEST_UNREACH;
switch (icmp4.code) {
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
if (icmp4.un.frag.mtu)
icmp6.icmp6_mtu = bpf_htonl(bpf_ntohs(icmp4.un.frag.mtu));
else
icmp6.icmp6_mtu = bpf_htonl(DEFAULT_MTU);
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
return ICMP_NAT_NOT_SUPPORTED;
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
return ICMP_NAT_NOT_SUPPORTED;
}

// Internet checksum calculations assume that checksum field in
// header is 0. Save the old checksum value and set checksum to 0.
old_csum = icmp4.checksum;
icmp4.checksum = 0;

// Calculate checksum difference between headers.
icmp6_csum_diff = bpf_csum_diff((void *)&icmp4, sizeof(struct icmphdr), (void *)&icmp6, sizeof(struct icmp6hdr), 0);
icmp6_csum_diff = csum_add(icmp6_csum_diff, pseudohdr_csum);

// Populate new packet with the old checksum, so that
// bpf_l4_csum_replace to correctly apply calculated diffs.
icmp6.icmp6_cksum = old_csum;

ret = bpf_skb_store_bytes(skb, icmp_offset, &icmp6, sizeof(struct icmp6hdr), 0);
if (ret < 0) {
#ifdef DEBUG
bpf_printk("ICMP4->ICMP6: bpf_skb_store_bytes failed with code: %d", ret);
#endif
return ICMP_NAT_ERROR;
}

ret = bpf_l4_csum_replace(skb, icmp6_csum_offset, 0, icmp6_csum_diff, BPF_F_PSEUDO_HDR);
if (ret < 0) {
#ifdef DEBUG
bpf_printk("ICMP4->ICMP6: bpf_l4_csum_replace failed with code: %d", ret);
#endif
return ICMP_NAT_ERROR;
}

return ICMP_NAT_OK;
}


static __always_inline int ip6_to_ip4(struct __sk_buff *skb, const int ip_offset) {
	struct ipv6hdr ip6 = {};
	struct iphdr ip4 = {};
	int ret = 0;
	__u16 *p = (void *)&ip4;
	__be16 tot_len = 0;
	int l4_offset = 0;
	__wsum pseudohdr_csum = 0;
	__wsum l4_csum_diff = 0;
	const __be16 ethtype = bpf_htons(ETH_P_IP);

	ret = bpf_skb_load_bytes(skb, ip_offset, &ip6, sizeof(struct ipv6hdr));
	if (ret < 0) {
		#ifdef DEBUG
		bpf_printk("IP6->IP4: bpf_skb_load_bytes failed with code: %d", ret);
		#endif
		return IP_NAT_ERROR;
	}

	tot_len = bpf_htons(bpf_ntohs(ip6.payload_len) + sizeof(struct iphdr));

	ip4.version = 4;
	ip4.ihl = sizeof(struct iphdr) / sizeof(__u32);
	ip4.tos = (__u8)((ip6.priority << 4) + (ip6.flow_lbl[0] >> 4));
	ip4.tot_len = tot_len;
	ip4.ttl = ip6.hop_limit;
	ip4.protocol = (ip6.nexthdr == IPPROTO_ICMPV6) ? IPPROTO_ICMP : ip6.nexthdr;

	ip4.saddr = ip4_new_saddr(&ip6);
	// Extract IPv4 address from the last 4 bytes of IPv6 address.
	ip4.daddr = ip6.daddr.in6_u.u6_addr32[3];

	// https://mailarchive.ietf.org/arch/msg/behave/JfxCt1fGT66pEtfXKuEDJ8rdd7w/
	if (bpf_ntohs(ip4.tot_len) > 1280)
		ip4.frag_off = bpf_htons(IP_DF);

	// TODO: see if BPF_F_RECOMPUTE_CSUM lets us skip this
	__wsum sum4 = 0;
	for (size_t i = 0; i < sizeof(struct iphdr) / sizeof(__u16); ++i) {
		sum4 += ((__u16*)&ip4)[i];
	}
	sum4 = (sum4 & 0xFFFF) + (sum4 >> 16);
	sum4 = (sum4 & 0xFFFF) + (sum4 >> 16);
	ip4.check = (__u16)~sum4;

	// This also takes care of resizing socket buffer to handle different IP
	// header size.
	ret = bpf_skb_change_proto(skb, ethtype, 0);
	if (ret < 0) {
		#ifdef DEBUG
		bpf_printk("IP6->IP4: bpf_skb_change_proto failed with code: %d", ret);
		#endif
		return IP_NAT_ERROR;
	}

	// bpf_skb_change_proto resized socket buffer to include different IP
	// header, after the change L4 offset is now based on IPv4 header size.
	l4_offset = ip_offset + sizeof(struct iphdr);

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
	l4_csum_diff = bpf_csum_diff((void *)&(ip6.saddr), 2*sizeof(struct in6_addr), (void *)&(ip4.saddr), 2*sizeof(__u32), 0);

	switch (ip4.protocol) {
	case IPPROTO_ICMP:
		pseudohdr_csum = ip6_pseudohdr_csum(&ip6);
		ret = icmp6_to_icmp4(skb, l4_offset, pseudohdr_csum);
		if (ret < 0) {
			switch (ret) {
			case ICMP_NAT_NOT_SUPPORTED:
				#ifdef DEBUG
				bpf_printk("IP6->IP4: ICMP NAT not supported");
				#endif
				return IP_NAT_NOT_SUPPORTED;
			case ICMP_NAT_ERROR:
				#ifdef DEBUG
				bpf_printk("IP6->IP4: ICMP NAT returned error");
				#endif
				return IP_NAT_ERROR;
			default:
				#ifdef DEBUG
				bpf_printk("IP6->IP4: ICMP NAT returned undefined return code, please file a bug report");
				#endif
				return IP_NAT_UNDEFINED;
			}
		}
		break;
	case IPPROTO_UDP:
		ret = bpf_l4_csum_replace(skb, l4_offset + offsetof(struct udphdr, check), 0, l4_csum_diff, BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0);
		if (ret < 0) {
			#ifdef DEBUG
			bpf_printk("IP6->IP4: UDP checksum replace failed with code: %d", ret);
			#endif
			return IP_NAT_ERROR;
		}
		break;
	case IPPROTO_TCP:
		ret = bpf_l4_csum_replace(skb, l4_offset + offsetof(struct tcphdr, check), 0, l4_csum_diff, BPF_F_PSEUDO_HDR);
		if (ret < 0) {
			#ifdef DEBUG
			bpf_printk("IP6->IP4: TCP checksum replace failed with code: %d", ret);
			#endif
			return IP_NAT_ERROR;
		}
		break;
	default:
		#ifdef DEBUG
		bpf_printk("IP6->IP4: protocol not supported: %d", ip4.protocol);
		#endif
		return IP_NAT_NOT_SUPPORTED;
	}

	// Copy over the new IPv4 header.
	// This takes care of updating the skb->csum field for a CHECKSUM_COMPLETE packet.
	// TODO: change to BPF_F_RECOMPUTE_CSUM
	ret = bpf_skb_store_bytes(skb, ip_offset, &ip4, sizeof(struct iphdr), 0);
	if (ret < 0) {
		#ifdef DEBUG
		bpf_printk("IP6->IP4: bpf_skb_store_bytes failed with code: %d", ret);
		#endif
		return IP_NAT_ERROR;
	}

	#ifdef DEBUG
	bpf_printk("IP6->IP4 packet: saddr: %pI4, daddr: %pI4", &ip4.saddr, &ip4.daddr);
	#endif
	return IP_NAT_OK;
}

static __always_inline int ip4_to_ip6(struct __sk_buff *skb, const int ip_offset) {
	struct iphdr ip4 = {};
	struct ipv6hdr ip6 = {};
	int ret = 0;
	__u16 *p = (void *)&ip6;
	__wsum pseudohdr_csum = 0;
	int l4_offset = 0;
	__wsum l4_csum_diff = 0;
	__u32 dst_addr = 0;
	const __be16 ethtype = bpf_htons(ETH_P_IPV6);

	ret = bpf_skb_load_bytes(skb, ip_offset, &ip4, sizeof(struct iphdr));
	if (ret < 0) {
		#ifdef DEBUG
		bpf_printk("IP4->IP6: bpf_skb_load_bytes failed with code: %d", ret);
		#endif
		return IP_NAT_ERROR;
	}

	// Zero assignments are here for readability, the entire struct is
	// already memset to 0, so they're not necessary.
	ip6.version = 6;
	ip6.priority = ip4.tos >> 4;
	ip6.payload_len = bpf_htons(bpf_ntohs(ip4.tot_len) - 20);
	ip6.hop_limit = ip4.ttl;
	ip6.nexthdr = (ip4.protocol == IPPROTO_ICMP) ? IPPROTO_ICMPV6 : ip4.protocol;

	ip6.flow_lbl[0] = (__u8)((ip4.tos & 0xF) << 4);
	ip6.flow_lbl[1] = 0;
	ip6.flow_lbl[2] = 0;

	// RFC 8215: use well-known prefix 64:ff9b for IPv6 src addr.
	ip6.saddr.in6_u.u6_addr32[0] = bpf_htonl(IPV6_NAT64_PREFIX_0 & IPV6_NAT64_MASK_0);
	ip6.saddr.in6_u.u6_addr32[1] = bpf_htonl(IPV6_NAT64_PREFIX_1 & IPV6_NAT64_MASK_1);
	ip6.saddr.in6_u.u6_addr32[2] = bpf_htonl(IPV6_NAT64_PREFIX_2 & IPV6_NAT64_MASK_2);
	ip6.saddr.in6_u.u6_addr32[3] = ip4.saddr;

	// Use container subnet here for dst address. Pod prefix is used for the
	// last byte.
	dst_addr = (POD_PREFIX_3 & POD_MASK_3) | (bpf_ntohl(ip4.daddr) & (~POD_MASK_3));
	ip6.daddr.in6_u.u6_addr32[0] = bpf_htonl(POD_PREFIX_0 & POD_MASK_0);
	ip6.daddr.in6_u.u6_addr32[1] = bpf_htonl(POD_PREFIX_1 & POD_MASK_1);
	ip6.daddr.in6_u.u6_addr32[2] = bpf_htonl(POD_PREFIX_2 & POD_MASK_2);
	ip6.daddr.in6_u.u6_addr32[3] = bpf_htonl(dst_addr);

	// This also takes care of resizing socket buffer to handle different IP
	// header size.
	ret = bpf_skb_change_proto(skb, ethtype, 0);
	if (ret < 0) {
		#ifdef DEBUG
		bpf_printk("IP4->IP6: bpf_skb_change_proto failed with code: %d", ret);
		#endif
		return IP_NAT_ERROR;
	}

	// bpf_skb_change_proto resized socket buffer to include different IP
	// header, after the change L4 offset is now based on IPv6 header size.
	l4_offset = ip_offset + sizeof(struct ipv6hdr);

	// See comment for IP6->IP4 direction for reasoning behind this.
	l4_csum_diff = bpf_csum_diff((void *)&(ip4.saddr), 2*sizeof(__u32), (void *)&(ip6.saddr), 2*sizeof(struct in6_addr), 0);

	switch (ip6.nexthdr) {
	case IPPROTO_ICMPV6:
		pseudohdr_csum = ip6_pseudohdr_csum(&ip6);
		ret = icmp4_to_icmp6(skb, l4_offset, pseudohdr_csum);
		if (ret < 0) {
			switch (ret) {
			case ICMP_NAT_NOT_SUPPORTED:
				#ifdef DEBUG
				bpf_printk("IP4->IP6: ICMP NAT not supported");
				#endif
				return IP_NAT_NOT_SUPPORTED;
			case ICMP_NAT_ERROR:
				#ifdef DEBUG
				bpf_printk("IP4->IP6: ICMP NAT returned error");
				#endif
				return IP_NAT_ERROR;
			default:
				#ifdef DEBUG
				bpf_printk("IP4->IP6: ICMP NAT returned undefined return code, please file a bug report");
				#endif
				return IP_NAT_UNDEFINED;
			}
		}

		break;
	case IPPROTO_UDP:
		ret = bpf_l4_csum_replace(skb, l4_offset + offsetof(struct udphdr, check), 0, l4_csum_diff, BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0);
		if (ret < 0) {
			#ifdef DEBUG
			bpf_printk("IP4->IP6: UDP checksum replace failed with code: %d", ret);
			#endif
			return IP_NAT_ERROR;
		}
		break;
	case IPPROTO_TCP:
		ret = bpf_l4_csum_replace(skb, l4_offset + offsetof(struct tcphdr, check), 0, l4_csum_diff, BPF_F_PSEUDO_HDR);
		if (ret < 0) {
			#ifdef DEBUG
			bpf_printk("IP4->IP6: TCP checksum replace failed with code: %d", ret);
			#endif
			return IP_NAT_ERROR;
		}

		break;
	default:
		#ifdef DEBUG
		bpf_printk("IP4->IP6: protocol not supported: %d", ip6.nexthdr);
		#endif
		return IP_NAT_NOT_SUPPORTED;
	}

	// Copy over the new IPv6 header.
	// This takes care of updating the skb->csum field for a CHECKSUM_COMPLETE packet.
	ret = bpf_skb_store_bytes(skb, sizeof(struct ethhdr), &ip6, sizeof(struct ipv6hdr), BPF_F_RECOMPUTE_CSUM);
	if (ret < 0) {
		#ifdef DEBUG
		bpf_printk("IP4->IP6: bpf_skb_store_bytes failed with code: %d", ret);
		#endif
		return IP_NAT_ERROR;
	}

	#ifdef DEBUG
	bpf_printk("IP4->IP6 packet: saddr: %pI6, daddr: %pI6", &ip6.saddr, &ip6.daddr);
	#endif
	return IP_NAT_OK;
}

// Create an IPv4 packets using as destination address the last 4 bytes the
// dst IPv6 address with the NAT64 prefix.
// Use as source address the last digit of the soucre address with the 169.254.64.x prefix
// Assume there are less than 254 pods always in the node and that range is empty
SEC("tc/nat64")
int nat64(struct __sk_buff *skb) {
	struct ethhdr eth = {};
	const __be16 ethtype = bpf_htons(ETH_P_IP);
	int ret = 0;

	#ifdef DEBUG
	bpf_printk("NAT64: starting...");
	#endif

	// Forward packet if we can't handle it.
	if (!nat64_valid(skb)) {
		#ifdef DEBUG
		bpf_printk("NAT64 packet forwarded: not valid for nat64");
		#endif
		return TC_ACT_OK;
	}

	ret = bpf_skb_load_bytes(skb, 0, &eth, sizeof(struct ethhdr));
	if (ret < 0) {
		#ifdef DEBUG
		bpf_printk("NAT64 packet dropped: bpf_skb_load_bytes failed for ethhdr");
		#endif
		return TC_ACT_SHOT;
	}

	// Replace the ethertype for a correct one for IPv4 packet.
	eth.h_proto = ethtype;

	ret = ip6_to_ip4(skb,  sizeof(struct ethhdr));
	if (ret < 0) {
		switch (ret) {
		case IP_NAT_NOT_SUPPORTED:
			#ifdef DEBUG
			bpf_printk("NAT64 packet forwarded: protocol not supported");
			#endif
			return TC_ACT_OK;
		case IP_NAT_ERROR:
			#ifdef DEBUG
			bpf_printk("NAT64 packet dropped: IP NAT returned error");
			#endif
			return TC_ACT_SHOT;
		default:
			#ifdef DEBUG
			bpf_printk("NAT64 packet forwarded: IP NAT returned undefined error code, please file a bug report");
			#endif
			return TC_ACT_OK;
		}
	}

	// Copy over the ethernet header with updated ethertype.
	ret = bpf_skb_store_bytes(skb, 0, &eth, sizeof(struct ethhdr), 0);
	if (ret < 0) {
		#ifdef DEBUG
		bpf_printk("NAT64 packet dropped: copy eth header");
		#endif
		return TC_ACT_SHOT;
	}
	#ifdef DEBUG
	bpf_printk("NAT64 finished...");
	#endif

	struct bpf_fib_lookup fib_params = {};
	int lookup_flags = 0;

	ret = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), lookup_flags);
	if (ret < 0) {
		return TC_ACT_SHOT;
	}
	return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}

// Build an IPv6 packet from an IPv4 packet
// destination address is pod prefix plus last digit from 169.254.64.x
// source address is the IPv4 src address embedded on the well known NAT64 prefix
SEC("tc/nat46")
int nat46(struct __sk_buff *skb) {
	struct ethhdr eth = {};
	const __be16 ethtype = bpf_htons(ETH_P_IPV6);
	int ret = 0;

	#ifdef DEBUG
	bpf_printk("NAT46: starting...");
	#endif

	// Forward packet if we can't handle it.
	if (!nat46_valid(skb)) {
		#ifdef DEBUG
		bpf_printk("NAT46 packet forwarded: not valid for nat46");
		#endif
		return TC_ACT_OK;
	}

	ret = bpf_skb_load_bytes(skb, 0, &eth, sizeof(struct ethhdr));
	if (ret < 0) {
		#ifdef DEBUG
		bpf_printk("NAT46 packet dropped: bpf_skb_load_bytes failed for ethhdr");
		#endif
		return TC_ACT_SHOT;
	}

	// Replace the ethertype for a correct one for IPv6 packet.
	eth.h_proto = ethtype;

	ret = ip4_to_ip6(skb,  sizeof(struct ethhdr));
	if (ret < 0) {
		switch (ret) {
		case IP_NAT_NOT_SUPPORTED:
			#ifdef DEBUG
			bpf_printk("NAT46 packet forwarded: protocol not supported");
			#endif
			return TC_ACT_OK;
		case IP_NAT_ERROR:
			#ifdef DEBUG
			bpf_printk("NAT46 packet dropped: IP NAT returned error");
			#endif
			return TC_ACT_SHOT;
		default:
			#ifdef DEBUG
			bpf_printk("NAT46 packet forwarded: IP NAT returned undefined error code, please file a bug report");
			#endif
			return TC_ACT_OK;
		}
	}

	// Copy over the ethernet header with updated ethertype.
	ret = bpf_skb_store_bytes(skb, 0, &eth, sizeof(struct ethhdr), 0);
	if (ret < 0) {
		#ifdef DEBUG
		bpf_printk("NAT46 packet dropped: copy eth header");
		#endif
		return TC_ACT_SHOT;
	}

	#ifdef DEBUG
	bpf_printk("NAT46 finished...");
	#endif
	return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}

char __license[] SEC("license") = "GPL";

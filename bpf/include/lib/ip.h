/*
Copyright 2025 The Kubernetes Authors.

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

#pragma once

#include <linux/ip.h>
#include <linux/ip6.h>
#include <linux/bpf.h>
#include <linux/types.h>

#include <lib/config.h>
#include <lib/csum.h>
#include <lib/icmp.h>

// Success error codes >= 0
#define IP_NAT_OK             0

// Failure error codes < 0
#define IP_NAT_NOT_SUPPORTED  -1
// TODO: differentiate errors between drop and forward?
#define IP_NAT_ERROR          -2
#define IP_NAT_UNDEFINED      -127

// Helper forward declarations, so that we can have the most
// important functions code first.
static __always_inline __u32 ip4_new_saddr(struct ipv6hdr *ip6);
static __always_inline __wsum ip6_pseudohdr_csum(struct ipv6hdr *ip6);

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

	// Initialize header to all zeroes.
	for (size_t i = 0; i < sizeof(struct iphdr) / sizeof(__u16); ++i) {
		p[i] = 0;
	}

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

	// Initialize header to all zeroes
	for (size_t i = 0; i < sizeof(struct ipv6hdr) / sizeof(__u16); ++i) {
		p[i] = 0;
	}

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
	ip6.saddr.in6_u.u6_addr32[0] = bpf_htonl(IPV6_NAT_PREFIX_0 & IPV6_NAT_MASK_0);
	ip6.saddr.in6_u.u6_addr32[1] = bpf_htonl(IPV6_NAT_PREFIX_1 & IPV6_NAT_MASK_1);
	ip6.saddr.in6_u.u6_addr32[2] = bpf_htonl(IPV6_NAT_PREFIX_2 & IPV6_NAT_MASK_2);
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

// TODO: this works only because of how k8s assigns IP to pods on nodes.
//       This naive approach works with max limit of 256 pods deployed
//       on the node. Future work would be to remove this limit by supporting
//       stateful src IP assignment.
static __always_inline __u32 ip4_new_saddr(struct ipv6hdr *ip6) {
	// Build source ip, save variable bytes of the ipv6 address plus the prefix.
	// 198.18.xxx.xxx
	__u32 new_src = IPV4_NAT_PREFIX & IPV4_NAT_MASK;
	__u32 mask = (~IPV4_NAT_MASK) & (~POD_MASK_3);
	__u32 ip6_saved_bytes = bpf_ntohl(ip6->saddr.in6_u.u6_addr32[3]) & mask;

	new_src = bpf_htonl(new_src | ip6_saved_bytes);
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

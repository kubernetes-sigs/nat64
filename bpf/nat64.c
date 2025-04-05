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

#include <lib/ip.h>

#define TC_ACT_OK	0
#define TC_ACT_SHOT	2

#define PACKET_HOST	0
#define DEBUG 1 // Define DEBUG as 1 for debug mode, 0 for production

/* Declare BPF maps */

// Helper forward declarations, so that we can have the most
// important functions code first.
static __always_inline bool nat46_valid(const struct __sk_buff *skb);
static __always_inline bool nat64_valid(const struct __sk_buff *skb);

// Create an IPv4 packets using as destination address the last 4 bytes the
// dst IPv6 address with the NAT64 prefix.
// Use as source address the last digit of the soucre address with the 169.254.64.x prefix
// Assume there are less than 254 pods always in the node and that range is empty
SEC("tc/nat64")
int nat64(struct __sk_buff *skb) {
	struct ethhdr eth = {};
	const __be16 ethtype = bpf_htons(ETH_P_IP);
	const int l3_offset = sizeof(struct ethhdr);
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

	ret = ip6_to_ip4(skb, l3_offset);
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
	return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}

// Build an IPv6 packet from an IPv4 packet
// destination address is pod prefix plus last digit from 169.254.64.x
// source address is the IPv4 src address embedded on the well known NAT64 prefix
SEC("tc/nat46")
int nat46(struct __sk_buff *skb) {
	struct ethhdr eth = {};
	const __be16 ethtype = bpf_htons(ETH_P_IPV6);
	const int l3_offset = sizeof(struct ethhdr);
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

	ret = ip4_to_ip6(skb, l3_offset);
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

char __license[] SEC("license") = "GPL";

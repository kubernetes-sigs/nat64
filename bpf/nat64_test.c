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

#include <lib/test.h>

#include "nat64.c"

static char pkt[200];

__always_inline int udp_packet6(void *dst) {
	// delete nat64 filter: tc filter del dev nat64 egress prio 1
	// send UDP packet: dig @64:ff9b::8.8.8.8 www.google.es
	// dump IPv6 packet: tcpdump -i nat64 -A -nnvvvexxXXKS
	//
	// 0x0000:  b6e3 323c ecf9 b6e3 323c ecf9 86dd 600a  ..2<....2<....`.
	// 0x0010:  713b 003e 113f fd00 0010 0244 0000 0000  q;.>.?.....D....
	// 0x0020:  0000 0000 0012 0064 ff9b 0000 0000 0000  .......d........
	// 0x0030:  0000 0808 0808 a69c 0035 003e 0fc6 2f66  .........5.>../f
	// 0x0040:  0120 0001 0000 0000 0001 0377 7777 0667  ...........www.g
	// 0x0050:  6f6f 676c 6502 6573 0000 0100 0100 0029  oogle.es.......)
	// 0x0060:  1000 0000 0000 000c 000a 0008 e84f 5b98  .............O[.
	// 0x0070:  42f0 aeb0                                B...

	// hex dumps in comments are using host byte order,
	// so need to convert to network byte order where
	// applicable

	// eth header: b6e3 323c ecf9 b6e3 323c ecf9 86dd

	// use 00:00:00:00:00:00 mac addresses to guarantee
	// skb->pkt_type == PACKET_HOST, if we use the ones from
	// dumped packet, it's gonna be PACKET_OTHERHOST instead
	struct ethhdr l2 = {
		.h_source = {0, 0, 0, 0, 0, 0},
		.h_dest = {0, 0, 0, 0, 0, 0},
		.h_proto = bpf_htons(ETH_P_IPV6) // 0x86dd (IPv6)
	};
	// ipv6 header: 600a 713b 003e 113f fd00 0010 0244 0000
	//              0000 0000 0000 0012 0064 ff9b 0000 0000
	//              0000 0000 0808 0808
	struct ipv6hdr l3 = {
		.version = 6,
		.priority = 0,
		.flow_lbl = {0x0a, 0x71, 0x3b},
		.payload_len = bpf_htons(62), // 0x003e
		.nexthdr = 17, // 0x11 (UDP)
		.hop_limit = 63, // 0x3f
		.saddr = { // fd00:10:244::12
			.in6_u = {
				.u6_addr32 = {bpf_htonl(0xfd000010), bpf_htonl(0x2440000), 0, bpf_htonl(0x12)}
			}
		},
		.daddr = { // 64:ff9b::808:808
			.in6_u = {
				.u6_addr32 = {bpf_htonl(0x64ff9b), 0, 0, bpf_htonl(0x8080808)}
			}
		},
	};
	// udp header: a69c 0035 003e 0fc6
	struct udphdr l4 = {
		.source = bpf_htons(42652), // 0xa69c
		.dest = bpf_htons(53), // 0x0035
		.len = bpf_htons(62), // 0x003e
		.check = 0x0fc6
	};
	// payload: 2f66 0120 0001 0000 0000 0001 0377 7777
	//          0667 6f6f 676c 6502 6573 0000 0100 0100
	//          0029 1000 0000 0000 000c 000a 0008 e84f
	//          5b98 42f0 aeb0
	char payload[54] = {
		0x2f, 0x66, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77,
		0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02,
		0x65, 0x73, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
		0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0xe8, 0x4f,
		0x5b, 0x98, 0x42, 0xf0, 0xae, 0xb0
	};

	__u8 *p = (void *)dst;
	__u8 *src = 0;

	// Copy L2 header
	src = (void *)&l2;
	for (size_t i = 0; i < sizeof(struct ethhdr) / sizeof(__u8); ++i) {
		p[i] = src[i];
	}
	p += sizeof(struct ethhdr) / sizeof(__u8);

	// Copy L3 header
	src = (void *)&l3;
	for (size_t i = 0; i < sizeof(struct ipv6hdr) / sizeof(__u8); ++i) {
		p[i] = src[i];
	}
	p += sizeof(struct ipv6hdr) / sizeof(__u8);

	// Copy L4 header
	src = (void *)&l4;
	for (size_t i = 0; i < sizeof(struct udphdr) / sizeof(__u8); ++i) {
		p[i] = src[i];
	}
	p += sizeof(struct udphdr) / sizeof(__u8);

	// Copy payload
	src = (void *)&payload;
	for (size_t i = 0; i < 54; ++i) {
		p[i] = src[i];
	}
	p += 54;

	return (int)(p - (__u8 *)dst);
}

// populate packet data in PKTGEN hook so that
// all skb fields that are inferred from data
// (like skb->protocol, skb->pkt_type) are
// initialized correctly
PKTGEN("tc", "nat64_udp")
int test_nat64_udp_pktgen(struct __sk_buff *skb) {
	int pkt_size = udp_packet6(pkt);

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + pkt_size > data_end)
		return TEST_ERROR;

	__u8 *dst = data;
	__u8 *p = (void *)pkt;
	for (size_t i = 0; i < pkt_size; ++i) {
		dst[i] = p[i];
	}

	return 0;
}

CHECK("tc", "nat64_udp")
int test_nat64_udp_check(struct __sk_buff *skb) {
	struct ethhdr eth = {};
	struct iphdr ip = {};
	struct udphdr udp = {};
	const int payload_len = 54;
	int ret = 0;
	int expected_pkt_size = sizeof(eth) + sizeof(ip) + sizeof(udp) + payload_len;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	test_init();

	// sanity check that skb is valid for nat64
	ret = nat64_valid(skb);
	assert(ret);

	// do nat64, skb should contain IPv4 packet now
	nat64(skb);
	assert(data + expected_pkt_size <= data_end);

	// verify L2 header
	test_log("verify L2 header");
	ret = bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));
	test_log("assert bpf_skb_load_bytes returns no error");
	assert(!ret);
	test_log("assert src / dst MAC addresses are as expected");
	for (size_t i = 0; i < 6; i++) {
		assert(eth.h_source[i] == 0x00);
		assert(eth.h_dest[i] == 0x00);
	}
	test_log("assert eth proto");
	assert(eth.h_proto == bpf_htons(ETH_P_IP));
	test_log("L2 header is correct");

	// verify L3 header
	test_log("verify L3 header");
	ret = bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip));
	test_log("assert bpf_skb_load_bytes returns no error");
	assert(!ret);
	test_log("assert IP version is 4");
	assert(ip.version == 4);
	test_log("assert ihl == %d", sizeof(struct iphdr) / sizeof(__u32));
	assert(ip.ihl == sizeof(struct iphdr) / sizeof(__u32));
	test_log("assert tos == 0");
	assert(ip.tos == 0); // (0x00 << 4) + (0x0a >> 4)
	test_log("assert tot_len == %d", 62 + sizeof(ip));
	assert(ip.tot_len == bpf_htons(62 + sizeof(ip)));
	test_log("assert protocol == %d", IPPROTO_UDP);
	assert(ip.protocol == IPPROTO_UDP);
	test_log("assert ttl == 63");
	assert(ip.ttl = 63);
	// we're not setting .id, .frag_off in nat64, skip checking them
	test_log("assert saddr is 169.254.64.18");
	assert(ip.saddr = bpf_htons(0xa9fe4012)); // 169.254.64.18
	test_log("assert daddr is 8.8.8.8");
	assert(ip.daddr = bpf_htons(0x8080808)); // 8.8.8.8
	test_log("L3 header is correct");

	// verify L4 header
	test_log("verify L4 header");
	ret = bpf_skb_load_bytes(skb, sizeof(eth) + sizeof(ip), &udp, sizeof(udp));
	test_log("assert bpf_skb_load_bytes returns no error");
	assert(!ret);
	test_log("assert source == 42652");
	assert(udp.source = bpf_htons(42652));
	test_log("assert dest == 53");
	assert(udp.dest = bpf_htons(53));
	test_log("assert len == 62");
	assert(udp.len = bpf_htons(62));
	test_log("L4 header is correct");

	// TODO: verify checksums for L3 and L4

	test_finish();
}


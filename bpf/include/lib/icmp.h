#pragma once

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/bpf.h>
#include <linux/types.h>

#include <lib/csum.h>

// Success error codes >= 0
#define ICMP_NAT_OK		0

// Failure error codes < 0
#define ICMP_NAT_NOT_SUPPORTED  -1
// TODO: differentiate errors between drop and forward?
#define ICMP_NAT_ERROR		-2

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
		bpf_printk("ICMP6->ICMP4: bpf_skb_load_bytes failed with code: %d", ret);
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
			icmp4.un.frag.mtu = bpf_htons(1500);
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
		bpf_printk("ICMP6->ICMP4: bpf_skb_store_bytes failed with code: %d", ret);
		return ICMP_NAT_ERROR;
	}

	ret = bpf_l4_csum_replace(skb, icmp_csum_offset, 0, icmp_csum_diff, BPF_F_PSEUDO_HDR);
	if (ret < 0) {
		bpf_printk("ICMP6->ICMP4: bpf_l4_csum_replace failed with code: %d", ret);
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
		bpf_printk("ICMP4->ICMP6: bpf_skb_load_bytes failed with code: %d", ret);
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
		bpf_printk("ICMP4->ICMP6: bpf_skb_store_bytes failed with code: %d", ret);
		return ICMP_NAT_ERROR;
	}

	ret = bpf_l4_csum_replace(skb, icmp6_csum_offset, 0, icmp6_csum_diff, BPF_F_PSEUDO_HDR);
	if (ret < 0) {
		bpf_printk("ICMP4->ICMP6: bpf_l4_csum_replace failed with code: %d", ret);
		return ICMP_NAT_ERROR;
	}

	return ICMP_NAT_OK;
}


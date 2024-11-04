#pragma once

#include <linux/types.h>
#include <bpf/bpf_endian.h>

static __always_inline __wsum csum_add(__wsum csum, __wsum addend) {
	csum += addend;
	return csum + (csum < addend);
}

static __always_inline __wsum csum_sub(__wsum csum, __wsum addend) {
	return csum_add(csum, ~addend);
}


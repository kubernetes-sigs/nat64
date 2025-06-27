#pragma once

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

#define NAT64_METRICS_ENABLED 1
#define NAT64_SUCCESSFUL 0
#define NAT64_UNSUPPORTED -1
#define NAT64_ERROR -2
#define NAT64_UNDEFINED -3


struct nat64_metrics_key {
  __s32 reason;
  __u8 protocol;
  __u8 pad1, pad2, pad3;
} __attribute__((packed));

struct nat64_metrics_value {
  int count;
  int pad1;
};

struct nat64_metrics_t {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, struct nat64_metrics_key);
  __type(value, struct nat64_metrics_value);
  __uint(max_entries, 256);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
};

extern struct nat64_metrics_t ip64_metrics SEC(".maps");
extern struct nat64_metrics_t ip46_metrics SEC(".maps");

/**
 * update_metrics
 * @reason: 0: successful, 1: unsupported, 2: error, 3 undefined
 * Updates the IPv6 metrics map.
 */

static __always_inline void update_nat64_metrics(void* metrics_map, int reason, __u8 protocol)
{
  #ifdef NAT64_METRICS_ENABLED
    struct nat64_metrics_value initial_value = {.count = 0, .pad1 = 0};
    struct nat64_metrics_key key =  {
      .reason = reason,
      .protocol = protocol,
      .pad1 = 0,
      .pad2 = 0,
      .pad3 = 0
    };
    bpf_map_update_elem(metrics_map, &key, &initial_value, BPF_NOEXIST);

    struct nat64_metrics_value *entry, new_entry;
    entry = bpf_map_lookup_elem(metrics_map, &key);
    new_entry.count = entry ? entry->count + 1 : 1;
    new_entry.pad1 = 0;
    bpf_map_update_elem(metrics_map, &key, &new_entry, BPF_ANY);
  #else
    return;
  #endif
}

static __always_inline void update_ip64_metrics(int reason, __u8 protocol) {
  return update_nat64_metrics(&ip64_metrics, reason, protocol);
}

static __always_inline void update_ip46_metrics(int reason, __u8 protocol) {
  return update_nat64_metrics(&ip46_metrics, reason, protocol);
}

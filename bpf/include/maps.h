#ifndef MAPS_H
#define MAPS_H

#define NAT64_SUCCESSFUL 0
#define NAT64_UNSUPPORTED 1
#define NAT64_ERROR 2

#include "bpf/bpf_helpers.h"
#include "linux/bpf.h"

struct ipv6_metrics_key {
  __s32 reason;
  __u8 protocol;
  __u8 pad1, pad2, pad3;
} __attribute__((packed));

struct ipv6_metrics_value {
  int count;
  int pad1;
};

struct ipv6_metrics_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct ipv6_metrics_key);
  __type(value, struct ipv6_metrics_value);
  __uint(max_entries, 256);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
};
extern struct ipv6_metrics_t ipv6_metrics SEC(".maps");

/**
 * update_metrics
 * @reason: 0: successful, 1: unsupported, 2: error
 * Updates the IPv6 metrics map.
 */
static __always_inline void update_ipv6_metrics(int reason, __u8 protocol)
{
  struct ipv6_metrics_value initial_value = {.count = 0, .pad1 = 0};
  struct ipv6_metrics_key key =  {
    .reason = reason,
    .protocol = protocol,
    .pad1 = 0,
    .pad2 = 0,
    .pad3 = 0
  };
  bpf_map_update_elem(&ipv6_metrics, &key, &initial_value, BPF_NOEXIST);

  struct ipv6_metrics_value *entry, new_entry;
  entry = bpf_map_lookup_elem(&ipv6_metrics, &key);
  new_entry.count = entry ? entry->count + 1 : 1;
  new_entry.pad1 = 0;
  bpf_map_update_elem(&ipv6_metrics, &key, &new_entry, 0);
}
#endif //MAPS_H

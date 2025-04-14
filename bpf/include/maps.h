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
} __attribute__((packed));

struct ipv6_metrics_value {
  int count;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct ipv6_metrics_key);
  __type(value, struct ipv6_metrics_value);
  __uint(max_entries, 256);
} ipv6_metrics SEC(".maps");

/**
 * update_metrics
 * @reason: 0: successful, 1: unsupported, 2: error
 * Updates the IPv6 metrics map.
 */
static __always_inline void update_ipv6_metrics(int reason, __u8 protocol)
{
  struct ipv6_metrics_value initial_value = {.count = 0};
  struct ipv6_metrics_key key =  {
    .reason = reason,
    .protocol = protocol,
  };
  bpf_map_update_elem(&ipv6_metrics, &key, &initial_value, BPF_NOEXIST);

  struct ipv6_metrics_value *entry, new_entry;
  entry = bpf_map_lookup_elem(&ipv6_metrics, &key);
  new_entry.count = entry ? entry->count + 1 : 1;
  bpf_map_update_elem(&ipv6_metrics, &key, &new_entry, 0);
}
#endif //MAPS_H

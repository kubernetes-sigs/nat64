#ifndef MAPS_H
#define MAPS_H

#define NAT64_SUCCESSFUL 0
#define NAT64_UNSUPPORTED 1
#define NAT64_ERROR 2

#include "linux/in.h"
#include "bpf/bpf_helpers.h"
#include "linux/bpf.h"

struct ipv6_metrics_value {
  __u8 protocol;
  int count;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, int);
  __type(value, struct ipv6_metrics);
  __uint(max_entries, 16);
} ipv6_metrics SEC(".maps");

/**
 * update_metrics
 * @reason: 0: successfull, 1: unsupported, 2: error
 * Updates the IPv6 metrics map.
 */
static __always_inline void update_ipv6_metrics(int reason, __u8 protocol)
{
  struct ipv6_metrics_value *entry, new_entry = {protocol};
  entry = bpf_map_lookup_elem(&ipv6_metrics, &reason);
  new_entry.count = entry ? entry->count + 1 : 1;
  bpf_map_update_elem(&ipv6_metrics, &reason, &new_entry, 0);
}
#endif //MAPS_H

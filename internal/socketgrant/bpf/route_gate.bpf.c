// SPDX-License-Identifier: GPL-2.0-only
// IPv4 UDP OUTPUT gate. Each instance has an nft-checked output interface.
// Every unsupported/malformed/missing/expired case returns no match, not Allow.
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "gate.h"
const volatile __u32 output_ifindex = 0;
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 64);
  __type(key, struct gate_key);
  __type(value, struct gate_value);
} grants SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} epoch SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 64);
  __type(key, struct gate_key);
  __type(value, struct gate_stats);
} hit_stats SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct gate_stats);
} totals SEC(".maps");
SEC("socket")
int socket_gate(struct __sk_buff *skb) {
  struct iphdr ip = {};
  struct udphdr udp = {};
  struct gate_key key = {};
  __u32 zero = 0;
  if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip))) return 0;
  if (ip.version != 4 || ip.ihl < 5 || ip.protocol != 17 ||
      (ip.frag_off & bpf_htons(0x3fff))) return 0;
  __u32 offset = ip.ihl * 4;
  if (bpf_ntohs(ip.tot_len) < offset + sizeof(udp) ||
      bpf_skb_load_bytes(skb, offset, &udp, sizeof(udp))) return 0;
  if (bpf_ntohs(udp.len) < sizeof(udp) ||
      bpf_ntohs(udp.len) > bpf_ntohs(ip.tot_len) - offset) return 0;
  if (!output_ifindex) return 0;
  key.ifindex = output_ifindex;
  key.cookie = bpf_get_socket_cookie(skb);
  if (!key.cookie) return 0;
  key.source = ip.saddr;
  key.destination = ip.daddr;
  key.source_port = udp.source;
  key.destination_port = udp.dest;
  struct gate_value *v = bpf_map_lookup_elem(&grants, &key);
  __u64 *generation = bpf_map_lookup_elem(&epoch, &zero);
  if (!v || !generation || !*generation || v->generation != *generation) return 0;
  // BOOTTIME includes suspend: resume cannot extend an old authorization.
  __u64 now = bpf_ktime_get_boot_ns();
  if (now >= v->deadline_ns) return 0;
  struct gate_stats *s = bpf_map_lookup_elem(&hit_stats, &key);
  if (s) {
    __sync_fetch_and_add(&s->packets, 1);
    __sync_fetch_and_add(&s->bytes, skb->len);
    s->last_seen_ns = now; // activity only, never evidence or expiry renewal
  }
  s = bpf_map_lookup_elem(&totals, &zero);
  if (s) {
    __sync_fetch_and_add(&s->packets, 1);
    __sync_fetch_and_add(&s->bytes, skb->len);
  }
  return 1;
}
char LICENSE[] SEC("license") = "GPL";

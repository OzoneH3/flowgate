// Socket-binding shaping only. NEVER a firewall permission source.
// clang-format off
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
// clang-format on
struct binding {
  __u64 until;
  __u32 minor;
  __u32 reserved;
};
struct config {
  __u64 until;
  __u32 major;
  __u32 reserved;
};
struct counter {
  __u64 packets, bytes;
};
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, __u64);
  __type(value, struct binding);
} bindings SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct config);
} config SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 18);
  __type(key, __u32);
  __type(value, struct counter);
} counters SEC(".maps");
SEC("classifier") int classify(struct __sk_buff *skb) {
  __u32 z = 0, idx = 0;
  struct config *c = bpf_map_lookup_elem(&config, &z);
  if (!c)
    return TC_ACT_UNSPEC;
  __u64 now = bpf_ktime_get_ns(), cookie = bpf_get_socket_cookie(skb);
  struct binding *b = bpf_map_lookup_elem(&bindings, &cookie);
  skb->priority = (c->major << 16) | 0xfffe;
  if (c->until > now && b && b->until > now && b->minor >= 1 &&
      b->minor <= 0xfffd) {
    skb->priority = (c->major << 16) | b->minor;
    idx = 1; // Aggregate classified counter; class IDs are not recycled.
  } else if (b)
    idx = 17;
  struct counter *n = bpf_map_lookup_elem(&counters, &idx);
  if (n) {
    n->packets++;
    n->bytes += skb->len;
  }
  return TC_ACT_UNSPEC;
}
char LICENSE[] SEC("license") = "GPL";

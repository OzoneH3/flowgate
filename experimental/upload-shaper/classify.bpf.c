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
  // Preserve unrelated SO_PRIORITY/QoS. Values in our reserved class namespace
  // cannot be supplied by an unbound socket to inherit another application's cap.
  if ((skb->priority >> 16) == c->major)
    skb->priority = 0;
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
  // Segmentation visibility: a GSO/TSO superpacket reaches this hook as ONE
  // skb carrying gso_segs segments. Index 2/3 count such skbs (classified /
  // not classified); index 4 accumulates their segment counts (packets =
  // classified, bytes = not classified). These prove segmented skbs reached
  // the shaping path; enabled offload flags alone never do.
  if (skb->gso_segs > 1) {
    __u32 g = idx == 1 ? 2 : 3;
    struct counter *s = bpf_map_lookup_elem(&counters, &g);
    if (s) {
      s->packets++;
      s->bytes += skb->len;
    }
    g = 4;
    s = bpf_map_lookup_elem(&counters, &g);
    if (s) {
      if (idx == 1)
        s->packets += skb->gso_segs;
      else
        s->bytes += skb->gso_segs;
    }
  }
  return TC_ACT_UNSPEC;
}
char LICENSE[] SEC("license") = "GPL";

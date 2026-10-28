// Egress (upload) adapter: socket-binding shaping only. NEVER a firewall
// permission source. Maps are shared with ingress.bpf.c (see shaping.bpf.h).
// clang-format off
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include "shaping.bpf.h"
// clang-format on
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
  } else if (b && b->minor)
    idx = 17; // A download-only binding (minor 0) is ordinary default egress.
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

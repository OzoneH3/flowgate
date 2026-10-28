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
  // An ARRAY map always returns its element; this guard only satisfies the
  // verifier. Before `init` the major is 0 and no FlowGate qdisc exists yet.
  if (!c)
    return TC_ACT_UNSPEC;
  __u64 now = bpf_ktime_get_ns(), cookie = bpf_get_socket_cookie(skb);
  struct binding *b = bpf_map_lookup_elem(&bindings, &cookie);
  // A packet can never select a class in our reserved major namespace itself
  // (SO_PRIORITY): it is cleared before any decision. The root HTB default is
  // the bypass class outside the budget, so every unmarked packet bypasses.
  if ((skb->priority >> 16) == c->major)
    skb->priority = 0;
  int live = c->until > now;
  if (live && b && b->until > now && b->minor >= 1 &&
      b->minor <= FG_MAX_APP_MINOR) {
    skb->priority = (c->major << 16) | b->minor;
    idx = 1; // Aggregate classified counter; class IDs are not recycled.
  } else {
    if (b && b->minor)
      idx = 17; // A download-only binding (minor 0) is ordinary default egress.
    if (!live)
      fg_count(11, skb); // lease expired: new packets bypass every budget
    else if (c->flags & FG_UL_BUDGET) {
      // Host-local scope evidence: the reversed packet tuple must exactly
      // match a CONNECTED socket in this device namespace. A socket cookie
      // alone does not establish namespace or local origin.
      struct fg_pkt p = {};
      int r = fg_parse(skb, &p, 1);
      if (r == 1 && p.unicast) {
        struct bpf_sock *sk = p.proto == IPPROTO_TCP
            ? bpf_sk_lookup_tcp(skb, &p.t, p.size, BPF_F_CURRENT_NETNS, 0)
            : bpf_sk_lookup_udp(skb, &p.t, p.size, BPF_F_CURRENT_NETNS, 0);
        int exact = 0;
        if (sk) {
          exact = fg_exact(sk, &p);
          bpf_sk_release(sk);
        }
        if (exact) {
          skb->priority = (c->major << 16) | FG_DEFAULT_MINOR;
          fg_count(14, skb);
        } else
          fg_count(13, skb);
      } else if (r)
        fg_count(10, skb);
    }
  }
  fg_count(idx, skb);
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

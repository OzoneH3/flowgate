// Download adapter: TC ingress classifier for the selected NIC. It resolves the
// LOCAL receiving established TCP socket from the packet 4-tuple
// (bpf_sk_lookup_tcp), reads that socket's cookie and, only when a binding with
// a download class exists, marks the skb with the IFB class and redirects it to
// the FlowGate-owned IFB where an HTB tree schedules local delivery.
// While a download budget is active, other TCP/UDP packets whose full 4-tuple
// exactly matches a CONNECTED local socket in this namespace (local address =
// packet destination, remote address/port = packet source) are redirected to
// the budgeted aggregate default class. Listener and wildcard/unconnected UDP
// matches are NOT accepted: a lookup can fall back to INADDR_ANY, so they do not
// prove local delivery (forwarded/DNAT traffic to a host port). Packets without
// such a socket, fragments, IPv6 extension headers, VLAN and multicast/broadcast
// are never redirected. Everything passes unchanged once the lease expires.
// Shaping only; NEVER a firewall permission source. The raw ingress skb cookie
// is never used (M0: it is absent or the peer sender's).
// clang-format off
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// clang-format on
// Minimal CO-RE view of the socket cookie; libbpf relocates by field name.
struct sock_common {
  struct { long counter; } skc_cookie;
} __attribute__((preserve_access_index));
struct sock {
  struct sock_common __sk_common;
} __attribute__((preserve_access_index));
struct inet_sock { struct sock sk; } __attribute__((preserve_access_index));
struct inet_connection_sock { struct inet_sock icsk_inet; } __attribute__((preserve_access_index));
struct tcp_sock { struct inet_connection_sock inet_conn; } __attribute__((preserve_access_index));

#include "shaping.bpf.h"


static __always_inline int redirect(struct __sk_buff *skb, __u32 major, __u32 minor, __u32 ifindex, __u32 idx) {
  skb->priority = (major << 16) | minor;
  fg_count(idx, skb);
  return bpf_redirect(ifindex, 0);
}

SEC("classifier") int classify_ingress(struct __sk_buff *skb) {
  __u32 z = 0;
  struct config *c = bpf_map_lookup_elem(&config, &z);
  struct download_config *d = bpf_map_lookup_elem(&download, &z);
  if (!c || !d || !d->ifindex || !d->major)
    return TC_ACT_UNSPEC;
  __u64 now = bpf_ktime_get_ns();
  if (c->until <= now)
    return TC_ACT_UNSPEC; // lease expired: every new packet bypasses the IFB
  int budget = d->flags & FG_DL_BUDGET;
  struct fg_pkt p = {};
  int r = fg_parse(skb, &p, 0);
  if (!r)
    return TC_ACT_UNSPEC; // non-IP / ICMPv6 control: never shaped
  if (r == 2) {
    if (budget)
      fg_count(9, skb);
    return TC_ACT_UNSPEC;
  }
  if (p.proto == IPPROTO_UDP) {
    // Per-application UDP download is unsupported; an exact connected local
    // UDP socket only qualifies the packet for the host-local aggregate.
    if (!budget)
      return TC_ACT_UNSPEC;
    if (!p.unicast) {
      fg_count(9, skb);
      return TC_ACT_UNSPEC;
    }
    struct bpf_sock *u = bpf_sk_lookup_udp(skb, &p.t, p.size, BPF_F_CURRENT_NETNS, 0);
    int exact = 0;
    if (u) {
      exact = fg_exact(u, &p);
      bpf_sk_release(u);
    }
    if (!exact) {
      fg_count(12, skb);
      return TC_ACT_UNSPEC;
    }
    return redirect(skb, d->major, FG_DEFAULT_MINOR, d->ifindex, 8);
  }
  // TCP. Per-application download keeps its existing contract: an exactly
  // matched ESTABLISHED local socket whose cookie has a fresh binding. The
  // aggregate additionally excludes VLAN and multicast/broadcast frames.
  struct bpf_sock *sk = bpf_sk_lookup_tcp(skb, &p.t, p.size, BPF_F_CURRENT_NETNS, 0);
  if (!sk) {
    fg_count(budget ? 12 : 6, skb);
    return TC_ACT_UNSPEC;
  }
  __u64 cookie = 0;
  int exact = fg_exact(sk, &p);
  if (exact && sk->state == BPF_TCP_ESTABLISHED) {
    struct tcp_sock *tp = bpf_skc_to_tcp_sock(sk);
    if (tp)
      cookie = tp->inet_conn.icsk_inet.sk.__sk_common.skc_cookie.counter;
  }
  bpf_sk_release(sk);
  struct binding *b = cookie ? bpf_map_lookup_elem(&bindings, &cookie) : 0;
  if (b && b->until > now && b->download >= 1 && b->download <= FG_MAX_APP_MINOR)
    return redirect(skb, d->major, b->download, d->ifindex, 5);
  fg_count(b ? 7 : 6, skb);
  if (!budget)
    return TC_ACT_UNSPEC;
  if (!p.unicast) {
    fg_count(9, skb);
    return TC_ACT_UNSPEC;
  }
  if (!exact) {
    fg_count(12, skb);
    return TC_ACT_UNSPEC;
  }
  return redirect(skb, d->major, FG_DEFAULT_MINOR, d->ifindex, 8);
}

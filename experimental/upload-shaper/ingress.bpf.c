// Download adapter: TC ingress classifier for the selected NIC. It resolves the
// LOCAL receiving established TCP socket from the packet 4-tuple
// (bpf_sk_lookup_tcp), reads that socket's cookie and, only when a binding with
// a download class exists, marks the skb with the IFB class and redirects it to
// the FlowGate-owned IFB where an HTB tree schedules local delivery.
// Everything else (unbound sockets, listeners, UDP, fragments, extension
// headers, non-IP) returns TC_ACT_UNSPEC and never touches the IFB.
// Shaping only; NEVER a firewall permission source. The raw ingress skb cookie
// is never used (M0: it is absent or the peer sender's).
// clang-format off
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
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

static __always_inline void count(__u32 idx, struct __sk_buff *skb) {
  struct counter *n = bpf_map_lookup_elem(&counters, &idx);
  if (n) {
    n->packets++;
    n->bytes += skb->len;
  }
}

SEC("classifier") int classify_ingress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data, *end = (void *)(long)skb->data_end;
  struct ethhdr *eth = data;
  struct bpf_sock_tuple t = {};
  __u32 size, z = 0, idx;
  if ((void *)(eth + 1) > end)
    return TC_ACT_UNSPEC;
  if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > end || ip->version != 4 || ip->ihl < 5 || ip->protocol != IPPROTO_TCP)
      return TC_ACT_UNSPEC;
    if (ip->frag_off & bpf_htons(0x3fff)) // fragments: explicit gap
      return TC_ACT_UNSPEC;
    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > end)
      return TC_ACT_UNSPEC;
    t.ipv4.saddr = ip->saddr;
    t.ipv4.daddr = ip->daddr;
    t.ipv4.sport = tcp->source;
    t.ipv4.dport = tcp->dest;
    size = sizeof(t.ipv4);
  } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > end || ip6->version != 6 || ip6->nexthdr != IPPROTO_TCP) // extension headers: explicit gap
      return TC_ACT_UNSPEC;
    struct tcphdr *tcp = (void *)(ip6 + 1);
    if ((void *)(tcp + 1) > end)
      return TC_ACT_UNSPEC;
    __builtin_memcpy(t.ipv6.saddr, &ip6->saddr, 16);
    __builtin_memcpy(t.ipv6.daddr, &ip6->daddr, 16);
    t.ipv6.sport = tcp->source;
    t.ipv6.dport = tcp->dest;
    size = sizeof(t.ipv6);
  } else
    return TC_ACT_UNSPEC;
  struct config *c = bpf_map_lookup_elem(&config, &z);
  struct download_config *d = bpf_map_lookup_elem(&download, &z);
  if (!c || !d || !d->ifindex)
    return TC_ACT_UNSPEC;
  // Local receiver lookup in the packet's namespace. Listeners, request/time-wait
  // minisocks and anything not ESTABLISHED are not download-bound receivers.
  struct bpf_sock *sk = bpf_sk_lookup_tcp(skb, &t, size, BPF_F_CURRENT_NETNS, 0);
  if (!sk) {
    count(6, skb);
    return TC_ACT_UNSPEC;
  }
  __u64 cookie = 0;
  if (sk->state == BPF_TCP_ESTABLISHED) {
    struct tcp_sock *tp = bpf_skc_to_tcp_sock(sk);
    if (tp)
      cookie = tp->inet_conn.icsk_inet.sk.__sk_common.skc_cookie.counter;
  }
  bpf_sk_release(sk);
  if (!cookie) {
    count(6, skb);
    return TC_ACT_UNSPEC;
  }
  __u64 now = bpf_ktime_get_ns();
  struct binding *b = bpf_map_lookup_elem(&bindings, &cookie);
  if (!b) {
    count(6, skb);
    return TC_ACT_UNSPEC;
  }
  if (!(c->until > now && b->until > now && b->download >= 1 && b->download <= 0xfffd && d->major)) {
    count(7, skb); // bound socket without current download class/lease: default path
    return TC_ACT_UNSPEC;
  }
  skb->priority = (d->major << 16) | b->download;
  idx = 5;
  count(idx, skb);
  return bpf_redirect(d->ifindex, 0);
}

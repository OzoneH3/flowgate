// Shared map layout of the egress (upload) and ingress (download) adapters.
// Both objects are linked into one classify.bpf.o so they use the SAME maps:
// one binding per socket cookie carries both class ids. NEVER a firewall source.
#ifndef FLOWGATE_SHAPING_BPF_H
#define FLOWGATE_SHAPING_BPF_H
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
struct binding {
  __u64 until;
  __u32 minor;    // NIC egress HTB class (upload) or 0
  __u32 download; // IFB HTB class (download) or 0
};
struct config {
  __u64 until;
  __u32 major; // egress HTB major
  __u32 flags; // bit0: upload budget active (host-local default marking)
};
struct download_config {
  __u32 major;   // IFB HTB major, 0 = download adapter withdrawn
  __u32 ifindex; // owned IFB ifindex, 0 = withdrawn
  __u32 flags;   // bit0: download budget active (host-local default redirect)
  __u32 reserved;
};
// Reserved class minors shared by both trees. Application classes are
// 1..FG_MAX_APP_MINOR; a packet can never select these through SO_PRIORITY
// because the classifiers clear the whole reserved major namespace first.
#define FG_MAX_APP_MINOR 0xffef
#define FG_BUDGET_MINOR 0xfff0
#define FG_BYPASS_MINOR 0xfff1
#define FG_DEFAULT_MINOR 0xfffe
#define FG_DL_BUDGET 1
#define FG_UL_BUDGET 1
struct counter {
  __u64 packets, bytes;
};
// Counter indices (measured evidence only; telemetry, never authority):
//  0 egress not app-classified, 1 egress app-classified, 2/3/4 egress
//  segmentation, 5 ingress app-redirected, 6 ingress TCP without a bound app
//  cookie (no lookup match or not established), 7 ingress binding without a
//  current download class/lease, 8 ingress aggregate default redirected,
//  9 ingress excluded from the download budget: unsupported packet format
//  (non-TCP/UDP IP, fragment, IPv6 extension header, VLAN, multicast/broadcast),
//  10 egress excluded from the upload budget: unsupported packet format,
//  11 egress config lease expired (bypass), 12 ingress excluded: no exact
//  connected local socket, 13 egress excluded: no exact connected local socket,
//  14 egress aggregate default marked, 17 egress expired binding.
//  8-14 are counted only while the respective budget is active (11 always).
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
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct download_config);
} download SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 18);
  __type(key, __u32);
  __type(value, struct counter);
} counters SEC(".maps");

// Shared packet parser. Fills a lookup tuple from the LOCAL socket's point of
// view: saddr/sport = remote peer, daddr/dport = local. Egress packets are
// therefore reversed. Fixed offsets only; no identity is inferred.
// Returns 0 for non-IP traffic and ICMPv6 (never shaped or counted), 2 for an
// unsupported IP format, 1 for parsed unicast-capable TCP/UDP.
struct fg_pkt {
  struct bpf_sock_tuple t;
  __u32 size;
  __u8 proto, unicast, v4, pad;
};
static __always_inline int fg_parse(struct __sk_buff *skb, struct fg_pkt *p, int egress) {
  void *data = (void *)(long)skb->data, *end = (void *)(long)skb->data_end;
  struct ethhdr *eth = data;
  void *l4;
  __be16 sport, dport;
  if ((void *)(eth + 1) > end)
    return 0;
  p->unicast = !(eth->h_dest[0] & 1) && !skb->vlan_present;
  if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > end || ip->version != 4 || ip->ihl < 5)
      return 2;
    p->proto = ip->protocol;
    if ((p->proto != IPPROTO_TCP && p->proto != IPPROTO_UDP) || (ip->frag_off & bpf_htons(0x3fff)))
      return 2;
    __be32 dst = egress ? ip->saddr : ip->daddr, src = egress ? ip->daddr : ip->saddr;
    __u32 other = bpf_ntohl(ip->daddr);
    if ((other >> 28) == 0xe || other == 0xffffffff)
      p->unicast = 0;
    p->t.ipv4.saddr = src;
    p->t.ipv4.daddr = dst;
    p->size = sizeof(p->t.ipv4);
    p->v4 = 1;
    l4 = (void *)ip + ip->ihl * 4;
  } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > end || ip6->version != 6)
      return 2;
    p->proto = ip6->nexthdr;
    if (p->proto == IPPROTO_ICMPV6)
      return 0;
    if (p->proto != IPPROTO_TCP && p->proto != IPPROTO_UDP)
      return 2; // extension headers and other protocols
    if (ip6->daddr.in6_u.u6_addr8[0] == 0xff)
      p->unicast = 0;
    if (egress) {
      __builtin_memcpy(p->t.ipv6.saddr, &ip6->daddr, 16);
      __builtin_memcpy(p->t.ipv6.daddr, &ip6->saddr, 16);
    } else {
      __builtin_memcpy(p->t.ipv6.saddr, &ip6->saddr, 16);
      __builtin_memcpy(p->t.ipv6.daddr, &ip6->daddr, 16);
    }
    p->size = sizeof(p->t.ipv6);
    p->v4 = 0;
    l4 = (void *)(ip6 + 1);
  } else
    return 0;
  struct udphdr *ports = l4; // ports share offsets in TCP and UDP
  if ((void *)(ports + 1) > end)
    return 2;
  if (p->proto == IPPROTO_TCP && l4 + sizeof(struct tcphdr) > end)
    return 2;
  sport = egress ? ports->dest : ports->source;
  dport = egress ? ports->source : ports->dest;
  if (p->v4) {
    p->t.ipv4.sport = sport;
    p->t.ipv4.dport = dport;
  } else {
    p->t.ipv6.sport = sport;
    p->t.ipv6.dport = dport;
  }
  return 1;
}

// Exact connected-socket evidence in the device namespace: the full 4-tuple of
// the returned socket equals the packet. Listener and wildcard/unconnected UDP
// lookup fallbacks never qualify (they do not establish local delivery).
static __always_inline int fg_exact(struct bpf_sock *sk, struct fg_pkt *p) {
  if (!sk->dst_port)
    return 0;
  if (p->v4)
    return sk->src_ip4 == p->t.ipv4.daddr && sk->dst_ip4 == p->t.ipv4.saddr &&
           sk->dst_port == p->t.ipv4.sport && sk->src_port == bpf_ntohs(p->t.ipv4.dport);
  return sk->src_ip6[0] == p->t.ipv6.daddr[0] && sk->src_ip6[1] == p->t.ipv6.daddr[1] &&
         sk->src_ip6[2] == p->t.ipv6.daddr[2] && sk->src_ip6[3] == p->t.ipv6.daddr[3] &&
         sk->dst_ip6[0] == p->t.ipv6.saddr[0] && sk->dst_ip6[1] == p->t.ipv6.saddr[1] &&
         sk->dst_ip6[2] == p->t.ipv6.saddr[2] && sk->dst_ip6[3] == p->t.ipv6.saddr[3] &&
         sk->dst_port == p->t.ipv6.sport && sk->src_port == bpf_ntohs(p->t.ipv6.dport);
}

static __always_inline int fg_count(__u32 idx, struct __sk_buff *skb) {
  struct counter *n = bpf_map_lookup_elem(&counters, &idx);
  if (n) {
    n->packets++;
    n->bytes += skb->len;
  }
  return 0;
}

#endif

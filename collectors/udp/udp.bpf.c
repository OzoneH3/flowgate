// SPDX-License-Identifier: GPL-2.0
// Own implementation. CO-RE uses the build host's BTF types, not fixed offsets.
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
struct udp_key {
  __u64 cookie;
};
struct udp_value {
  __u64 uploaded, downloaded;
};
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 2048);
  __type(key, struct udp_key);
  __type(value, struct udp_value);
} counters SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} misses SEC(".maps");
const volatile __u32 target_netns;
const volatile __u32 target_uid;
static __always_inline int account(struct sock *sk, int ret, int flags,
                                   int receive) {
  if (ret < 0 ||
      (receive && (flags & (2 /*MSG_PEEK*/ | 8192 /*MSG_ERRQUEUE*/))))
    return 0;
  if (BPF_CORE_READ(sk, sk_protocol) != 17)
    return 0;
  __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
  if (family != 2 && family != 10)
    return 0;
  if (BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum) != target_netns ||
      BPF_CORE_READ(sk, sk_uid.val) != target_uid)
    return 0;
  struct udp_key k = {.cookie =
                          BPF_CORE_READ(sk, __sk_common.skc_cookie.counter)};
  struct udp_value *v = bpf_map_lookup_elem(&counters, &k);
  if (!k.cookie || !v) {
    __u32 zero = 0;
    __u64 *lost = bpf_map_lookup_elem(&misses, &zero);
    if (lost)
      __sync_fetch_and_add(lost, 1);
    return 0;
  }
  if (receive)
    __sync_fetch_and_add(&v->downloaded, (__u64)ret);
  else
    __sync_fetch_and_add(&v->uploaded, (__u64)ret);
  return 0;
}
SEC("tp_btf/sock_send_length")
int BPF_PROG(sent, struct sock *sk, int ret, int flags) {
  return account(sk, ret, flags, 0);
}
SEC("tp_btf/sock_recv_length")
int BPF_PROG(received, struct sock *sk, int ret, int flags) {
  return account(sk, ret, flags, 1);
}
char LICENSE[] SEC("license") = "GPL";

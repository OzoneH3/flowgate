// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
struct initiation_value { __u64 observed_ns; __u32 direction; __u32 reserved; };
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,8192); __type(key,__u64); __type(value,struct initiation_value); } evidence SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,__u64); } losses SEC(".maps");
const volatile __u64 target_netns_cookie;
const volatile __u32 observe_shared;
static __always_inline void lost(void) { __u32 zero=0;__u64 *n=bpf_map_lookup_elem(&losses,&zero);if(n)__sync_fetch_and_add(n,1); }
SEC("sockops")
int fg_tcp_initiation(struct bpf_sock_ops *ops) {
 if (bpf_get_netns_cookie(ops)!=target_netns_cookie) {return 1;}
 __u32 op=ops->op;
 if(op==BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB||op==BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB){
  // Shared mode NEVER changes callback flags. Only record where another
  // program already requested close notifications; otherwise report loss/unknown.
  if(observe_shared && !(ops->bpf_sock_ops_cb_flags&BPF_SOCK_OPS_STATE_CB_FLAG)){lost();return 1;}
  __u64 cookie=bpf_get_socket_cookie(ops);
  struct initiation_value v={.observed_ns=bpf_ktime_get_ns(),.direction=op==BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB?1:2};
  struct initiation_value *old=bpf_map_lookup_elem(&evidence,&cookie);
  if(old&&old->direction!=v.direction)v.direction=3;
  if(!cookie||bpf_map_update_elem(&evidence,&cookie,&v,BPF_ANY))lost();
  // Only request lifecycle notifications; no packet, sockopt, routing or timer mutation.
  if(!observe_shared && bpf_sock_ops_cb_flags_set(ops,ops->bpf_sock_ops_cb_flags|BPF_SOCK_OPS_STATE_CB_FLAG))lost();
 } else if(op==BPF_SOCK_OPS_STATE_CB && ops->args[1]==7 /*TCP_CLOSE*/){
  __u64 cookie=bpf_get_socket_cookie(ops);bpf_map_delete_elem(&evidence,&cookie);
 }
 // Never write reply/tuning fields, including replies from another program.
 return 1;
}
char LICENSE[] SEC("license")="GPL";

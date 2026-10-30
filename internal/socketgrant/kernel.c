//go:build socketprototype

// Isolated build only. The lab creates its queue chain BEFORE calling fg_open.
#include "kernel.h"
#include "owned_rule.h"
#include "../../.workspace/socket-auth/gate.skel.h"
#include <bpf/bpf.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/xt_bpf.h>
#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>
#include <stdlib.h>
#include <sys/socket.h>

struct fg_gate { struct gate_bpf *b; struct fg_owned_rule owned; int closing, ready; };
static int install(struct fg_gate *g,int fd) {
  struct nftnl_rule *r=nftnl_rule_alloc();
  if (!r) return -ENOMEM;
  int result=-ENOMEM;
  nftnl_rule_set_u32(r,NFTNL_RULE_FAMILY,NFPROTO_INET);
  nftnl_rule_set_str(r,NFTNL_RULE_TABLE,"flowgate_lab");
  nftnl_rule_set_str(r,NFTNL_RULE_CHAIN,"gate");
  nftnl_rule_set_u32(r,NFTNL_RULE_COMPAT_PROTO,0);
  nftnl_rule_set_u32(r,NFTNL_RULE_COMPAT_FLAGS,0);
  struct xt_bpf_info_v1 *info=calloc(1,sizeof(*info));
  if (!info) goto out;
  info->mode=XT_BPF_MODE_FD_ELF; info->fd=fd;
  struct nftnl_expr *e=nftnl_expr_alloc("match");
  if (!e) {free(info);goto out;}
  nftnl_expr_set_str(e,NFTNL_EXPR_MT_NAME,"bpf");
  nftnl_expr_set_u32(e,NFTNL_EXPR_MT_REV,1);
  if(nftnl_expr_set(e,NFTNL_EXPR_MT_INFO,info,sizeof(*info))<0) {
    free(info);nftnl_expr_free(e);goto out;
  }
  nftnl_rule_add_expr(r,e);
  e=nftnl_expr_alloc("immediate"); if(!e)goto out;
  nftnl_expr_set_u32(e,NFTNL_EXPR_IMM_DREG,NFT_REG_VERDICT);
  nftnl_expr_set_u32(e,NFTNL_EXPR_IMM_VERDICT,NF_ACCEPT);
  nftnl_rule_add_expr(r,e);
  // No APPEND: the caller supplies an owned gate chain before the queue.
  result=fg_rule_insert(&g->owned,r);
out:
  nftnl_rule_free(r);
  return result;
}
struct fg_gate *fg_open(int *error) {
  *error=0;
  struct fg_gate *g=calloc(1,sizeof(*g));if(!g){*error=-ENOMEM;return NULL;}
  g->b=gate_bpf__open_and_load();if(!g->b){*error=errno?-errno:-EIO;free(g);return NULL;}
  int result=fg_rule_identity(&g->owned,"flowgate_lab","gate");
  if(result){gate_bpf__destroy(g->b);free(g);*error=result;return NULL;}
  result=install(g,bpf_program__fd(g->b->progs.socket_gate));
  if(result){
    // Even a lost ACK may have installed the rule. Return the tagged owner for
    // retryable cleanup; no authorization can be written through this object.
    g->closing=1;*error=result;return g;
  }
  g->ready=1;return g;
}
int fg_epoch(struct fg_gate *g,uint64_t value) {
  if(value && (!g->ready || g->closing))return -ESHUTDOWN;
  uint32_t zero=0;
  return bpf_map_update_elem(bpf_map__fd(g->b->maps.epoch),&zero,&value,BPF_ANY)?-errno:0;
}
int fg_put(struct fg_gate *g,void *key,void *value) {
  if(!g->ready || g->closing)return -ESHUTDOWN;
  uint64_t empty[3]={0};
  if(bpf_map_update_elem(bpf_map__fd(g->b->maps.hit_stats),key,empty,BPF_NOEXIST) && errno!=EEXIST)return -errno;
  return bpf_map_update_elem(bpf_map__fd(g->b->maps.grants),key,value,BPF_ANY)?-errno:0;
}
int fg_delete(struct fg_gate *g,void *key) {
  if(bpf_map_delete_elem(bpf_map__fd(g->b->maps.grants),key) && errno!=ENOENT)return -errno;
  if(bpf_map_delete_elem(bpf_map__fd(g->b->maps.hit_stats),key) && errno!=ENOENT)return -errno;
  return 0;
}
int fg_stats(struct fg_gate *g,void *key,void *out) {
  return bpf_map_lookup_elem(bpf_map__fd(g->b->maps.hit_stats),key,out)?-errno:0;
}
int fg_totals(struct fg_gate *g,void *out) {
  uint32_t zero=0;return bpf_map_lookup_elem(bpf_map__fd(g->b->maps.totals),&zero,out)?-errno:0;
}
int fg_close(struct fg_gate *g) {
  if(!g)return 0;
  g->closing=1;
  int result=fg_epoch(g,0);if(result)return result;
  result=fg_rule_remove(&g->owned);if(result)return result;
  gate_bpf__destroy(g->b);free(g);return 0;
}

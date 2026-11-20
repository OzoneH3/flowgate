//go:build socketprototype

// The caller must own the target regular chain and place its jump at the
// original UDP admission point. No host hook or chain is created here.
#include <arpa/inet.h>
#include "route_kernel.h"
#include "owned_rule.h"
#include "bpf/gate.h"
#include "../../build/socket-route-build/route_gate.skel.h"
#include <bpf/bpf.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/xt_bpf.h>
#include <libnftnl/expr.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#define FG_ROUTE_INTERFACES 32
struct fg_route_instance {
 uint32_t ifindex;
 struct route_gate_bpf *b;
 struct fg_owned_rule rule;
 int ready;
};
struct fg_route_gate {
 struct route_gate_bpf *base;
 char table[64],chain[64];
 struct fg_route_instance instances[FG_ROUTE_INTERFACES];
 unsigned count;
 int closing;
};
static int install_route(struct fg_route_instance *instance) {
 struct nftnl_rule *r=nftnl_rule_alloc();if(!r)return -ENOMEM;
 int result=-ENOMEM;
 nftnl_rule_set_u32(r,NFTNL_RULE_FAMILY,NFPROTO_INET);
 if(nftnl_rule_set_str(r,NFTNL_RULE_TABLE,instance->rule.table)<0 || nftnl_rule_set_str(r,NFTNL_RULE_CHAIN,instance->rule.chain)<0)goto out;
 nftnl_rule_set_u32(r,NFTNL_RULE_COMPAT_PROTO,0);
 nftnl_rule_set_u32(r,NFTNL_RULE_COMPAT_FLAGS,0);
 struct nftnl_expr *e=nftnl_expr_alloc("meta");if(!e)goto out;
 nftnl_expr_set_u32(e,NFTNL_EXPR_META_KEY,NFT_META_OIF);
 nftnl_expr_set_u32(e,NFTNL_EXPR_META_DREG,NFT_REG_1);nftnl_rule_add_expr(r,e);
 e=nftnl_expr_alloc("cmp");if(!e)goto out;
 nftnl_expr_set_u32(e,NFTNL_EXPR_CMP_SREG,NFT_REG_1);
 nftnl_expr_set_u32(e,NFTNL_EXPR_CMP_OP,NFT_CMP_EQ);
 if(nftnl_expr_set(e,NFTNL_EXPR_CMP_DATA,&instance->ifindex,sizeof(instance->ifindex))<0){nftnl_expr_free(e);goto out;}
 nftnl_rule_add_expr(r,e);
 struct xt_bpf_info_v1 *info=calloc(1,sizeof(*info));if(!info)goto out;
 info->mode=XT_BPF_MODE_FD_ELF;info->fd=bpf_program__fd(instance->b->progs.socket_gate);
 e=nftnl_expr_alloc("match");if(!e){free(info);goto out;}
 nftnl_expr_set_str(e,NFTNL_EXPR_MT_NAME,"bpf");nftnl_expr_set_u32(e,NFTNL_EXPR_MT_REV,1);
 if(nftnl_expr_set(e,NFTNL_EXPR_MT_INFO,info,sizeof(*info))<0){free(info);nftnl_expr_free(e);goto out;}
 nftnl_rule_add_expr(r,e);
 e=nftnl_expr_alloc("immediate");if(!e)goto out;
 nftnl_expr_set_u32(e,NFTNL_EXPR_IMM_DREG,NFT_REG_VERDICT);
 nftnl_expr_set_u32(e,NFTNL_EXPR_IMM_VERDICT,NF_ACCEPT);nftnl_rule_add_expr(r,e);
 result=fg_rule_insert(&instance->rule,r);
out:
 nftnl_rule_free(r);return result;
}
struct fg_route_gate *fg_route_open(const char *table,const char *chain,int *error) {
 *error=-EINVAL;
 if(!table || !chain || !*table || !*chain || strlen(table)>=64 || strlen(chain)>=64)return NULL;
 struct fg_route_gate *g=calloc(1,sizeof(*g));if(!g){*error=-ENOMEM;return NULL;}
 strcpy(g->table,table);strcpy(g->chain,chain);
 // Base program has constant zero: it can never match and is never attached.
 // Grants and statistics are shared. Each interface keeps its OWN epoch
 // so retiring one link cannot revoke unrelated links.
 g->base=route_gate_bpf__open_and_load();
 if(!g->base){*error=errno?-errno:-EIO;free(g);return NULL;}
 *error=0;return g;
}
int fg_route_add(struct fg_route_gate *g,uint32_t ifindex) {
 if(g->closing)return -ESHUTDOWN;
 if(!ifindex)return -EINVAL;
 for(unsigned i=0;i<g->count;i++)if(g->instances[i].ifindex==ifindex)return g->instances[i].ready?0:-ESHUTDOWN;
 if(g->count==FG_ROUTE_INTERFACES)return -ENOSPC;
 struct fg_route_instance *instance=&g->instances[g->count];
 int result=fg_rule_identity(&instance->rule,g->table,g->chain);if(result)return result;
 instance->b=route_gate_bpf__open();if(!instance->b)return errno?-errno:-ENOMEM;
 instance->ifindex=ifindex;instance->b->rodata->output_ifindex=ifindex;
 #define REUSE(name) do {result=bpf_map__reuse_fd(instance->b->maps.name,bpf_map__fd(g->base->maps.name));if(result)goto failed_load;} while(0)
 REUSE(grants);REUSE(hit_stats);REUSE(totals);
 #undef REUSE
 result=route_gate_bpf__load(instance->b);if(result)goto failed_load;
 // From this point a failed ACK may leave a rule; retain the complete owner.
 g->count++;
 result=install_route(instance);
 if(result){g->closing=1;fg_route_epoch(g,0);return result;}
 instance->ready=1;return 0;
failed_load:
 route_gate_bpf__destroy(instance->b);memset(instance,0,sizeof(*instance));return result;
}
int fg_route_epoch(struct fg_route_gate *g,uint64_t value) {
 if(value && g->closing)return -ESHUTDOWN;
 uint32_t zero=0;
 if(bpf_map_update_elem(bpf_map__fd(g->base->maps.epoch),&zero,&value,BPF_ANY))return -errno;
 for(unsigned i=0;i<g->count;i++) {
  uint64_t next=g->instances[i].ready?value:0;
  if(bpf_map_update_elem(bpf_map__fd(g->instances[i].b->maps.epoch),&zero,&next,BPF_ANY))return -errno;
 }
 return 0;
}
int fg_route_retire(struct fg_route_gate *g,uint32_t ifindex) {
 if(g->closing)return -ESHUTDOWN;
 for(unsigned i=0;i<g->count;i++)if(g->instances[i].ifindex==ifindex) {
  uint32_t zero=0;uint64_t disabled=0;
  if(bpf_map_update_elem(bpf_map__fd(g->instances[i].b->maps.epoch),&zero,&disabled,BPF_ANY))return -errno;
  // Never re-enable this numeric index in this session, even after reuse.
  g->instances[i].ready=0;return 0;
 }
 return -ENODEV;
}
int fg_route_put(struct fg_route_gate *g,void *raw,void *value) {
 if(g->closing)return -ESHUTDOWN;
 struct gate_key *key=raw;int ready=0;
 for(unsigned i=0;i<g->count;i++)if(g->instances[i].ifindex==key->ifindex && g->instances[i].ready){ready=1;break;}
 if(!ready)return -ENODEV;
 struct gate_stats empty={0};
 if(bpf_map_update_elem(bpf_map__fd(g->base->maps.hit_stats),key,&empty,BPF_NOEXIST) && errno!=EEXIST)return -errno;
 return bpf_map_update_elem(bpf_map__fd(g->base->maps.grants),key,value,BPF_ANY)?-errno:0;
}
int fg_route_delete(struct fg_route_gate *g,void *key) {
 if(bpf_map_delete_elem(bpf_map__fd(g->base->maps.grants),key) && errno!=ENOENT)return -errno;
 if(bpf_map_delete_elem(bpf_map__fd(g->base->maps.hit_stats),key) && errno!=ENOENT)return -errno;
 return 0;
}
int fg_route_stats(struct fg_route_gate *g,void *key,void *out) {return bpf_map_lookup_elem(bpf_map__fd(g->base->maps.hit_stats),key,out)?-errno:0;}
int fg_route_totals(struct fg_route_gate *g,void *out) {uint32_t zero=0;return bpf_map_lookup_elem(bpf_map__fd(g->base->maps.totals),&zero,out)?-errno:0;}
int fg_route_close(struct fg_route_gate *g) {
 if(!g)return 0;
 g->closing=1;int result=fg_route_epoch(g,0);if(result)return result;
 for(unsigned i=0;i<g->count;i++){result=fg_rule_remove(&g->instances[i].rule);if(result)return result;}
 for(unsigned i=0;i<g->count;i++)route_gate_bpf__destroy(g->instances[i].b);
 route_gate_bpf__destroy(g->base);free(g);return 0;
}
int fg_route_release_removed(struct fg_route_gate *g) {
 if(!g)return 0;
 g->closing=1;
 // Independently confirm every exact owned rule is absent. Only then can
 // cleanup proceed without an epoch write (for example after map IO failure).
 for(unsigned i=0;i<g->count;i++) {
  int absent=fg_rule_absent(&g->instances[i].rule);
  if(absent<0)return absent;
  if(!absent)return -EBUSY;
 }
 for(unsigned i=0;i<g->count;i++)route_gate_bpf__destroy(g->instances[i].b);
 route_gate_bpf__destroy(g->base);free(g);return 0;
}

// Fatal map-write fallback: no grant can match after every owned rule is gone.
// Resources stay owned until normal verified table cleanup/release.
int fg_route_detach(struct fg_route_gate *g) {
 if(!g)return 0;
 g->closing=1;
 for(unsigned i=0;i<g->count;i++) {int result=fg_rule_remove(&g->instances[i].rule);if(result)return result;}
 return 0;
}

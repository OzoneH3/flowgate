//go:build socketprototype

// Exact, tagged rule ownership. This does not establish ownership of a table:
// the firewall-session caller must validate its target before creating a gate.
#include <arpa/inet.h>
#include "owned_rule.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <poll.h>
#include <time.h>
#include <sys/random.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <libmnl/libmnl.h>
#include <libnftnl/gen.h>
#include <libnftnl/udata.h>
#include <linux/netfilter/nfnetlink.h>
#include <sys/socket.h>

struct reply {
 struct fg_owned_rule *owned;
 uint64_t found;
 unsigned matches;
 int acknowledged, finished, generationRead;
 uint32_t generation;
};
static uint64_t milliseconds(void) {
 struct timespec ts;
 if(clock_gettime(CLOCK_BOOTTIME,&ts))return 0;
 return (uint64_t)ts.tv_sec*1000+ts.tv_nsec/1000000;
}
static int ack_cb(const struct nlmsghdr *h,void *data) {
 struct reply *r=data;
 if(h->nlmsg_len<NLMSG_LENGTH(sizeof(struct nlmsgerr))) {errno=EBADMSG;return MNL_CB_ERROR;}
 const struct nlmsgerr *err=mnl_nlmsg_get_payload(h);
 if(err->error) {errno=err->error<0?-err->error:err->error;return MNL_CB_ERROR;}
 r->acknowledged=1;return MNL_CB_OK;
}
static int overrun_cb(const struct nlmsghdr *h,void *data) { (void)h;(void)data;errno=ENOBUFS;return MNL_CB_ERROR;}
static int done_cb(const struct nlmsghdr *h,void *data) {
 struct reply *r=data;
 // Multipart dumps can end with an error instead of a valid complete snapshot.
 if(h->nlmsg_len>=NLMSG_LENGTH(sizeof(int))) {
  int result;memcpy(&result,mnl_nlmsg_get_payload(h),sizeof(result));
  if(result){errno=result<0?-result:result;return MNL_CB_ERROR;}
 }
 r->finished=1;return MNL_CB_OK;
}
static int rule_cb(const struct nlmsghdr *h,void *data) {
 struct reply *reply=data;struct fg_owned_rule *owned=reply->owned;
 if((h->nlmsg_type & 0xff)==NFT_MSG_NEWGEN) {
  struct nftnl_gen *gen=nftnl_gen_alloc();
  if(!gen){errno=ENOMEM;return MNL_CB_ERROR;}
  int parsed=nftnl_gen_nlmsg_parse(h,gen);
  if(parsed<0 || !nftnl_gen_is_set(gen,NFTNL_GEN_ID)) {
   nftnl_gen_free(gen);errno=EBADMSG;return MNL_CB_ERROR;
  }
  reply->generation=nftnl_gen_get_u32(gen,NFTNL_GEN_ID);
  reply->generationRead=1;nftnl_gen_free(gen);return MNL_CB_OK;
 }
 if(!owned || (h->nlmsg_type & 0xff)!=NFT_MSG_NEWRULE){errno=EBADMSG;return MNL_CB_ERROR;}
 struct nftnl_rule *r=nftnl_rule_alloc();
 if(!r){errno=ENOMEM;return MNL_CB_ERROR;}
 int result=MNL_CB_OK;
 if(nftnl_rule_nlmsg_parse(h,r)<0){result=MNL_CB_ERROR;goto out;}
 const char *table=nftnl_rule_get_str(r,NFTNL_RULE_TABLE);
 const char *chain=nftnl_rule_get_str(r,NFTNL_RULE_CHAIN);
 uint32_t length=0;
 const void *tag=nftnl_rule_get_data(r,NFTNL_RULE_USERDATA,&length);
 if(table && chain && !strcmp(table,owned->table) && !strcmp(chain,owned->chain) &&
    nftnl_rule_get_u32(r,NFTNL_RULE_FAMILY)==NFPROTO_INET &&
    tag && length==owned->tag_len && !memcmp(tag,owned->tag,length)) {
  uint64_t handle=nftnl_rule_get_u64(r,NFTNL_RULE_HANDLE);
  if(!handle || (owned->handle && owned->handle!=handle) || ++reply->matches>1) {
   errno=ESTALE;result=MNL_CB_ERROR;goto out;
  }
  reply->found=handle;
 }
out:
 nftnl_rule_free(r);return result;
}
// One absolute three-second exchange deadline, bounded reply bytes. A dump is
// accepted only with its terminating message; a mutation only with its ACK.
static int exchange(void *buf,size_t length,unsigned sequence,struct reply *reply,int dump) {
 struct mnl_socket *nl=mnl_socket_open(NETLINK_NETFILTER);
 if(!nl)return -errno;
 int result=0;
 if(mnl_socket_bind(nl,0,MNL_SOCKET_AUTOPID)<0){result=-errno;goto out;}
 struct timeval timeout={.tv_sec=3};
 if(setsockopt(mnl_socket_get_fd(nl),SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout))<0){result=-errno;goto out;}
 if(mnl_socket_sendto(nl,buf,length)!=(ssize_t)length){result=-errno;goto out;}
 uint64_t start=milliseconds();
 if(!start){result=-EIO;goto out;}
 uint64_t deadline=start+3000;
 size_t received=0;
 mnl_cb_t control[NLMSG_MIN_TYPE]={0};
 control[NLMSG_ERROR]=ack_cb;control[NLMSG_DONE]=done_cb;control[NLMSG_OVERRUN]=overrun_cb;
 while(dump ? !reply->finished : (!reply->acknowledged || (!reply->owned && !reply->generationRead))) {
  uint64_t now=milliseconds();
  if(!now || now>=deadline){result=-ETIMEDOUT;goto out;}
  struct pollfd pollfd={.fd=mnl_socket_get_fd(nl),.events=POLLIN};
  int ready=poll(&pollfd,1,(int)(deadline-now));
  if(ready<0 && errno==EINTR)continue;
  if(ready<=0){result=ready==0?-ETIMEDOUT:-errno;goto out;}
  char incoming[65536];
  int n=mnl_socket_recvfrom(nl,incoming,sizeof(incoming));
  if(n<=0){result=n==0?-EIO:-errno;goto out;}
  received+=(size_t)n;
  if(received>4*1024*1024){result=-E2BIG;goto out;}
  int remaining=n;
  for(struct nlmsghdr *h=(struct nlmsghdr *)incoming;mnl_nlmsg_ok(h,remaining);h=mnl_nlmsg_next(h,&remaining)) {
   // GENID rejection belongs to batch BEGIN (seq 1), not the rule (seq 2).
   // Accept only a validated error for that exact request; never treat its ACK
   // as proof that the rule operation succeeded.
   if(!dump && reply->owned && h->nlmsg_seq==1 && h->nlmsg_type==NLMSG_ERROR) {
    if(!mnl_nlmsg_portid_ok(h,mnl_socket_get_portid(nl)) || h->nlmsg_len<NLMSG_LENGTH(sizeof(struct nlmsgerr))) {result=-EBADMSG;goto out;}
    const struct nlmsgerr *error=mnl_nlmsg_get_payload(h);
    if(error->msg.nlmsg_seq!=1 || error->msg.nlmsg_type!=NFNL_MSG_BATCH_BEGIN || error->error>=0) {result=-EBADMSG;goto out;}
    result=error->error==-ERESTART ? -EAGAIN : error->error;
    goto out;
   }
   if(mnl_cb_run2(h,h->nlmsg_len,sequence,mnl_socket_get_portid(nl),rule_cb,reply,control,NLMSG_MIN_TYPE)<0) {
    result=-errno;goto out;
   }
  }
  if(remaining){result=-EBADMSG;goto out;}
 }
out:
 mnl_socket_close(nl);return result;
}
static int current_generation(uint32_t *generation) {
 char buf[8192];
 struct nlmsghdr *h=nftnl_nlmsg_build_hdr(buf,NFT_MSG_GETGEN,NFPROTO_INET,NLM_F_ACK,2);
 struct reply reply={0};
 int result=exchange(buf,h->nlmsg_len,2,&reply,0);
 if(result)return result;
 if(!reply.generationRead)return -EBADMSG;
 *generation=reply.generation;return 0;
}
int fg_rule_identity(struct fg_owned_rule *r,const char *table,const char *chain) {
 if(!r || !table || !chain || !*table || !*chain || strlen(table)>=sizeof(r->table) || strlen(chain)>=sizeof(r->chain))return -EINVAL;
 memset(r,0,sizeof(*r));strcpy(r->table,table);strcpy(r->chain,chain);
 unsigned char random[16];size_t n=0;
 while(n<sizeof(random)) {
  ssize_t got=getrandom(random+n,sizeof(random)-n,0);
  if(got<0 && errno==EINTR)continue;
  if(got<=0)return got==0?-EIO:-errno;
  n+=got;
 }
 char comment[64]="flowgate-socket:";
 size_t offset=strlen(comment);
 static const char hex[]="0123456789abcdef";
 for(n=0;n<sizeof(random);n++){comment[offset+2*n]=hex[random[n]>>4];comment[offset+2*n+1]=hex[random[n]&15];}
 comment[offset+2*n]=0;
 struct nftnl_udata_buf *userdata=nftnl_udata_buf_alloc(sizeof(r->tag));
 if(!userdata)return -ENOMEM;
 if(!nftnl_udata_put_strz(userdata,NFTNL_UDATA_RULE_COMMENT,comment)){nftnl_udata_buf_free(userdata);return -ENOMEM;}
 r->tag_len=nftnl_udata_buf_len(userdata);
 memcpy(r->tag,nftnl_udata_buf_data(userdata),r->tag_len);
 nftnl_udata_buf_free(userdata);
 return 0;
}
static struct nftnl_rule *target(struct fg_owned_rule *owned) {
 struct nftnl_rule *r=nftnl_rule_alloc();if(!r)return NULL;
 nftnl_rule_set_u32(r,NFTNL_RULE_FAMILY,NFPROTO_INET);
 if(nftnl_rule_set_str(r,NFTNL_RULE_TABLE,owned->table)<0 || nftnl_rule_set_str(r,NFTNL_RULE_CHAIN,owned->chain)<0){nftnl_rule_free(r);return NULL;}
 return r;
}
static int lookup(struct fg_owned_rule *owned,uint64_t *handle) {
 struct nftnl_rule *r=target(owned);if(!r)return -ENOMEM;
 char buf[8192];
 struct nlmsghdr *h=nftnl_nlmsg_build_hdr(buf,NFT_MSG_GETRULE,NFPROTO_INET,NLM_F_DUMP,2);
 nftnl_rule_nlmsg_build_payload(h,r);
 struct reply reply={.owned=owned};
 int result=exchange(buf,h->nlmsg_len,2,&reply,1);
 nftnl_rule_free(r);
 // A removed private chain/table has no remaining rule reference.
 if(result==-ENOENT){*handle=0;return 0;}
 if(!result)*handle=reply.found;
 return result;
}
int fg_rule_insert(struct fg_owned_rule *owned,struct nftnl_rule *r) {
 if(nftnl_rule_set_data(r,NFTNL_RULE_USERDATA,owned->tag,owned->tag_len)<0)return -ENOMEM;
 char buf[8192];unsigned off=0;
 struct nlmsghdr *h=nftnl_batch_begin(buf,1);off+=NLMSG_ALIGN(h->nlmsg_len);
 h=nftnl_nlmsg_build_hdr(buf+off,NFT_MSG_NEWRULE,NFPROTO_INET,NLM_F_CREATE|NLM_F_ACK|NLM_F_ECHO,2);
 nftnl_rule_nlmsg_build_payload(h,r);off+=NLMSG_ALIGN(h->nlmsg_len);
 h=nftnl_batch_end(buf+off,3);off+=NLMSG_ALIGN(h->nlmsg_len);
 struct reply reply={.owned=owned};
 int result=exchange(buf,off,2,&reply,0);
 if(reply.found)owned->handle=reply.found;
 // Also confirm after ACK: response ordering/loss must not turn an unknown
 // handle into a guessed deletion. A failed insert remains epoch0.
 if(!result) {
  uint64_t handle=0;result=lookup(owned,&handle);
  if(!result && !handle)result=-ENOENT;
  if(!result)owned->handle=handle;
 }
 return result;
}
static int remove_generation(struct fg_owned_rule *owned,uint32_t generation,uint64_t handle) {
 struct nftnl_rule *r=target(owned);if(!r)return -ENOMEM;
 nftnl_rule_set_u64(r,NFTNL_RULE_HANDLE,handle);
 char buf[8192];unsigned off=0;
 struct nlmsghdr *h=nftnl_batch_begin(buf,1);
 // Refuse if ANY ruleset mutation raced the tagged-ownership lookup.
 mnl_attr_put_u32(h,NFNL_BATCH_GENID,htonl(generation));
 off+=NLMSG_ALIGN(h->nlmsg_len);
 h=nftnl_nlmsg_build_hdr(buf+off,NFT_MSG_DELRULE,NFPROTO_INET,NLM_F_ACK,2);
 nftnl_rule_nlmsg_build_payload(h,r);off+=NLMSG_ALIGN(h->nlmsg_len);
 h=nftnl_batch_end(buf+off,3);off+=NLMSG_ALIGN(h->nlmsg_len);
 struct reply reply={.owned=owned};
 int result=exchange(buf,off,2,&reply,0);
 nftnl_rule_free(r);
 if(result==-ENOENT)result=0;
 if(!result)owned->handle=0;
 return result;
}
static int remove_once(struct fg_owned_rule *owned) {
 uint32_t generation=0;
 int result=current_generation(&generation);if(result)return result;
 uint64_t handle=0;result=lookup(owned,&handle);
 if(result || !handle)return result;
 return remove_generation(owned,generation,handle);
}
int fg_rule_remove(struct fg_owned_rule *owned) {
 // A concurrent editor is allowed to win. Re-read both generation and exact
 // ownership on each retry; never retry the old handle blindly.
 int result=-EAGAIN;
 for(unsigned attempt=0;attempt<3 && result==-EAGAIN;attempt++)result=remove_once(owned);
 return result;
}
int fg_rule_absent(struct fg_owned_rule *owned) {
 uint64_t handle=0;
 int result=lookup(owned,&handle);
 return result?result:(handle?0:1);
}

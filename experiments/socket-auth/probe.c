// SPDX-License-Identifier: GPL-2.0-only
// Mechanism-only test. Synthetic map grants are NOT identity acceptance.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/xt_bpf.h>
#include <libmnl/libmnl.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "gate.h"
#include "gate.skel.h"

static void must(int ok, const char *what) {
  if (!ok) { fprintf(stderr, "%s: %s\n", what, strerror(errno)); exit(1); }
}
static void isolated(void) {
  const char *names[] = {"pid", "net", "mnt"};
  for (unsigned i=0;i<3;i++) {
    char env[64], current[64]; struct stat a,b;
    snprintf(env,sizeof(env),"FG_PARENT_%s",names[i]);
    snprintf(current,sizeof(current),"/proc/self/ns/%s",names[i]);
    const char *p=getenv(env);
    must(p && stat(p,&a)==0 && stat(current,&b)==0 && a.st_ino!=b.st_ino,
         "requires private pid/net/mount namespaces");
  }
  must(getpid()==1, "requires private proc and namespace init");
}
static struct nftnl_rule *make_rule(int fd) {
  struct nftnl_rule *r=nftnl_rule_alloc(); must(r!=NULL,"allocate rule");
  nftnl_rule_set_u32(r,NFTNL_RULE_FAMILY,NFPROTO_IPV4);
  nftnl_rule_set_str(r,NFTNL_RULE_TABLE,"fg_socket_probe");
  nftnl_rule_set_str(r,NFTNL_RULE_CHAIN,"output");
  nftnl_rule_set_u32(r,NFTNL_RULE_COMPAT_PROTO,0);
  nftnl_rule_set_u32(r,NFTNL_RULE_COMPAT_FLAGS,0);
  // NFTNL_EXPR_MT_INFO takes ownership of this allocation; it does not copy.
  // nftnl_rule_free ultimately frees it through the match expression.
  struct xt_bpf_info_v1 *info=calloc(1,sizeof(*info)); must(info!=NULL,"match allocation");
  info->mode=XT_BPF_MODE_FD_ELF;
  info->fd=fd;
  struct nftnl_expr *e=nftnl_expr_alloc("match"); must(e!=NULL,"match expr");
  nftnl_expr_set_str(e,NFTNL_EXPR_MT_NAME,"bpf");
  nftnl_expr_set_u32(e,NFTNL_EXPR_MT_REV,1);
  // nft_compat requires XT_ALIGN(matchsize), including zeroed kernel pointer.
  must(nftnl_expr_set(e,NFTNL_EXPR_MT_INFO,info,sizeof(*info))==0,"match data");
  nftnl_rule_add_expr(r,e);
  e=nftnl_expr_alloc("immediate"); must(e!=NULL,"verdict expr");
  nftnl_expr_set_u32(e,NFTNL_EXPR_IMM_DREG,NFT_REG_VERDICT);
  nftnl_expr_set_u32(e,NFTNL_EXPR_IMM_VERDICT,NF_ACCEPT);
  nftnl_rule_add_expr(r,e);
  return r;
}
static void install(int fd) {
  struct nftnl_rule *r=make_rule(fd);
  char buf[8192]; unsigned off=0;
  struct nlmsghdr *h=nftnl_batch_begin(buf,1); off+=NLMSG_ALIGN(h->nlmsg_len);
  h=nftnl_nlmsg_build_hdr(buf+off,NFT_MSG_NEWRULE,NFPROTO_IPV4,
      NLM_F_CREATE|NLM_F_APPEND|NLM_F_ACK,2);
  nftnl_rule_nlmsg_build_payload(h,r); off+=NLMSG_ALIGN(h->nlmsg_len);
  h=nftnl_batch_end(buf+off,3); off+=NLMSG_ALIGN(h->nlmsg_len);
  struct mnl_socket *nl=mnl_socket_open(NETLINK_NETFILTER); must(nl!=NULL,"netlink open");
  must(mnl_socket_bind(nl,0,MNL_SOCKET_AUTOPID)==0,"netlink bind");
  struct timeval timeout={.tv_sec=3};
  must(setsockopt(mnl_socket_get_fd(nl),SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))==0,"netlink timeout");
  must(mnl_socket_sendto(nl,buf,off)==(int)off,"insert send");
  int n=mnl_socket_recvfrom(nl,buf,sizeof(buf)); must(n>0,"insert reply");
  must(mnl_cb_run(buf,n,2,mnl_socket_get_portid(nl),NULL,NULL)>=0,"insert acknowledgement");
  mnl_socket_close(nl); nftnl_rule_free(r);
}
static __u64 now(void) {
  struct timespec t; must(clock_gettime(CLOCK_BOOTTIME,&t)==0,"clock");
  return (__u64)t.tv_sec*1000000000+t.tv_nsec;
}
static int udp(struct sockaddr_in *a) {
  int s=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0); must(s>=0,"udp socket");
  *a=(struct sockaddr_in){.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
  must(bind(s,(void*)a,sizeof(*a))==0,"bind"); socklen_t n=sizeof(*a);
  must(getsockname(s,(void*)a,&n)==0,"getsockname"); return s;
}
static void delivery(int tx,int rx,struct sockaddr_in *dst,int expected,const char *label) {
  char x='x';
  ssize_t sent=sendto(tx,&x,1,0,(void*)dst,sizeof(*dst));
  int send_error=sent<0 ? errno : 0;
  // A LOCAL_OUT DROP may synchronously return EPERM to the sender. This is
  // expected only in negative cases; unrelated send failures never pass.
  must(sent==1 || (!expected && sent==-1 && send_error==EPERM),"send");
  struct pollfd p={.fd=rx,.events=POLLIN}; int ready=poll(&p,1,25);
  must(ready>=0,"poll"); must((ready>0)==expected,label);
  if (ready) must(recv(rx,&x,1,0)==1,"receive");
  printf("PASS %s send=%s delivered=%d\n",label,
         sent==1 ? "accepted" : "blocked-EPERM",ready>0); fflush(stdout);
}
int main(int argc, char **argv) {
  if (argc==2 && strcmp(argv[1],"--encoding-test")==0) {
    // No netlink socket, namespace, BPF load, or packet operations.
    for (unsigned i=0;i<100;i++) {
      struct nftnl_rule *r=make_rule(42);
      char buf[8192];
      struct nlmsghdr *h=nftnl_nlmsg_build_hdr(buf,NFT_MSG_NEWRULE,NFPROTO_IPV4,0,2);
      nftnl_rule_nlmsg_build_payload(h,r);
      must(h->nlmsg_len>NLMSG_HDRLEN && h->nlmsg_len<sizeof(buf),"encoded length");
      nftnl_rule_free(r);
    }
    puts("PASS 100 rule construction/encoding/destruction cycles; no kernel operations");
    return 0;
  }
  must(argc==1,"unexpected arguments");
  isolated();
  must(system("ip link set lo up")==0,"loopback up");
  struct gate_bpf *b=gate_bpf__open_and_load(); must(b!=NULL,"BPF load");
  must(system("nft 'add table ip fg_socket_probe; add chain ip fg_socket_probe output { type filter hook output priority 10; policy drop; }'")==0,"create private table");
  install(bpf_program__fd(b->progs.socket_gate));
  struct sockaddr_in src,a,z;
  int tx=udp(&src),rx=udp(&a),other=udp(&z);
  __u64 cookie=0; socklen_t size=sizeof(cookie);
  must(getsockopt(tx,SOL_SOCKET,SO_COOKIE,&cookie,&size)==0 && cookie,"SO_COOKIE");
  struct gate_key k={.cookie=cookie,.source=src.sin_addr.s_addr,.destination=a.sin_addr.s_addr,
    .source_port=src.sin_port,.destination_port=a.sin_port};
  __u32 zero=0; __u64 gen=1;
  must(bpf_map_update_elem(bpf_map__fd(b->maps.epoch),&zero,&gen,BPF_ANY)==0,"epoch");
  delivery(tx,rx,&a,0,"ungranted socket");
  struct gate_value v={.deadline_ns=now()+250000000,.generation=gen};
  must(bpf_map_update_elem(bpf_map__fd(b->maps.grants),&k,&v,BPF_NOEXIST)==0,"grant");
  delivery(tx,rx,&a,1,"exact cookie and destination");
  delivery(tx,other,&z,0,"same socket other destination");
  gen=2; must(bpf_map_update_elem(bpf_map__fd(b->maps.epoch),&zero,&gen,BPF_ANY)==0,"revoke epoch");
  delivery(tx,rx,&a,0,"policy generation revoked");
  v.generation=gen; v.deadline_ns=now()+250000000;
  must(bpf_map_update_elem(bpf_map__fd(b->maps.grants),&k,&v,BPF_EXIST)==0,"fresh grant");
  delivery(tx,rx,&a,1,"fresh authorization");
  // No userspace expiry action: leave the certificate in the map untouched.
  struct timespec delay={.tv_nsec=300000000}; nanosleep(&delay,NULL);
  delivery(tx,rx,&a,0,"kernel expiry with verifier idle");
  v.deadline_ns=now()+250000000;
  must(bpf_map_update_elem(bpf_map__fd(b->maps.grants),&k,&v,BPF_EXIST)==0,"replacement fixture grant");
  close(tx); tx=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0); must(tx>=0,"replacement");
  must(bind(tx,(void*)&src,sizeof(src))==0,"reuse local tuple");
  delivery(tx,rx,&a,0,"new socket same tuple");
  close(tx); close(rx); close(other);
  must(system("nft delete table ip fg_socket_probe")==0,"remove owned private table");
  gate_bpf__destroy(b);
  puts("PASS mechanism only; synthetic grants, no application identity or performance acceptance");
  return 0;
}

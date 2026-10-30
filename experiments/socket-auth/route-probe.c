// Synthetic exact-tuple route mechanism probe, not application authorization.
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "../../internal/socketgrant/route_kernel.c"
static void must(int ok,const char *name){if(!ok){fprintf(stderr,"FAIL %s errno=%d\n",name,errno);exit(1);}}
static __u64 boot(void){struct timespec t;must(!clock_gettime(CLOCK_BOOTTIME,&t),"clock");return (__u64)t.tv_sec*1000000000+t.tv_nsec;}
static void delivery(int tx,int rx,struct sockaddr_in *dst,int allowed,int raw){
 char data='X';int sent=sendto(tx,&data,1,0,(void*)dst,sizeof(*dst));
 must(sent==1 || (!allowed && sent==-1 && errno==EPERM),"send");
 struct pollfd p={.fd=rx,.events=POLLIN};int ready=poll(&p,1,20);must(ready>=0 && (ready>0)==allowed,"receiver");
 if(ready){char buf[2048];int n=recv(rx,buf,sizeof(buf),0);must(n>0 && (!raw || (n>=43 && buf[n-1]=='X')),"packet payload");}
}
static char *rules_json(void) {
 FILE *p=popen("nft -j list table inet flowgate_route_probe","r");must(p!=NULL,"nft JSON start");
 char *buf=calloc(1,65537);must(buf!=NULL,"dump buffer");
 size_t n=fread(buf,1,65536,p);must(n<65536 && !ferror(p),"bounded nft JSON");
 must(pclose(p)==0,"nft JSON supports xt_bpf");return buf;
}
static unsigned map_id(struct bpf_map *m){struct bpf_map_info i={0};unsigned n=sizeof(i);must(!bpf_obj_get_info_by_fd(bpf_map__fd(m),&i,&n),"map id");return i.id;}
int main(void){
 must(getpid()==1,"private namespace PID1");
 unsigned lo=if_nametoindex("lo"),out=if_nametoindex("fgv0"),peer=if_nametoindex("fgv1");must(lo&&out&&peer,"links");
 int error=0;struct fg_route_gate *g=fg_route_open("flowgate_route_probe","gate",&error);must(g&&!error,"open route gate");
 must(!fg_route_add(g,out) && !fg_route_add(g,lo),"install two guarded instances");
 must(map_id(g->base->maps.grants)==map_id(g->instances[0].b->maps.grants) && map_id(g->base->maps.grants)==map_id(g->instances[1].b->maps.grants),"shared grants");
 must(map_id(g->base->maps.epoch)==map_id(g->instances[0].b->maps.epoch) && map_id(g->base->maps.epoch)==map_id(g->instances[1].b->maps.epoch),"shared epoch");
 char *before=rules_json();
 int tx=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0),rx=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);must(tx>=0&&rx>=0,"udp sockets");
 struct sockaddr_in src={.sin_family=AF_INET},dst={.sin_family=AF_INET};inet_pton(AF_INET,"198.18.0.1",&src.sin_addr);inet_pton(AF_INET,"198.18.0.2",&dst.sin_addr);
 must(!bind(tx,(void*)&src,sizeof(src)),"sender bind");socklen_t n=sizeof(src);must(!getsockname(tx,(void*)&src,&n),"sender name");
 struct sockaddr_in any={.sin_family=AF_INET};must(!bind(rx,(void*)&any,sizeof(any)),"receiver bind");n=sizeof(any);must(!getsockname(rx,(void*)&any,&n),"receiver name");dst.sin_port=any.sin_port;
 int raw=socket(AF_PACKET,SOCK_RAW|SOCK_CLOEXEC,htons(ETH_P_IP));must(raw>=0,"packet receiver");
 struct sockaddr_ll address={.sll_family=AF_PACKET,.sll_protocol=htons(ETH_P_IP),.sll_ifindex=peer};must(!bind(raw,(void*)&address,sizeof(address)),"packet bind");
 struct gate_key key={.source=src.sin_addr.s_addr,.destination=dst.sin_addr.s_addr,.source_port=src.sin_port,.destination_port=dst.sin_port,.ifindex=out};n=sizeof(key.cookie);must(!getsockopt(tx,SOL_SOCKET,SO_COOKIE,&key.cookie,&n),"cookie");
 struct gate_value value={.generation=1,.deadline_ns=boot()+250000000};must(!fg_route_epoch(g,1)&&!fg_route_put(g,&key,&value),"grant output");
 delivery(tx,raw,&dst,1,1);
 must(!system("ip route add local 198.18.0.2/32 dev lo table local"),"move route");
 must(boot()<value.deadline_ns,"old grant still live before miss");delivery(tx,rx,&dst,0,0);must(boot()<value.deadline_ns,"miss not expiry");
 puts("PASS same socket/tuple moved from veth to lo cannot use live old-interface grant");
 key.ifindex=lo;value.deadline_ns=boot()+250000000;must(!fg_route_put(g,&key,&value),"grant new interface");delivery(tx,rx,&dst,1,0);
 must(!fg_route_epoch(g,2),"global revoke");delivery(tx,rx,&dst,0,0);
 puts("PASS fresh interface-specific grant works; one shared epoch revokes");
 char *after=rules_json();must(!strcmp(before,after),"audited JSON unchanged by traffic/map updates");free(before);free(after);
 puts("PASS xt_bpf JSON listing remains identical across traffic and epoch updates");
 // Bound is on instances even when the referenced interfaces have no traffic.
 for(unsigned i=2;i<32;i++)must(!fg_route_add(g,10000+i),"fill instance bound");
 must(fg_route_add(g,20000)==-ENOSPC,"33rd instance rejected");
 key.ifindex=20000;must(fg_route_put(g,&key,&value)==-ENODEV,"uninstalled interface cannot publish");
 must(!fg_route_close(g),"owned cleanup");close(tx);close(rx);close(raw);
 puts("PASS bounded instances; unsupported interface remains ungranted; cleanup");return 0;
}

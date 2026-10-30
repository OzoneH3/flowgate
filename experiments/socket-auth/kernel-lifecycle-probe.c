// Synthetic grants test resource lifetime only, not application identity.
#include <arpa/inet.h>
#include <errno.h>
#include <linux/types.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "gate.h"
#include "../../internal/socketgrant/kernel.c"
static void must(int ok,const char *label) {if(!ok){fprintf(stderr,"FAIL %s errno=%d\n",label,errno);exit(1);}}
static __u64 now(void) {struct timespec t;must(!clock_gettime(CLOCK_BOOTTIME,&t),"clock");return (__u64)t.tv_sec*1000000000+t.tv_nsec;}
static int udp(struct sockaddr_in *a) {
 int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);must(fd>=0,"socket");
 *a=(struct sockaddr_in){.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
 must(!bind(fd,(void*)a,sizeof(*a)),"bind");socklen_t n=sizeof(*a);must(!getsockname(fd,(void*)a,&n),"name");return fd;
}
static void delivery(int tx,int rx,struct sockaddr_in *dst,int expected) {
 char c='x';int rc=sendto(tx,&c,1,0,(void*)dst,sizeof(*dst));
 must(rc==1 || (!expected && rc==-1 && errno==EPERM),"send");
 struct pollfd p={.fd=rx,.events=POLLIN};rc=poll(&p,1,30);must(rc>=0 && (rc>0)==expected,"delivery");
 if(rc)must(recv(rx,&c,1,0)==1,"recv");
}
static unsigned program_id(struct fg_gate *g) {
 struct bpf_prog_info info={0};unsigned len=sizeof(info);
 must(!bpf_obj_get_info_by_fd(bpf_program__fd(g->b->progs.socket_gate),&info,&len),"program identity");return info.id;
}
static void gone(unsigned id) {
 for(unsigned i=0;i<40;i++) {
  int fd=bpf_prog_get_fd_by_id(id);
  if(fd<0){must(errno==ENOENT,"program lookup");return;}
  close(fd);struct timespec delay={.tv_nsec=50000000};nanosleep(&delay,NULL);
 }
 must(0,"program reference survives cleanup");
}
static struct fg_gate *open_gate(void) {int error=0;struct fg_gate *g=fg_open(&error);if(error)fprintf(stderr,"open error=%d\n",error);must(g && !error,"open gate");return g;}
static void grant(struct fg_gate *g,struct gate_key *key) {
 struct gate_value value={.deadline_ns=now()+250000000,.generation=1};
 must(!fg_epoch(g,1) && !fg_put(g,key,&value),"synthetic grant");
}
int main(void) {
 must(getpid()==1,"private PID init");
 must(!system("ip link set lo up"),"loopback");
 struct sockaddr_in src,dst;int tx=udp(&src),rx=udp(&dst);
 __u64 cookie=0;socklen_t n=sizeof(cookie);must(!getsockopt(tx,SOL_SOCKET,SO_COOKIE,&cookie,&n),"cookie");
 struct gate_key key={.cookie=cookie,.source=src.sin_addr.s_addr,.destination=dst.sin_addr.s_addr,.source_port=src.sin_port,.destination_port=dst.sin_port};
 struct fg_gate *g=open_gate();unsigned id=program_id(g);grant(g,&key);delivery(tx,rx,&dst,1);
 must(!fg_close(g),"close removes attached rule");gone(id);delivery(tx,rx,&dst,0);
 puts("PASS BPF-attached rule allows grant; Close removes permission and reference");fflush(stdout);
 int fds[2];must(!pipe(fds),"pipe");pid_t child=fork();must(child>=0,"fork");
 if(child==0){close(fds[0]);g=open_gate();grant(g,&key);id=program_id(g);must(write(fds[1],&id,sizeof(id))==sizeof(id),"ready");for(;;)pause();}
 close(fds[1]);must(read(fds[0],&id,sizeof(id))==sizeof(id),"child ready");close(fds[0]);
 delivery(tx,rx,&dst,1);must(!kill(child,SIGKILL),"kill verifier");int status;must(waitpid(child,&status,0)==child && WIFSIGNALED(status),"reap");
 struct timespec wait={.tv_nsec=300000000};while(nanosleep(&wait,&wait) && errno==EINTR){}
 delivery(tx,rx,&dst,0);
 puts("PASS SIGKILL cannot extend the kernel deadline");
 // The fixture owns this entire private chain. Production must separately
 // establish its protection-session ownership before this reconciliation.
 must(!system("nft flush chain inet flowgate_lab gate"),"reconcile private owned chain");gone(id);
 g=open_gate();id=program_id(g);grant(g,&key);delivery(tx,rx,&dst,1);must(!fg_close(g),"restart close");gone(id);delivery(tx,rx,&dst,0);
 puts("PASS new instance after owned-chain reconciliation; final closed gate blocks");
 close(tx);close(rx);return 0;
}

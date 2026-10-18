// SPDX-License-Identifier: MIT
#include "initiation.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/magic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/vfs.h>
#include <unistd.h>
const char flowgate_tcp_protocol[] __attribute__((used))="FLOWGATE_TCP_INITIATION_PROTOCOL=1";
struct value { uint64_t observed_ns;uint32_t direction,reserved; };
int main(int argc,char **argv){
 if(argc!=2||argv[1][0]!='/'){fprintf(stderr,"usage: tcp-initiation-collector ABSOLUTE_CGROUP_V2_PATH\n");return 2;}
 int ownership=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);struct sockaddr_un owner={.sun_family=AF_UNIX};const char *name="flowgate.tcp.initiation.v1";memcpy(owner.sun_path+1,name,strlen(name));
 if(ownership<0||bind(ownership,(struct sockaddr*)&owner,offsetof(struct sockaddr_un,sun_path)+1+strlen(name))){fprintf(stderr,"collector_conflict: existing initiation helper in this namespace\n");return 1;}
 int cg=open(argv[1],O_DIRECTORY|O_RDONLY|O_CLOEXEC|O_NOFOLLOW);struct statfs fs;
 if(cg<0||fstatfs(cg,&fs)||fs.f_type!=CGROUP2_SUPER_MAGIC){fprintf(stderr,"cgroup_unavailable: real cgroup-v2 directory required: %s\n",strerror(errno));return 1;}
 uint32_t ids[64],attach_flags=0,count=64;
 if(bpf_prog_query(cg,BPF_CGROUP_SOCK_OPS,BPF_F_QUERY_EFFECTIVE,&attach_flags,ids,&count)||count){fprintf(stderr,"sockops_conflict_or_unavailable: cannot exclusively observe cgroup with pre-existing effective sockops programs: %s\n",strerror(errno));close(cg);return 1;}
 int ns=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);uint64_t cookie=0;socklen_t len=sizeof(cookie);
 if(ns<0||getsockopt(ns,SOL_SOCKET,SO_NETNS_COOKIE,&cookie,&len)||!cookie){fprintf(stderr,"netns_cookie_unavailable: %s\n",strerror(errno));return 1;}close(ns);
 struct initiation_bpf *s=initiation_bpf__open();if(!s){fprintf(stderr,"BPF open failed\n");return 1;}
 s->rodata->target_netns_cookie=cookie;
 if(initiation_bpf__load(s)){fprintf(stderr,"initiation_load_failed: requires initial namespace BPF/network administration privileges and sockops helpers\n");initiation_bpf__destroy(s);return 1;}
 struct bpf_link *link=bpf_program__attach_cgroup(s->progs.fg_tcp_initiation,cg);
 if(!link){fprintf(stderr,"initiation_attach_failed: %s\n",strerror(errno));initiation_bpf__destroy(s);return 1;}
 close(cg);puts("READY");fflush(stdout);
 char line[65536];int fd=bpf_map__fd(s->maps.evidence),lossfd=bpf_map__fd(s->maps.losses);
 while(fgets(line,sizeof(line),stdin)){
  if(!strchr(line,'\n'))break;
  char *save=NULL;size_t n=0;int comma=0;printf("{\"rows\":[");
  for(char *v=strtok_r(line," \n",&save);v;v=strtok_r(NULL," \n",&save)){
   char *end;uint64_t key=strtoull(v,&end,10);if(*end||!key||++n>2048){fprintf(stderr,"invalid bounded cookie query\n");goto done;}
   struct value val={0};if(bpf_map_lookup_elem(fd,&key,&val)==0){printf("%s{\"cookie\":\"%016"PRIx64"\",\"direction\":%u,\"observed_ns\":%"PRIu64"}",comma?",":"",key,val.direction,val.observed_ns);comma=1;}
  }
  uint32_t zero=0;uint64_t loss=0;bpf_map_lookup_elem(lossfd,&zero,&loss);
  printf("],\"lost_events\":%"PRIu64"}\n",loss);fflush(stdout);
 }
 done:bpf_link__destroy(link);initiation_bpf__destroy(s);close(ownership);return 0;
}

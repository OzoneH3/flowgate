// SPDX-License-Identifier: MIT
// Load an unattached iterator and hand its FD to the launching daemon. There
// are no persistent maps, hooks, pins or background helper processes.
#include "fds.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
const char flowgate_fd_iterator_protocol[] __attribute__((used)) = "FLOWGATE_FD_ITERATOR=2";
int main(int argc, char **argv) {
  if(argc!=2 || strcmp(argv[1],"--send-program-fd"))return 2;
  struct fds_bpf *s=fds_bpf__open_and_load();
  if(!s)return 1;
  int fd=bpf_program__fd(s->progs.fds);
  char control[CMSG_SPACE(sizeof(fd))]={0};
  struct bpf_prog_info info={0};unsigned len=sizeof(info);
  if(bpf_obj_get_info_by_fd(fd,&info,&len) || info.type!=BPF_PROG_TYPE_TRACING || strcmp(info.name,"fds")) {
    fds_bpf__destroy(s);return 1;
  }
  // The trusted, pinned loader supplies the tag of its embedded, relocated
  // object. The receiver independently verifies the received FD's type/tag/name.
  unsigned char magic[13]="FGFI2";memcpy(magic+5,info.tag,8);
  struct iovec io={.iov_base=magic,.iov_len=sizeof(magic)};
  struct msghdr msg={.msg_iov=&io,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
  struct cmsghdr *c=CMSG_FIRSTHDR(&msg);
  c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(fd));
  memcpy(CMSG_DATA(c),&fd,sizeof(fd));
  int ok=sendmsg(3,&msg,MSG_NOSIGNAL)==(ssize_t)io.iov_len;
  fds_bpf__destroy(s);
  // Closing all loader FDs is safe: SCM_RIGHTS gives the daemon its own ref.
  return ok?0:1;
}

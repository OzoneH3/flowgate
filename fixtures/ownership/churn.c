// Deterministic descriptor-table membership churn for the holder census. No
// privileges, no traffic. Every change happens only when a command arrives on
// stdin, so a test can place it exactly between the census and the recheck.
//
// usage: churn 4|6 tcp|udp            holder: leader + one worker share the
//                                     table holding a bound socket; prints
//                                     "READY inode tgid worker"
//        churn recv PATH              receiver: listens on the Unix socket PATH,
//                                     spawns a receiving thread only on "recv";
//                                     prints "READY 0 tgid 0"
//        churn recv-pre PATH          receiver whose receiving thread already
//                                     exists before READY (no topology change
//                                     when it later receives); prints
//                                     "READY 0 tgid tid"
// commands (one per line, each acknowledged on stdout):
//   join        a new thread joins the shared table            -> "JOINED tid"
//   leave       the most recently joined thread exits           -> "LEFT tid"
//   unshare     a new thread unshares CLONE_FILES; its private   -> "UNSHARED tid"
//               copy of the table still holds the socket
//   send PATH   pass the socket via SCM_RIGHTS to the receiver  -> "SENT"
//   recv        (receiver) spawn the receiving thread           -> "SPAWNED tid"
//               the thread later prints "RECEIVED inode tid"
// stdin EOF ends the process and every thread.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

static int family, type, fd = -1, listener = -1;
static unsigned long inode;
struct rec {
  pthread_t t;
  long tid;
  int stop, unshared, receiver;
};
static struct rec recs[64];
static int nrecs;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static pthread_barrier_t started;

static void die(const char *what) {
  perror(what);
  _exit(1);
}
static unsigned long inode_of(int f) {
  struct stat st;
  if (fstat(f, &st))
    die("fstat");
  return (unsigned long)st.st_ino;
}
static void open_socket(void) {
  fd = socket(family == 4 ? AF_INET : AF_INET6, type, 0);
  struct sockaddr_storage a = {0};
  socklen_t len;
  if (family == 4) {
    struct sockaddr_in *v = (void *)&a;
    v->sin_family = AF_INET;
    v->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    len = sizeof(*v);
  } else {
    struct sockaddr_in6 *v = (void *)&a;
    v->sin6_family = AF_INET6;
    v->sin6_addr = in6addr_loopback;
    len = sizeof(*v);
  }
  if (fd < 0 || bind(fd, (void *)&a, len) ||
      (type == SOCK_STREAM && listen(fd, 4)))
    die("churn socket");
  inode = inode_of(fd);
}
static void park(struct rec *r) {
  pthread_mutex_lock(&mu);
  while (!r->stop)
    pthread_cond_wait(&cv, &mu);
  pthread_mutex_unlock(&mu);
}
static void *member(void *arg) {
  struct rec *r = arg;
  r->tid = syscall(SYS_gettid);
  if (r->unshared && unshare(CLONE_FILES))
    die("unshare");
  pthread_barrier_wait(&started);
  park(r);
  return NULL;
}
static void *receiver(void *arg) {
  struct rec *r = arg;
  r->tid = syscall(SYS_gettid);
  pthread_barrier_wait(&started);
  int c = accept(listener, NULL, NULL);
  if (c < 0)
    die("accept");
  char b;
  struct iovec io = {.iov_base = &b, .iov_len = 1};
  union {
    struct cmsghdr h;
    char buf[CMSG_SPACE(sizeof(int))];
  } u;
  struct msghdr m = {.msg_iov = &io, .msg_iovlen = 1, .msg_control = &u, .msg_controllen = sizeof(u)};
  if (recvmsg(c, &m, 0) < 1)
    die("recvmsg");
  struct cmsghdr *h = CMSG_FIRSTHDR(&m);
  if (!h || h->cmsg_level != SOL_SOCKET || h->cmsg_type != SCM_RIGHTS)
    die("no descriptor");
  int got;
  memcpy(&got, CMSG_DATA(h), sizeof(got));
  close(c);
  printf("RECEIVED %lu %ld\n", inode_of(got), r->tid);
  fflush(stdout);
  park(r); // keeps the received descriptor open
  return NULL;
}
static struct rec *spawn(int unshared, int recv) {
  if (nrecs == 64)
    die("too many threads");
  struct rec *r = &recs[nrecs++];
  memset(r, 0, sizeof(*r));
  r->unshared = unshared;
  r->receiver = recv;
  pthread_barrier_init(&started, NULL, 2);
  if (pthread_create(&r->t, NULL, recv ? receiver : member, r))
    die("pthread_create");
  pthread_barrier_wait(&started);
  pthread_barrier_destroy(&started);
  return r;
}
static void leave(void) {
  if (nrecs == 0)
    die("nothing to leave");
  struct rec *r = &recs[nrecs - 1];
  pthread_mutex_lock(&mu);
  r->stop = 1;
  pthread_cond_broadcast(&cv);
  pthread_mutex_unlock(&mu);
  pthread_join(r->t, NULL);
  nrecs--;
  printf("LEFT %ld\n", r->tid);
}
static struct sockaddr_un unix_address(const char *path) {
  struct sockaddr_un a = {.sun_family = AF_UNIX};
  if (strlen(path) >= sizeof(a.sun_path))
    die("unix path too long");
  memcpy(a.sun_path, path, strlen(path) + 1);
  return a;
}
static void send_fd(const char *path) {
  int u = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un a = unix_address(path);
  if (u < 0 || connect(u, (void *)&a, sizeof(a)))
    die("connect");
  char b = 'x';
  struct iovec io = {.iov_base = &b, .iov_len = 1};
  union {
    struct cmsghdr h;
    char buf[CMSG_SPACE(sizeof(int))];
  } cm;
  memset(&cm, 0, sizeof(cm));
  struct msghdr m = {.msg_iov = &io, .msg_iovlen = 1, .msg_control = &cm, .msg_controllen = sizeof(cm)};
  struct cmsghdr *h = CMSG_FIRSTHDR(&m);
  h->cmsg_level = SOL_SOCKET;
  h->cmsg_type = SCM_RIGHTS;
  h->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(h), &fd, sizeof(fd));
  if (sendmsg(u, &m, 0) != 1)
    die("sendmsg");
  close(u);
  printf("SENT\n");
}
int main(int argc, char **argv) {
  if (argc != 3)
    return 2;
  setvbuf(stdout, NULL, _IOLBF, 0);
  int recv_mode = !strcmp(argv[1], "recv") || !strcmp(argv[1], "recv-pre");
  long first = 0;
  if (recv_mode) {
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a = unix_address(argv[2]);
    unlink(argv[2]);
    if (listener < 0 || bind(listener, (void *)&a, sizeof(a)) || listen(listener, 1))
      die("unix listener");
    if (!strcmp(argv[1], "recv-pre"))
      first = spawn(0, 1)->tid;
  } else {
    family = atoi(argv[1]);
    type = strcmp(argv[2], "tcp") ? SOCK_DGRAM : SOCK_STREAM;
    open_socket();
    first = spawn(0, 0)->tid;
  }
  printf("READY %lu %d %ld\n", inode, getpid(), first);
  char line[256];
  while (fgets(line, sizeof(line), stdin)) {
    line[strcspn(line, "\n")] = 0;
    if (!strcmp(line, "join"))
      printf("JOINED %ld\n", spawn(0, 0)->tid);
    else if (!strcmp(line, "leave"))
      leave();
    else if (!strcmp(line, "unshare"))
      printf("UNSHARED %ld\n", spawn(1, 0)->tid);
    else if (!strncmp(line, "send ", 5))
      send_fd(line + 5);
    else if (!strcmp(line, "recv"))
      printf("SPAWNED %ld\n", spawn(0, 1)->tid);
    else
      die("unknown command");
  }
  _exit(0);
}

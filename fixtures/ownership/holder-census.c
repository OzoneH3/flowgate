// Descriptor-table topologies for the holder census. No privileges or traffic.
// usage: holder-census MODE 4|6 tcp|udp
//   control       live leader and two workers share one table holding the socket
//   exit-shared   leader pthread_exit; two workers share the table
//   exit-split    worker 0 unshares CLONE_FILES after the socket exists, then
//                 the leader exits: two tables (worker 0; worker 1) both hold it
//   private-live  worker 0 unshares, then opens the socket in its private table;
//                 the live leader's table (shared by worker 1) never holds it
// Prints "READY inode tgid worker0 worker1" and runs until stdin closes.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static const char *mode;
static int family, type;
static long tids[2];
static unsigned long inode;
static pthread_barrier_t ready;

static void die(const char *what) {
  perror(what);
  _exit(1);
}
static void open_socket(void) {
  int fd = socket(family == 4 ? AF_INET : AF_INET6, type, 0);
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
  struct stat st;
  if (fd < 0 || bind(fd, (void *)&a, len) ||
      (type == SOCK_STREAM && listen(fd, 4)) || fstat(fd, &st))
    die("holder-census socket");
  inode = (unsigned long)st.st_ino;
}
static void wait_stdin(void) {
  char b;
  while (read(0, &b, 1) > 0)
    ;
  _exit(0);
}
static void *worker(void *arg) {
  int i = (int)(long)arg;
  tids[i] = syscall(SYS_gettid);
  if (i == 0 && !strcmp(mode, "exit-split") && unshare(CLONE_FILES))
    die("unshare");
  if (i == 0 && !strcmp(mode, "private-live")) {
    if (unshare(CLONE_FILES))
      die("unshare");
    open_socket();
  }
  pthread_barrier_wait(&ready);
  if (i == 1 && !strncmp(mode, "exit-", 5))
    wait_stdin();
  for (;;)
    pause();
  return NULL;
}
int main(int argc, char **argv) {
  if (argc != 4)
    return 2;
  mode = argv[1];
  family = atoi(argv[2]);
  type = strcmp(argv[3], "tcp") ? SOCK_DGRAM : SOCK_STREAM;
  if (strcmp(mode, "private-live"))
    open_socket();
  pthread_barrier_init(&ready, NULL, 3);
  pthread_t t[2];
  for (long i = 0; i < 2; i++)
    if (pthread_create(&t[i], NULL, worker, (void *)i))
      die("pthread_create");
  pthread_barrier_wait(&ready);
  printf("READY %lu %d %ld %ld\n", inode, getpid(), tids[0], tids[1]);
  fflush(stdout);
  if (!strncmp(mode, "exit-", 5))
    pthread_exit(NULL);
  wait_stdin();
}

// A live native worker retains IPv4/IPv6 TCP/UDP sockets after pthread_exit
// terminates the thread-group leader. No privileges, packet hooks or metadata.
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
static void *worker(void *arg) {
  (void)arg;
  int ports[4];
  for (int i = 0; i < 4; i++) {
    int family = i % 2 ? AF_INET6 : AF_INET;
    int fd = socket(family, i < 2 ? SOCK_STREAM : SOCK_DGRAM, 0);
    struct sockaddr_storage a = {0};
    socklen_t len;
    if (family == AF_INET) {
      struct sockaddr_in *v = (void *)&a;
      v->sin_family = family;
      v->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      len = sizeof(*v);
    } else {
      struct sockaddr_in6 *v = (void *)&a;
      v->sin6_family = family;
      v->sin6_addr = in6addr_loopback;
      len = sizeof(*v);
    }
    if (fd < 0 || bind(fd, (void *)&a, len) || (i < 2 && listen(fd, 4)) ||
        getsockname(fd, (void *)&a, &len)) {
      perror("ownership fixture");
      _exit(1);
    }
    ports[i] =
        ntohs(family == AF_INET ? ((struct sockaddr_in *)&a)->sin_port
                                : ((struct sockaddr_in6 *)&a)->sin6_port);
  }
  printf("{\"pid\":%d,\"tid\":%ld,\"ports\":[%d,%d,%d,%d]}\n", getpid(),
         syscall(SYS_gettid), ports[0], ports[1], ports[2], ports[3]);
  fflush(stdout);
  while (1)
    pause();
  return NULL;
}
int main(void) {
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, NULL))
    return 1;
  pthread_exit(NULL);
}

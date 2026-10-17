// Native UDP accounting fixtures only; receiver data is checked, not logged.
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
static int family, fd[3], peers[32], child = -1, barrier = -1, reuseport;
static uint64_t up[3], down[3];
static void check(int ok) {
  if (!ok) {
    perror("UDP fixture");
    exit(2);
  }
}
static void addr(struct sockaddr_storage *ss, unsigned port, int any) {
  memset(ss, 0, sizeof(*ss));
  if (family == AF_INET) {
    struct sockaddr_in *a = (void *)ss;
    a->sin_family = family;
    a->sin_port = htons(port);
    inet_pton(family, any ? "0.0.0.0" : "127.0.0.1", &a->sin_addr);
  } else {
    struct sockaddr_in6 *a = (void *)ss;
    a->sin6_family = family;
    a->sin6_port = htons(port);
    a->sin6_addr = any ? in6addr_any : in6addr_loopback;
  }
}
static socklen_t size(void) {
  return family == AF_INET ? sizeof(struct sockaddr_in)
                           : sizeof(struct sockaddr_in6);
}
static unsigned port(int f) {
  struct sockaddr_storage a;
  socklen_t n = sizeof(a);
  check(getsockname(f, (void *)&a, &n) == 0);
  return ntohs(family == AF_INET ? ((struct sockaddr_in *)&a)->sin_port
                                 : ((struct sockaddr_in6 *)&a)->sin6_port);
}
static int make(unsigned p, int any, int reuse) {
  int f = socket(family, SOCK_DGRAM, 0);
  check(f >= 0);
  if (reuse) {
    int one = 1;
    check(setsockopt(f, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) == 0);
  }
  struct sockaddr_storage a;
  addr(&a, p, any);
  check(bind(f, (void *)&a, size()) == 0);
  struct timeval t = {2, 0};
  setsockopt(f, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));
  return f;
}
static void cookie(int f) {
  uint64_t v = 0;
  socklen_t n = sizeof(v);
  check(getsockopt(f, SOL_SOCKET, SO_COOKIE, &v, &n) == 0);
  unsigned char *p = (void *)&v;
  putchar('"');
  for (int i = 0; i < 8; i++)
    printf("%02x", p[i]);
  putchar('"');
}
static void state(const char *event) {
  printf("{\"event\":\"%s\",\"pid\":%d,\"child\":%d,\"ports\":[%u,%u,%u],"
         "\"cookies\":[",
         event, getpid(), child, port(fd[0]), port(fd[1]), port(fd[2]));
  for (int i = 0; i < 3; i++) {
    if (i)
      putchar(',');
    cookie(fd[i]);
  }
  printf("],\"uploaded\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64
         "],\"downloaded\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 "]",
         up[0], up[1], up[2], down[0], down[1], down[2]);
  if (reuseport) {
    printf(",\"peers\":[");
    for (int i = 0; i < 32; i++) {
      if (i)
        putchar(',');
      cookie(peers[i]);
    }
    putchar(']');
  }
  puts("}");
  fflush(stdout);
}
static void sendtofd(int from, int target, int bytes) {
  char data[65536];
  memset(data, 0x5a, sizeof(data));
  struct sockaddr_storage a;
  addr(&a, port(target), 0);
  check(sendto(from, data, bytes, 0, (void *)&a, size()) == bytes);
}
static void receive(int index, int bytes, int flags) {
  char data[65536];
  int n = recv(fd[index], data, bytes, flags);
  check(n >= 0);
  if (!(flags & MSG_PEEK))
    down[index] += n;
}
static void burst(int n) {
  for (int j = 0; j < n; j++) {
    struct sockaddr_storage a;
    addr(&a, port(fd[1]), 0);
    check(connect(fd[0], (void *)&a, size()) == 0);
    check(send(fd[0], "abcdefghijklmnopqrstuvwxyz", 26, 0) == 26);
    up[0] += 26;
    receive(1, 65536, 0);
    sendtofd(fd[1], fd[0], 800);
    up[1] += 800;
    receive(0, 65536, 0);
    sendtofd(fd[1], fd[2], 600);
    up[1] += 600;
    receive(2, 65536, 0);
  }
}
int main(int argc, char **argv) {
  check(argc >= 3);
  family = !strcmp(argv[1], "6") ? AF_INET6 : AF_INET;
  const char *mode = argv[2];
  if (!strcmp(mode, "holder")) {
    check(argc == 7);
    for (int i = 0; i < 3; i++)
      fd[i] = atoi(argv[3 + i]);
    char b;
    ssize_t n = read(atoi(argv[6]), &b, 1);
    // Parent teardown closes the barrier without handing off. EOF is expected.
    if (n == 0)
      return 0;
    check(n == 1);
    close(atoi(argv[6]));
    state("handoff");
  } else {
    reuseport = !strcmp(mode, "reuseport");
    fd[0] = make(0, 0, 0);
    fd[1] = make(0, 1, reuseport);
    fd[2] = make(reuseport ? port(fd[1]) : 0, reuseport, reuseport);
    if (reuseport)
      for (int i = 0; i < 32; i++)
        peers[i] = make(0, 0, 0);
    if (!strcmp(mode, "shared")) {
      check(argc == 4);
      int p[2];
      check(pipe(p) == 0);
      child = fork();
      check(child >= 0);
      if (child == 0) {
        close(p[1]);
        char a[4][24];
        for (int i = 0; i < 3; i++)
          snprintf(a[i], 24, "%d", fd[i]);
        snprintf(a[3], 24, "%d", p[0]);
        execl(argv[3], argv[3], argv[1], "holder", a[0], a[1], a[2], a[3],
              NULL);
        _exit(3);
      }
      close(p[0]);
      barrier = p[1];
    }
    state("ready");
  }
  char command[64];
  while (fgets(command, sizeof(command), stdin)) {
    if (!strncmp(command, "transfer", 8)) {
      burst(1);
      state("transfer");
    } else if (!strncmp(command, "burst", 5)) {
      burst(100);
      state("burst");
    } else if (!strncmp(command, "edges", 5)) {
      sendtofd(fd[1], fd[0], 100);
      up[1] += 100;
      receive(0, 10, MSG_PEEK);
      receive(0, 10, MSG_PEEK);
      receive(0, 10, 0);
      sendtofd(fd[1], fd[0], 100);
      up[1] += 100;
      receive(0, 10, MSG_TRUNC);
      char data[65536] = {0};
      check(send(fd[0], data, sizeof(data), 0) < 0);
      state("edges");
    } else if (!strncmp(command, "rebind", 6)) {
      unsigned old = port(fd[0]);
      close(fd[0]);
      fd[0] = make(old, 0, 0);
      up[0] = down[0] = 0;
      state("rebind");
    } else if (!strncmp(command, "reuse", 5)) {
      check(reuseport);
      for (int j = 0; j < 32; j++) {
        sendtofd(peers[j], fd[1], 200 + j);
        struct pollfd p[2] = {{fd[1], POLLIN, 0}, {fd[2], POLLIN, 0}};
        check(poll(p, 2, 2000) > 0);
        receive(p[0].revents & POLLIN ? 1 : 2, 65536, 0);
      }
      state("reuse");
    } else if (!strncmp(command, "handoff", 7)) {
      check(child > 0);
      check(write(barrier, "x", 1) == 1);
      return 0;
    } else if (!strncmp(command, "quit", 4))
      break;
  }
  if (child > 0) {
    kill(child, SIGTERM);
    waitpid(child, NULL, 0);
  }
  return 0;
}

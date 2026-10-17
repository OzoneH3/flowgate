// Controlled host loopback transfers. No firewall or privileged observation.
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
static void check(int ok) {
  if (!ok) {
    perror("fixture");
    exit(1);
  }
}
static int bind_socket(int family, int type) {
  int fd = socket(family, type, 0);
  check(fd >= 0);
  struct sockaddr_storage ss = {0};
  socklen_t len;
  if (family == AF_INET) {
    struct sockaddr_in *a = (void *)&ss;
    a->sin_family = family;
    inet_pton(AF_INET, "127.77.0.1", &a->sin_addr);
    len = sizeof(*a);
  } else {
    struct sockaddr_in6 *a = (void *)&ss;
    a->sin6_family = family;
    a->sin6_addr = in6addr_loopback;
    len = sizeof(*a);
  }
  check(bind(fd, (void *)&ss, len) == 0);
  return fd;
}
static unsigned port(int fd) {
  struct sockaddr_storage s;
  socklen_t n = sizeof(s);
  check(getsockname(fd, (void *)&s, &n) == 0);
  return ntohs(s.ss_family == AF_INET ? ((struct sockaddr_in *)&s)->sin_port
                                      : ((struct sockaddr_in6 *)&s)->sin6_port);
}
static void transfer(int from, int to, int bytes) {
  char data[16384] = {0};
  while (bytes) {
    int n = bytes > 16384 ? 16384 : bytes;
    check(send(from, data, n, MSG_NOSIGNAL) == n);
    int read = 0;
    while (read < n) {
      int got = recv(to, data, n - read, 0);
      check(got > 0);
      read += got;
    }
    bytes -= n;
  }
}
int main(int argc, char **argv) {
  int c[2], a[2], l[2], u[2];
  for (int i = 0; i < 2; i++) {
    int fam = i ? AF_INET6 : AF_INET;
    l[i] = bind_socket(fam, SOCK_STREAM);
    check(listen(l[i], 4) == 0);
    c[i] = bind_socket(fam, SOCK_STREAM);
    struct sockaddr_storage ss;
    socklen_t n = sizeof(ss);
    check(getsockname(l[i], (void *)&ss, &n) == 0);
    check(connect(c[i], (void *)&ss, n) == 0);
    a[i] = accept(l[i], NULL, NULL);
    check(a[i] >= 0);
    u[i] = bind_socket(fam, SOCK_DGRAM);
  }
  int child = -1;
  if (argc > 1 && !strcmp(argv[1], "shared")) {
    child = fork();
    check(child >= 0);
    if (!child) {
      while (1)
        pause();
    }
  }
  if (argc > 1 && !strcmp(argv[1], "hidden"))
    check(prctl(PR_SET_DUMPABLE, 0) == 0);
  printf("{\"pid\":%d,\"child\":%d,\"client4\":%u,\"server4\":%u,\"client6\":%"
         "u,\"server6\":%u,\"udp4\":%u,\"udp6\":%u}\n",
         getpid(), child, port(c[0]), port(a[0]), port(c[1]), port(a[1]),
         port(u[0]), port(u[1]));
  fflush(stdout);
  int command;
  while ((command = getchar()) != EOF) {
    if (command == 't') {
      for (int i = 0; i < 2; i++) {
        transfer(c[i], a[i], 262144);
        transfer(a[i], c[i], 131072);
      }
      puts("TRANSFERRED");
      fflush(stdout);
    }
    if (command == 'v') {
      check(prctl(PR_SET_DUMPABLE, 1) == 0);
      puts("VISIBLE");
      fflush(stdout);
    }
    if (command == 'c') {
      for (int i = 0; i < 2; i++) {
        close(c[i]);
        close(a[i]);
      }
      puts("CLOSED");
      fflush(stdout);
    }
  }
  if (child > 0) {
    kill(child, SIGTERM);
    waitpid(child, NULL, 0);
  }
  return 0;
}

// Native one-shot sender. Keep the actual socket alive while a decision waits.
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc != 5)
    return 2;
  int family = strchr(argv[1], '6') ? AF_INET6 : AF_INET;
  int tcp = !strncmp(argv[1], "tcp", 3);
  int fd = socket(family, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
  if (fd < 0)
    return 3;
  struct sockaddr_storage a = {0}, local = {0};
  socklen_t size;
  if (family == AF_INET) {
    struct sockaddr_in *s = (void *)&a, *l = (void *)&local;
    s->sin_family = l->sin_family = family;
    s->sin_port = htons(atoi(argv[3]));
    inet_pton(family, argv[2], &s->sin_addr);
    inet_pton(family, argv[4], &l->sin_addr);
    size = sizeof(*s);
  } else {
    struct sockaddr_in6 *s = (void *)&a, *l = (void *)&local;
    s->sin6_family = l->sin6_family = family;
    s->sin6_port = htons(atoi(argv[3]));
    inet_pton(family, argv[2], &s->sin6_addr);
    inet_pton(family, argv[4], &l->sin6_addr);
    size = sizeof(*s);
  }
  if (bind(fd, (void *)&local, size)) {
    perror("bind");
    return 4;
  }
  struct timeval timeout = {20, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  puts("READY");
  fflush(stdout);
  if (tcp) {
    if (connect(fd, (void *)&a, size)) {
      perror("connect");
      return 5;
    }
    if (send(fd, "fixture", 7, 0) != 7)
      return 6;
  } else {
    if (sendto(fd, "fixture", 7, 0, (void *)&a, size) != 7)
      return 7;
  }
  char b[16];
  if (recv(fd, b, sizeof(b), 0) > 0) {
    puts("REPLY");
    fflush(stdout);
  }
  if (tcp && getenv("FLOWGATE_CLIENT_REPEAT")) {
    if (getchar() == '+') {
      if (send(fd, "again", 5, 0) == 5 && recv(fd, b, sizeof(b), 0) > 0) {
        puts("REPLY2");
        fflush(stdout);
      }
    }
  }
  // Also permit a delayed test to change policy while the ownership stays
  // visible.
  sleep(2);
  close(fd);
  return 0;
}

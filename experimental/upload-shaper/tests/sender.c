#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static pid_t child = 0;
static int fds[8], nf = 0, fam = 4, stream = 0, connected = 1;
static struct sockaddr_storage dst;
static socklen_t dl;
static int dport = 43001;
static uint64_t ns(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}
static void dest(void) {
  memset(&dst, 0, sizeof(dst));
  if (fam == 4) {
    struct sockaddr_in *a = (void *)&dst;
    a->sin_family = AF_INET;
    a->sin_port = htons(dport);
    inet_pton(AF_INET, "10.79.0.2", &a->sin_addr);
    dl = sizeof(*a);
  } else {
    struct sockaddr_in6 *a = (void *)&dst;
    a->sin6_family = AF_INET6;
    a->sin6_port = htons(dport);
    inet_pton(AF_INET6, "fd79::2", &a->sin6_addr);
    dl = sizeof(*a);
  }
}
static void info(void) {
  printf("{\"pid\":%d,\"family\":%d,\"protocol\":\"%s\",\"sockets\":[",
         getpid(), fam, stream ? "tcp" : "udp");
  for (int i = 0; i < nf; i++) {
    struct sockaddr_storage a;
    socklen_t l = sizeof(a), cl = 8;
    uint64_t c = 0;
    struct stat st;
    fstat(fds[i], &st);
    getsockname(fds[i], (void *)&a, &l);
    getsockopt(fds[i], SOL_SOCKET, SO_COOKIE, &c, &cl);
    int port = fam == 4 ? ntohs(((struct sockaddr_in *)&a)->sin_port)
                        : ntohs(((struct sockaddr_in6 *)&a)->sin6_port);
    printf("%s{\"fd\":%d,\"port\":%d,\"inode\":%llu,\"cookie\":\"",
           i ? "," : "", fds[i], port, (unsigned long long)st.st_ino);
    for (int j = 0; j < 8; j++)
      printf("%02x", ((unsigned char *)&c)[j]);
    printf("\"}");
  }
  puts("]}");
}
static void drain(int millis) {
  if (millis < 1 || millis > 60000 || nf < 1) exit(2); // TCP or connected UDP
  struct pollfd ps[8];
  for (int i=0;i<nf;i++) ps[i]=(struct pollfd){.fd=fds[i],.events=POLLIN};
  uint64_t start=ns(), until=start+(uint64_t)millis*1000000, bytes=0;
  char buf[65536];
  while(ns()<until) {
    if(poll(ps,nf,10)<0 && errno!=EINTR) exit(2);
    for(int i=0;i<nf;i++) if(ps[i].revents&POLLIN) {
      ssize_t n=recv(fds[i],buf,sizeof(buf),MSG_DONTWAIT);
      if(n>0) bytes+=(uint64_t)n;
    }
  }
  printf("{\"bytes\":%llu,\"elapsed_ns\":%llu}\n",(unsigned long long)bytes,(unsigned long long)(ns()-start));
}
static void closeall(void) {
  for (int i = 0; i < nf; i++)
    close(fds[i]);
  nf = 0;
}
static void opens(int count, int localport) {
  closeall();
  dest();
  for (int i = 0; i < count && i < 8; i++) {
    int f = socket(fam == 4 ? AF_INET : AF_INET6,
                   stream ? SOCK_STREAM : SOCK_DGRAM, 0);
    struct timeval tv = {2, 0};
    setsockopt(f, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int buf = 8192;
    setsockopt(f, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    struct sockaddr_storage a = dst;
    if (fam == 4) {
      ((struct sockaddr_in *)&a)->sin_port = htons(localport);
      inet_pton(AF_INET, "10.79.0.1", &((struct sockaddr_in *)&a)->sin_addr);
    } else {
      ((struct sockaddr_in6 *)&a)->sin6_port = htons(localport);
      inet_pton(AF_INET6, "fd79::1", &((struct sockaddr_in6 *)&a)->sin6_addr);
    }
    if (f < 0 || bind(f, (void *)&a, dl) ||
        (connected && connect(f, (void *)&dst, dl))) {
      printf("{\"error\":%d}\n", errno);
      if (f >= 0)
        close(f);
      return;
    }
    fds[nf++] = f;
  }
  info();
}
static void sends(const char *tag, int count, int delay) {
  uint64_t begin = ns();
  int ok = 0, errors = 0;
  unsigned char b[1200] = {0};
  snprintf((char *)b, 16, "%.15s", tag);
  for (int i = 0;
       i < count && i < 4000 && nf > 0 && ns() - begin < 15000000000ULL; i++) {
    uint64_t seq = i, t = ns();
    memcpy(b + 16, &seq, 8);
    memcpy(b + 24, &t, 8);
    size_t off = 0;
    do {
      ssize_t n =
          connected ? send(fds[i % nf], b + off, sizeof(b) - off, MSG_NOSIGNAL)
                    : sendto(fds[i % nf], b, sizeof(b), MSG_NOSIGNAL,
                             (void *)&dst, dl);
      if (n <= 0) {
        errors++;
        break;
      }
      off += n;
    } while (stream && off < sizeof(b));
    if (off == sizeof(b))
      ok++;
    if (delay) {
      struct timespec pause = {delay / 1000000, (delay % 1000000) * 1000};
      nanosleep(&pause, 0);
    }
  }
  printf("{\"sent\":%d,\"errors\":%d,\"elapsed_ns\":%llu}\n", ok, errors,
         (unsigned long long)(ns() - begin));
}
#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
// Bulk for a bounded time with large messages. TCP: big writes let the stack
// build GSO/TSO superpackets (sized by autosizing). UDP with gso>0: explicit
// UDP_SEGMENT superpackets that the kernel segments after the qdisc. Payload
// starts with the tag; the receiver accounts by flow (source port).
static void bulk(const char *tag, int millis, int size, int gso) {
  static unsigned char b[65536];
  // UDP datagrams (including UDP_SEGMENT superpackets) are bounded by the IP
  // maximum payload; TCP writes may use the full buffer.
  if (size < 32 || size > (int)sizeof(b) || (!stream && size > 65507) || nf < 1) {
    puts("{\"error\":22}");
    return;
  }
  memset(b, 'b', size);
  snprintf((char *)b, 16, "%.15s", tag);
  int buf = 4 * 1024 * 1024;
  setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
  uint64_t begin = ns(), deadline = begin + (uint64_t)millis * 1000000ULL;
  uint64_t bytes = 0;
  int messages = 0, errors = 0, eagain = 0;
  while (ns() < deadline) {
    ssize_t n;
    if (!stream && gso > 0) {
      struct iovec io = {b, size};
      union {
        struct cmsghdr align;
        char bytes[CMSG_SPACE(sizeof(uint16_t))];
      } c = {0};
      struct msghdr m = {.msg_name = connected ? NULL : &dst,
                         .msg_namelen = connected ? 0 : dl,
                         .msg_iov = &io,
                         .msg_iovlen = 1,
                         .msg_control = &c,
                         .msg_controllen = sizeof(c)};
      struct cmsghdr *h = CMSG_FIRSTHDR(&m);
      h->cmsg_level = SOL_UDP;
      h->cmsg_type = UDP_SEGMENT;
      h->cmsg_len = CMSG_LEN(sizeof(uint16_t));
      uint16_t g = gso;
      memcpy(CMSG_DATA(h), &g, sizeof(g));
      n = sendmsg(fds[0], &m, MSG_NOSIGNAL);
    } else if (connected) {
      n = send(fds[0], b, size, MSG_NOSIGNAL);
    } else {
      n = sendto(fds[0], b, size, MSG_NOSIGNAL, (void *)&dst, dl);
    }
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        eagain++;
        struct timespec pause = {0, 2000000};
        nanosleep(&pause, 0);
        continue;
      }
      if (++errors > 64)
        break;
      continue;
    }
    bytes += n;
    messages++;
  }
  printf("{\"tag\":\"%s\",\"bytes\":%llu,\"messages\":%d,\"errors\":%d,"
         "\"timeouts\":%d,\"elapsed_ns\":%llu,\"gso\":%d}\n",
         tag, (unsigned long long)bytes, messages, errors, eagain,
         (unsigned long long)(ns() - begin), gso);
}
static void transfer(const char *path, int receive) {
  int u = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un a = {.sun_family = AF_UNIX};
  snprintf(a.sun_path, sizeof(a.sun_path), "%s", path);
  int s = u;
  if (receive) {
    unlink(path);
    if (bind(u, (void *)&a, sizeof(a)) || listen(u, 1)) {
      perror("bindunix");
      exit(2);
    }
    puts("{\"listening\":true}");
    s = accept(u, NULL, NULL);
  } else if (connect(u, (void *)&a, sizeof(a))) {
    perror("connectunix");
    exit(2);
  }
  char b = 'x';
  struct iovec io = {&b, 1};
  union {
    struct cmsghdr align;
    char bytes[CMSG_SPACE(sizeof(int))];
  } c = {0};
  struct msghdr m = {.msg_iov = &io,
                     .msg_iovlen = 1,
                     .msg_control = &c,
                     .msg_controllen = sizeof(c)};
  if (receive) {
    if (recvmsg(s, &m, 0) != 1)
      exit(2);
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    if (!h || h->cmsg_type != SCM_RIGHTS)
      exit(2);
    closeall();
    memcpy(&fds[0], CMSG_DATA(h), sizeof(int));
    nf = 1;
    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);
    getsockname(fds[0], (void *)&sa, &len);
    fam = sa.ss_family == AF_INET ? 4 : 6;
    int typ;
    socklen_t tl = sizeof(typ);
    getsockopt(fds[0], SOL_SOCKET, SO_TYPE, &typ, &tl);
    stream = typ == SOCK_STREAM;
    connected = 1;
    dest();
    info();
    close(s);
    unlink(path);
  } else {
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    h->cmsg_level = SOL_SOCKET;
    h->cmsg_type = SCM_RIGHTS;
    h->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(h), &fds[0], sizeof(int));
    if (sendmsg(s, &m, 0) != 1)
      exit(2);
    puts("{\"sent_fd\":true}");
  }
  close(u);
}
int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  if (argc == 7 && !strcmp(argv[1], "resume")) {
    fam = atoi(argv[2]);
    stream = atoi(argv[3]);
    connected = atoi(argv[4]);
    nf = atoi(argv[5]);
    char *p = argv[6];
    for (int i = 0; i < nf; i++) {
      fds[i] = strtol(p, &p, 10);
      if (*p == ',')
        p++;
    }
    dest();
  }
  info();
  char line[1024], tag[64], path[512];
  int n, delay, lp, dp, sz, gso;
  while (fgets(line, sizeof(line), stdin)) {
    if (sscanf(line, "OPEN %d %d %d %d %d %d", &fam, &stream, &n, &connected,
               &lp, &dp) == 6) {
      dport = dp;
      opens(n, lp);
    } else if (sscanf(line, "OPEN %d %d %d %d %d", &fam, &stream, &n,
                      &connected, &lp) == 5) {
      dport = 43001;
      opens(n, lp);
    } else if (sscanf(line, "DRAIN %d", &n) == 1)
      drain(n);
    else if (sscanf(line, "BULK %63s %d %d %d", tag, &n, &sz, &gso) == 4)
      bulk(tag, n, sz, gso);
    else if (sscanf(line, "SEND %63s %d %d", tag, &n, &delay) == 3)
      sends(tag, n, delay);
    else if (sscanf(line, "EXEC %511s", path) == 1) {
      char fa[16], st[16], co[16], cnt[16], fdstr[128] = "";
      snprintf(fa, 16, "%d", fam);
      snprintf(st, 16, "%d", stream);
      snprintf(co, 16, "%d", connected);
      snprintf(cnt, 16, "%d", nf);
      for (int i = 0; i < nf; i++) {
        char f[16];
        snprintf(f, 16, "%d,", fds[i]);
        strcat(fdstr, f);
      }
      execl(path, path, "resume", fa, st, co, cnt, fdstr, NULL);
      perror("exec");
      return 2;
    } else if (sscanf(line, "GIVE %511s", path) == 1)
      transfer(path, 0);
    else if (sscanf(line, "RECV %511s", path) == 1)
      transfer(path, 1);
    else if (sscanf(line, "PEER %d", &lp) == 1) {
      if (fam == 4)
        ((struct sockaddr_in *)&dst)->sin_port = htons(lp);
      else
        ((struct sockaddr_in6 *)&dst)->sin6_port = htons(lp);
      puts("{\"peer_changed\":true}");
    } else if (!strncmp(line, "FORK", 4)) {
      child = fork();
      if (child == 0) {
        for (;;)
          pause();
      }
      printf("{\"child\":%d}\n", child);
    } else if (!strncmp(line, "UNFORK", 6)) {
      if (child > 0) {
        kill(child, SIGTERM);
        waitpid(child, 0, 0);
        child = 0;
      }
      puts("{\"closed_child\":true}");
    } else if (!strncmp(line, "CLOSE", 5)) {
      closeall();
      info();
    } else if (!strncmp(line, "INFO", 4))
      info();
    else
      return 2;
  }
  closeall();
  return 0;
}

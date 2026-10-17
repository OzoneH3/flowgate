// One socket shared by either same-image fork or distinct-image exec.
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "child")) {
    while (1)
      pause();
  }
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in a = {.sin_family = AF_INET,
                          .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  socklen_t n = sizeof(a);
  if (fd < 0 || bind(fd, (void *)&a, n) || getsockname(fd, (void *)&a, &n))
    return 1;
  int pipefd[2];
  if (pipe(pipefd) || fcntl(pipefd[1], F_SETFD, FD_CLOEXEC))
    return 1;
  pid_t child = fork();
  if (child < 0)
    return 1;
  if (!child) {
    close(pipefd[0]);
    if (argc > 1) {
      execl(argv[1], argv[1], "child", NULL);
      _exit(2);
    }
    close(pipefd[1]);
    while (1)
      pause();
  }
  close(pipefd[1]);
  char b;
  read(pipefd[0], &b, 1);
  close(pipefd[0]);
  printf("{\"pid\":%d,\"child\":%d,\"port\":%d}\n", getpid(), child,
         ntohs(a.sin_port));
  fflush(stdout);
  // stdin EOF or 'q' triggers cleanup of this fixture's child only.
  getchar();
  kill(child, 15);
  waitpid(child, NULL, 0);
  close(fd);
  return 0;
}

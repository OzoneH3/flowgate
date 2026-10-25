/* Lab-only: exec another synthetic image while retaining the same UDP socket. */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int fd;
    if (!strncmp(argv[1], "fd=", 3)) fd = atoi(argv[1] + 3);
    else {
        int family = !strcmp(argv[1], "6") ? AF_INET6 : AF_INET;
        fd = socket(family, SOCK_DGRAM, 0);
        if (fd < 0) return 3;
        struct sockaddr_in a = {.sin_family = AF_INET};
        struct sockaddr_in6 b = {.sin6_family = AF_INET6};
        if (bind(fd, family == AF_INET ? (void *)&a : (void *)&b,
                 family == AF_INET ? sizeof a : sizeof b)) return 4;
    }
    struct sockaddr_storage addr;
    socklen_t n = sizeof addr;
    struct stat st;
    if (getsockname(fd, (void *)&addr, &n) || fstat(fd, &st)) return 5;
    unsigned port = ntohs(addr.ss_family == AF_INET ?
        ((struct sockaddr_in *)&addr)->sin_port : ((struct sockaddr_in6 *)&addr)->sin6_port);
    printf("READY %lu %d %u\n", (unsigned long)st.st_ino, getpid(), port);
    fflush(stdout);
    char line[4096];
    while (fgets(line, sizeof line, stdin)) {
        line[strcspn(line, "\n")] = 0;
        if (!strncmp(line, "EXEC ", 5)) {
            char arg[32];
            snprintf(arg, sizeof arg, "fd=%d", fd);
            execl(line + 5, line + 5, arg, (char *)NULL);
            return 6;
        }
        if (!strcmp(line, "QUIT")) break;
        return 7;
    }
    close(fd);
    return 0;
}

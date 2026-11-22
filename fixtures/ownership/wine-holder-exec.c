#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    int image = open(argv[0], O_RDONLY);
    if (image < 0 || mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE, image, 0) == MAP_FAILED) return 3;
    close(image);
    sigset_t waitset;
    sigemptyset(&waitset);
    sigaddset(&waitset, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &waitset, NULL) < 0) return 4;
    puts(argv[0]);
    fflush(stdout);
    if (argc == 3) {
        int signo;
        if (sigwait(&waitset, &signo) || setenv("WINEPREFIX", argv[2], 1)) return 5;
        execl("/proc/self/exe", argv[1], "replaced", (char *)NULL);
        return 6;
    }
    for (;;) pause();
}

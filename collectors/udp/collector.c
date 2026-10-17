// SPDX-License-Identifier: MIT
#include "udp.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <unistd.h>
const char flowgate_udp_helper_protocol[] __attribute__((used)) =
    "FLOWGATE_UDP_HELPER_PROTOCOL=1";
const char flowgate_udp_machine_protocol[] __attribute__((used)) = "FLOWGATE_UDP_MACHINE=1";
struct counter {
  uint64_t up, down;
};
static volatile sig_atomic_t stopped;
static void stop(int sig) {
  (void)sig;
  stopped = 1;
}
// Line protocol is private stdin/stdout to the owning Go collector only.
// Caller supplies the current bounded inet_diag cookie set; never
// FD/PID/tuples.
int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: udp-collector UID NETNS_INODE\n");
    return 2;
  }
  // Abstract AF_UNIX names are local to the current network namespace. Every
  // rebuilt prototype/daemon helper participates; no pins or filesystem locks.
  int ownership = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  struct sockaddr_un owner = {.sun_family = AF_UNIX};
  const char *name = "flowgate.udp.accounting.v1";
  memcpy(owner.sun_path + 1, name, strlen(name));
  if (ownership < 0 || bind(ownership, (struct sockaddr *)&owner,
      offsetof(struct sockaddr_un, sun_path) + 1 + strlen(name))) {
    fprintf(stderr, "collector_conflict: another collector owns this network namespace\n");
    if (ownership >= 0) close(ownership);
    return 1;
  }
  // Detect an already-loaded older pre-lock collector too. No programs removed.
  uint32_t id = 0;
  while (bpf_prog_get_next_id(id, &id) == 0) {
    int existing = bpf_prog_get_fd_by_id(id);
    if (existing < 0) {
      if (errno == ENOENT) continue; // Program disappeared during read-only inspection.
      fprintf(stderr, "collector_inspection_denied: cannot inspect existing tracing program: %s\n", strerror(errno));
      close(ownership); return 1;
    }
    struct bpf_prog_info info = {0}; uint32_t length = sizeof(info);
    if (bpf_obj_get_info_by_fd(existing, &info, &length)) {
      fprintf(stderr, "collector_inspection_denied: existing program info unavailable: %s\n", strerror(errno));
      close(existing); close(ownership); return 1;
    }
    int conflict = info.type == BPF_PROG_TYPE_TRACING &&
      (!strcmp(info.name, "sent") || !strcmp(info.name, "received"));
    close(existing);
    if (conflict) { fprintf(stderr, "collector_conflict: existing UDP-named tracing program; inspect ownership before starting\n"); close(ownership); return 1; }
  }
  if (errno != ENOENT) {
    fprintf(stderr, "collector_inspection_denied: cannot exclude an older tracing collector: %s\n", strerror(errno));
    close(ownership); return 1;
  }
  struct udp_bpf *s = udp_bpf__open();
  if (!s) {
    perror("BPF open");
    return 1;
  }
  s->rodata->target_all_uids = !strcmp(argv[1], "all");
  s->rodata->target_uid = s->rodata->target_all_uids ? 0 : strtoul(argv[1], NULL, 10);
  s->rodata->target_netns = strtoul(argv[2], NULL, 10);
  if (udp_bpf__load(s) || udp_bpf__attach(s)) {
    fprintf(stderr,
            "UDP accounting unavailable: BPF load/attach requires supported "
            "sock length tracepoints, BTF and initial-user-namespace "
            "CAP_BPF/CAP_PERFMON (or CAP_SYS_ADMIN).\n");
    udp_bpf__destroy(s);
    return 1;
  }
  signal(SIGTERM, stop);
  signal(SIGINT, stop);
  int fd = bpf_map__fd(s->maps.counters), lossfd = bpf_map__fd(s->maps.misses);
  puts("READY");
  fflush(stdout);
  char line[65536];
  uint64_t active[2048];
  size_t count = 0;
  while (!stopped && fgets(line, sizeof(line), stdin)) {
    uint64_t wanted[2048];
    size_t n = 0;
    char *save = NULL;
    for (char *v = strtok_r(line, " \n", &save); v;
         v = strtok_r(NULL, " \n", &save)) {
      if (n == 2048) {
        fprintf(stderr, "cookie capacity exceeded\n");
        stopped = 1;
        break;
      }
      char *end;
      uint64_t k = strtoull(v, &end, 10);
      if (*end || !k) {
        stopped = 1;
        break;
      }
      wanted[n++] = k;
    }
    if (stopped)
      break;
    for (size_t i = 0; i < count; i++) {
      int keep = 0;
      for (size_t j = 0; j < n; j++)
        if (active[i] == wanted[j])
          keep = 1;
      if (!keep)
        bpf_map_delete_elem(fd, &active[i]);
    }
    printf("{\"rows\":[");
    for (size_t i = 0; i < n; i++) {
      struct counter c = {0};
      int existed = bpf_map_lookup_elem(fd, &wanted[i], &c) == 0;
      if (!existed && bpf_map_update_elem(fd, &wanted[i], &c, BPF_NOEXIST)) {
        fprintf(stderr, "counter map insertion failed\n");
        stopped = 1;
        break;
      }
      printf("%s{\"cookie\":\"%016" PRIx64 "\",\"uploaded\":%" PRIu64
             ",\"downloaded\":%" PRIu64 ",\"new\":%s}",
             i ? "," : "", wanted[i], c.up, c.down, existed ? "false" : "true");
    }
    uint32_t z = 0;
    uint64_t lost = 0;
    bpf_map_lookup_elem(lossfd, &z, &lost);
    printf("],\"missed_operations\":%" PRIu64 "}\n", lost);
    fflush(stdout);
    memcpy(active, wanted, n * sizeof(uint64_t));
    count = n;
  }
  udp_bpf__destroy(s);
  return stopped ? 1 : 0;
}

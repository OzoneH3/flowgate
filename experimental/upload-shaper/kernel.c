// Private helper for the isolated controller: bounded map operations, no
// payloads.
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
struct value {
  uint64_t until;
  uint32_t id, download; // egress class, IFB class (either may be 0)
};
// The config map value reuses this layout: until, egress major, flags.
struct download_config {
  uint32_t major, ifindex, flags, reserved; // flags bit0: download budget
};
// Application class ids exclude the reserved budget/bypass/default minors.
#define MAX_APP_MINOR 0xffef
static void die(const char *s) {
  perror(s);
  exit(1);
}
static int map(const char *p, const char *n) {
  char s[512];
  if (snprintf(s, sizeof(s), "%s/%s", p, n) >= (int)sizeof(s))
    exit(2);
  int fd = bpf_obj_get(s);
  if (fd < 0)
    die("pinned object");
  return fd;
}
static uint64_t now(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t))
    die("clock");
  return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}
static uint64_t cookie(const char *s) {
  if (strlen(s) != 16)
    exit(2);
  uint64_t c;
  unsigned char b[8];
  for (int i = 0; i < 8; i++) {
    unsigned v;
    if (sscanf(s + i * 2, "%2x", &v) != 1)
      exit(2);
    b[i] = v;
  }
  memcpy(&c, b, 8);
  return c;
}
static int dispatch(int argc, char **argv) {
  if (argc < 3)
    return 2;
  const char *op = argv[1], *pin = argv[2];
  uint32_t z = 0;
  if (!strcmp(op, "load")) {
    if (argc != 4)
      return 2;
    struct bpf_object *o = bpf_object__open_file(argv[3], NULL);
    if (libbpf_get_error(o) || bpf_object__load(o))
      die("load");
    if (bpf_object__pin_maps(o, pin))
      die("pin");
    // One object carries both direction adapters sharing one map set:
    // egress "classify" -> program, ingress "classify_ingress" -> ingress.
    struct bpf_program *prog;
    int pinned = 0;
    bpf_object__for_each_program(prog, o) {
      const char *name = bpf_program__name(prog);
      char p[512];
      if (!strcmp(name, "classify"))
        snprintf(p, sizeof(p), "%s/program", pin);
      else if (!strcmp(name, "classify_ingress"))
        snprintf(p, sizeof(p), "%s/ingress", pin);
      else
        exit(2);
      if (bpf_program__pin(prog, p))
        die("program");
      pinned++;
    }
    if (pinned != 2)
      exit(2);
    bpf_object__close(o);
    return 0;
  }
  if (!strcmp(op, "priority-test")) {
    if (argc != 4) return 2;
    int fd = map(pin, "program");
    unsigned char packet[64] = {0};
    struct __sk_buff in = {0}, out = {0};
    in.priority = strtoul(argv[3], NULL, 10);
    struct bpf_test_run_opts opts = {.sz = sizeof(opts), .data_in = packet,
      .data_size_in = sizeof(packet), .ctx_in = &in, .ctx_size_in = sizeof(in),
      .ctx_out = &out, .ctx_size_out = sizeof(out), .repeat = 1};
    if (bpf_prog_test_run_opts(fd, &opts)) die("priority-test");
    printf("{\"priority\":%u}\n", out.priority);
    close(fd); return 0;
  }
  if (!strcmp(op, "ids")) {
    const char *names[] = {"bindings", "config", "counters", "download", "program", "ingress"};
    printf("{");
    for (int i = 0; i < 6; i++) {
      int fd = map(pin, names[i]), isprog = i >= 4;
      struct bpf_map_info m = {0};
      struct bpf_prog_info p = {0};
      uint32_t n = isprog ? sizeof(p) : sizeof(m);
      if (bpf_obj_get_info_by_fd(fd, isprog ? (void *)&p : (void *)&m, &n))
        die("info");
      printf("%s\"%s\":%u", i ? "," : "", names[i], isprog ? p.id : m.id);
      close(fd);
    }
    puts("}");
    return 0;
  }
  if (!strcmp(op, "init") || !strcmp(op, "beat")) {
    int fd = map(pin, "config");
    struct value v = {0};
    if (!strcmp(op, "init")) {
      if (argc != 4)
        return 2;
      v.id = strtoul(argv[3], NULL, 10);
      if (v.id < 0x100 || v.id >= 0xff00)
        return 2;
    } else if (bpf_map_lookup_elem(fd, &z, &v))
      die("config");
    v.until = now() + 5000000000ULL;
    if (bpf_map_update_elem(fd, &z, &v, BPF_ANY))
      die("heartbeat");
    close(fd);
    return 0;
  }
  if (!strcmp(op, "ulbudget")) {
    // Upload budget flag (bit0 of config.flags); until/major are preserved.
    if (argc != 4 || (strcmp(argv[3], "0") && strcmp(argv[3], "1")))
      return 2;
    int fd = map(pin, "config");
    struct value v = {0};
    if (bpf_map_lookup_elem(fd, &z, &v))
      die("config");
    v.download = argv[3][0] == '1';
    if (bpf_map_update_elem(fd, &z, &v, BPF_ANY))
      die("ulbudget");
    close(fd);
    return 0;
  }
  if (!strcmp(op, "download")) {
    if (argc != 6 || (strcmp(argv[5], "0") && strcmp(argv[5], "1")))
      return 2;
    int fd = map(pin, "download");
    struct download_config d = {.major = strtoul(argv[3], NULL, 10),
                                .ifindex = strtoul(argv[4], NULL, 10),
                                .flags = argv[5][0] == '1'};
    if ((d.major && (d.major < 0x100 || d.major >= 0xff00)) || (!d.major) != (!d.ifindex) || (!d.major && d.flags))
      return 2;
    if (bpf_map_update_elem(fd, &z, &d, BPF_ANY))
      die("download");
    close(fd);
    return 0;
  }
  if (!strcmp(op, "health")) {
    int cf = map(pin, "config"), fd = map(pin, "bindings");
    struct value v = {0};
    if (bpf_map_lookup_elem(cf, &z, &v))
      die("health config");
    printf("{\"config_until\":%llu,\"bindings\":[",
           (unsigned long long)v.until);
    uint64_t key, next;
    int have = 0, count = 0;
    while (bpf_map_get_next_key(fd, have ? &key : NULL, &next) == 0) {
      if (++count > 128)
        return 2;
      key = next;
      struct value b;
      if (bpf_map_lookup_elem(fd, &key, &b))
        die("health binding");
      printf("%s{\"cookie\":\"", have ? "," : "");
      unsigned char *raw = (void *)&key;
      for (int i = 0; i < 8; i++)
        printf("%02x", raw[i]);
      printf("\",\"until\":%llu,\"minor\":%u,\"download\":%u}",
             (unsigned long long)b.until, b.id, b.download);
      have = 1;
    }
    if (errno != ENOENT) {
      die("health iteration");
    }
    puts("]}");
    close(cf);
    close(fd);
    return 0;
  }
  if (!strcmp(op, "stats")) {
    int fd = map(pin, "counters"), n = libbpf_num_possible_cpus();
    if (n < 1 || n > 256)
      return 2;
    uint64_t *v = calloc(n, 16);
    if (!v)
      die("allocate");
    puts("[");
    for (uint32_t k = 0; k < 18; k++) {
      if (bpf_map_lookup_elem(fd, &k, v))
        die("counter");
      uint64_t p = 0, b = 0;
      for (int i = 0; i < n; i++) {
        p += v[2 * i];
        b += v[2 * i + 1];
      }
      printf("{\"packets\":%llu,\"bytes\":%llu}%s\n", (unsigned long long)p,
             (unsigned long long)b, k == 17 ? "" : ",");
    }
    puts("]");
    free(v);
    close(fd);
    return 0;
  }
  int fd = map(pin, "bindings");
  if (argc < 4)
    return 2;
  uint64_t key = cookie(argv[3]);
  if (!strcmp(op, "del")) {
    if (bpf_map_delete_elem(fd, &key) && errno != ENOENT)
      die("delete");
  } else if (!strcmp(op, "bind")) {
    if (argc != 6)
      return 2;
    struct value v = {.until = now() + 5000000000ULL,
                      .id = strtoul(argv[4], NULL, 10),
                      .download = strtoul(argv[5], NULL, 10)};
    // Both ids may be 0: a priority-only application without any budgeted
    // direction keeps its lease but receives no class.
    if (v.id > MAX_APP_MINOR || v.download > MAX_APP_MINOR)
      return 2;
    if (bpf_map_update_elem(fd, &key, &v, BPF_ANY))
      die("binding");
  } else
    return 2;
  close(fd);
  return 0;
}


// Private serial protocol. The completion marker is emitted ONLY after a
// successful operation, including all map reads/writes. No descriptors or
// observations survive a request. Failure terminates the worker without ACK.
int main(int argc, char **argv) {
  if (argc != 2 || strcmp(argv[1], "serve"))
    return dispatch(argc, argv);
  char line[1024];
  while (fgets(line, sizeof(line), stdin)) {
    size_t n = strlen(line);
    if (!n || line[n - 1] != '\n') return 2;
    char *args[8] = {argv[0]}, *save = NULL;
    int count = 1;
    for (char *p = strtok_r(line, " \n", &save); p;
         p = strtok_r(NULL, " \n", &save)) {
      if (count == 8) return 2;
      args[count++] = p;
    }
    if (count < 3) return 2;
    const char *op = args[1];
    if (strcmp(op,"ids") && strcmp(op,"beat") && strcmp(op,"health") &&
        strcmp(op,"stats") && strcmp(op,"bind") && strcmp(op,"del")) return 2;
    if (count != (!strcmp(op,"bind") ? 6 : !strcmp(op,"del") ? 4 : 3))
      return 2;
    if (dispatch(count,args)) return 2;
    if (fputs("\036OK\n",stdout) == EOF || fflush(stdout)) return 1;
  }
  return ferror(stdin) ? 1 : 0;
}

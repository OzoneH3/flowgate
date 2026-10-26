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
  uint32_t id, reserved;
};
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
int main(int argc, char **argv) {
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
    char p[512];
    snprintf(p, sizeof(p), "%s/program", pin);
    if (bpf_program__pin(bpf_object__next_program(o, NULL), p))
      die("program");
    bpf_object__close(o);
    return 0;
  }
  if (!strcmp(op, "ids")) {
    const char *names[] = {"bindings", "config", "counters", "program"};
    printf("{");
    for (int i = 0; i < 4; i++) {
      int fd = map(pin, names[i]);
      struct bpf_map_info m = {0};
      struct bpf_prog_info p = {0};
      uint32_t n = i == 3 ? sizeof(p) : sizeof(m);
      if (bpf_obj_get_info_by_fd(fd, i == 3 ? (void *)&p : (void *)&m, &n))
        die("info");
      printf("%s\"%s\":%u", i ? "," : "", names[i], i == 3 ? p.id : m.id);
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
      printf("\",\"until\":%llu,\"minor\":%u}", (unsigned long long)b.until,
             b.id);
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
    if (argc != 5)
      return 2;
    struct value v = {.until = now() + 5000000000ULL,
                      .id = strtoul(argv[4], NULL, 10)};
    if (v.id < 1 || v.id > 0xfffd)
      return 2;
    if (bpf_map_update_elem(fd, &key, &v, BPF_ANY))
      die("binding");
  } else
    return 2;
  close(fd);
  return 0;
}

// Single BPF object: both direction adapters share one map set (shaping.bpf.h).
// Egress (upload) and ingress (download) packet handling stay in their own files.
#include "classify.bpf.c"
#include "ingress.bpf.c"
char LICENSE[] SEC("license") = "GPL";

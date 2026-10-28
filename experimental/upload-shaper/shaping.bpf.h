// Shared map layout of the egress (upload) and ingress (download) adapters.
// Both objects are linked into one classify.bpf.o so they use the SAME maps:
// one binding per socket cookie carries both class ids. NEVER a firewall source.
#ifndef FLOWGATE_SHAPING_BPF_H
#define FLOWGATE_SHAPING_BPF_H
struct binding {
  __u64 until;
  __u32 minor;    // NIC egress HTB class (upload) or 0
  __u32 download; // IFB HTB class (download) or 0
};
struct config {
  __u64 until;
  __u32 major; // egress HTB major
  __u32 reserved;
};
struct download_config {
  __u32 major;   // IFB HTB major, 0 = download adapter withdrawn
  __u32 ifindex; // owned IFB ifindex, 0 = withdrawn
};
struct counter {
  __u64 packets, bytes;
};
// Counter indices: 0 egress unbound/default, 1 egress classified, 2/3/4 egress
// segmentation, 5 ingress redirected, 6 ingress TCP without binding/receiver,
// 7 ingress bound socket without current download class or lease, 17 egress
// expired binding. Telemetry only, never authority.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, __u64);
  __type(value, struct binding);
} bindings SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct config);
} config SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct download_config);
} download SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 18);
  __type(key, __u32);
  __type(value, struct counter);
} counters SEC(".maps");
#endif

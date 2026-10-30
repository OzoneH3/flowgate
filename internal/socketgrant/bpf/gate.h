/* Shared exact-match ABI. Application authority is supplied only after verification. */
#ifndef FLOWGATE_SOCKET_GATE_H
#define FLOWGATE_SOCKET_GATE_H
#include <linux/types.h>
struct gate_key {
  __u64 cookie;
  __u32 source, destination; /* network byte order */
  __u16 source_port, destination_port; /* network byte order */
  __u32 ifindex;
};
struct gate_value { __u64 deadline_ns, generation; };
struct gate_stats { __u64 packets, bytes, last_seen_ns; };
#endif

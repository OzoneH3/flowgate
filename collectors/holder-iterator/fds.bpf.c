// SPDX-License-Identifier: GPL-2.0-only
// Fresh per-TID file enumeration. No hooks, pins, policy or cached ownership.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
struct row { __u64 inode; __u32 fd; __u32 end; };
SEC("iter/task_file")
int fds(struct bpf_iter__task_file *ctx) {
  struct row r = {};
  struct file *file = ctx->file;
  if (!file) {
    r.end = 1;
    bpf_seq_write(ctx->meta->seq, &r, sizeof(r));
    return 0;
  }
  r.fd = ctx->fd;
  struct inode *i = 0;
  struct super_block *sb = 0;
  unsigned short mode = 0;
  unsigned long magic = 0;
  if (bpf_core_read(&i, sizeof(i), &file->f_inode) ||
      bpf_core_read(&mode, sizeof(mode), &i->i_mode) ||
      bpf_core_read(&sb, sizeof(sb), &i->i_sb) ||
      bpf_core_read(&magic, sizeof(magic), &sb->s_magic)) r.end=2;
  // Filesystem socket nodes opened O_PATH are not socket descriptors.
  if (!r.end && (mode & 0170000) == 0140000 && magic == 0x534f434b)
    if (bpf_core_read(&r.inode, sizeof(r.inode), &i->i_ino)) r.end=2;
  // seq_file manages buffer overflow/retry. The iterator callback must return
  // a verifier-bounded value, not the helper's arbitrary signed result.
  // Userspace requires a complete record stream and the final trailer.
  bpf_seq_write(ctx->meta->seq, &r, sizeof(r));
  return 0;
}
char LICENSE[] SEC("license") = "GPL";

#ifndef EVENT_H
#define EVENT_H

#ifdef __BPF__
#include "vmlinux.h"
#else
#include <linux/types.h>
#endif

#define EVENT_EXEC 1
#define EVENT_FILE_OPEN 2

struct event {
  __u32 pid;
  __u32 uid;
  __u64 cgroup_id;
  __u32 type;
  __u64 inode;
  char comm[16];
  char filename[256];
};
#endif

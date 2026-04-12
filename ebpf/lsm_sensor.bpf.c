// SPDX-License-Identifier: GPL
#include "event.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* ring buffer map */

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

/* ---------------------------
   EXEC SENSOR
---------------------------- */

SEC("lsm/bprm_check_security")
int BPF_PROG(exec_monitor, struct linux_binprm *bprm) {
  struct event *e;

  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;

  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->uid = bpf_get_current_uid_gid();
  e->cgroup_id = bpf_get_current_cgroup_id();
  e->type = EVENT_EXEC;

  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), bprm->filename);

  bpf_ringbuf_submit(e, 0);

  return 0;
}

/* ---------------------------
   FILE OPEN SENSOR
---------------------------- */

SEC("lsm/file_open")
int BPF_PROG(file_open_monitor, struct file *file) {
  struct event *e;
  struct dentry *de;

  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;

  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->uid = bpf_get_current_uid_gid();
  e->cgroup_id = bpf_get_current_cgroup_id();
  e->type = EVENT_FILE_OPEN;

  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  de = file->f_path.dentry;

  bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), de->d_name.name);

  bpf_ringbuf_submit(e, 0);

  return 0;
}

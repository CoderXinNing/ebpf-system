// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct exec_event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    evt->timestamp = bpf_ktime_get_ns();
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    // 安全读取——只读args[0]，不循环
    char *cmd = evt->filename;
    const char *arg0 = (const char *)ctx->args[0];
    if (arg0) {
        bpf_probe_read_user_str(cmd, 255, arg0);
    } else {
        cmd[0] = 0;
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

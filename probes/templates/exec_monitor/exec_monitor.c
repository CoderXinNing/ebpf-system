// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct exec_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char comm[16];
    char filename[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ppid = (bpf_get_current_pid_tgid() << 32) >> 32; // TODO: 获取真正的ppid
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // 读取execve的第一个参数（文件名）
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename_ptr);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

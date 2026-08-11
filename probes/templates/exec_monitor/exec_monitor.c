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

// 白名单 map: 进程名 -> 1 (命中则跳过采集)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[16]);
    __type(value, __u8);
} exec_whitelist SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    // 白名单过滤：命中直接返回，不采集
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (bpf_map_lookup_elem(&exec_whitelist, &comm)) {
        return 0;
    }

    struct exec_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ppid = (bpf_get_current_pid_tgid() << 32) >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __builtin_memcpy(event->comm, comm, sizeof(event->comm));

    // 读取execve的第一个参数（文件名）
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename_ptr);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

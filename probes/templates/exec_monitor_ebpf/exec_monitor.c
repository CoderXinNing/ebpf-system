// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "../alert_common.h"
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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[16]);
    __type(value, __u8);
} exec_whitelist SEC(".maps");

// ring buffer 连续失败计数器
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} ring_full_cnt SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    char comm[16] __attribute__((aligned(8)));
    bpf_get_current_comm(&comm, sizeof(comm));
    
    if (bpf_map_lookup_elem(&exec_whitelist, &comm)) {
        return 0;
    }

    struct exec_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->ppid = (bpf_get_current_pid_tgid() << 32) >> 32;
        event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        __builtin_memcpy(event->comm, comm, sizeof(event->comm));

        __u64 filename_u64 = ctx->args[0];
        const char *filename_ptr = (const char *)filename_u64;
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename_ptr);

        bpf_ringbuf_submit(event, 0);
        
        // 重置失败计数
        __u32 key = 0;
        __u32 *fail_cnt = bpf_map_lookup_elem(&ring_full_cnt, &key);
        if (fail_cnt) *fail_cnt = 0;
        
        return 0;
    }
    
    // ring buffer 满
    __u32 key = 0;
    __u32 *fail_cnt = bpf_map_lookup_elem(&ring_full_cnt, &key);
    if (!fail_cnt) return 0;
    
    (*fail_cnt)++;
    
    // 连续失败 3 次才认为 Agent 挂了
    if (*fail_cnt >= 3) {
        struct alert_event alert = {};
        alert.pid = bpf_get_current_pid_tgid() >> 32;
        alert.event_type = 1;
        alert.timestamp = bpf_ktime_get_ns();
        __builtin_memcpy(alert.comm, comm, sizeof(comm));
        
        __u64 filename_u64 = ctx->args[0];
        const char *filename_ptr = (const char *)filename_u64;
        bpf_probe_read_user_str(alert.details, sizeof(alert.details), filename_ptr);
        
        alert_push(&alert);
    }
    
    return 0;
}

// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// 用map存储agent_pid，加载器启动时写入
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} agent_config SEC(".maps");

struct alert_event {
    __u32 pid;
    __u32 target_pid;
    __u32 syscall_nr;
    char comm[16];
    char details[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} alerts SEC(".maps");

// 获取agent_pid
static __u32 get_agent_pid() {
    __u32 key = 0;
    __u32 *val = bpf_map_lookup_elem(&agent_config, &key);
    return val ? *val : 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int trace_kill(struct trace_event_raw_sys_enter *ctx)
{
    __u32 target_pid = ctx->args[0];
    __u32 my_pid = get_agent_pid();
    
    if (my_pid == 0 || target_pid != my_pid) {
        return 0;
    }
    
    struct alert_event *event;
    event = bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);
    if (!event) return 0;
    
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->target_pid = target_pid;
    event->syscall_nr = 62;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memcpy(event->details, "Attempt to kill Agent process", 30);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    __u32 target_pid = ctx->args[1];
    __u32 my_pid = get_agent_pid();
    
    if (my_pid == 0 || target_pid != my_pid) {
        return 0;
    }
    
    struct alert_event *event;
    event = bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);
    if (!event) return 0;
    
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->target_pid = target_pid;
    event->syscall_nr = 101;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memcpy(event->details, "Attempt to ptrace Agent process", 32);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf_delete(struct trace_event_raw_sys_enter *ctx)
{
    __u32 cmd = ctx->args[0];
    __u32 my_pid = get_agent_pid();
    
    if (my_pid == 0 || cmd != 3) {
        return 0;
    }
    
    struct alert_event *event;
    event = bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);
    if (!event) return 0;
    
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->target_pid = my_pid;
    event->syscall_nr = 321;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memcpy(event->details, "Attempt to delete BPF map entry", 31);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

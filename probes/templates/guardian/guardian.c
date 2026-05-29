// SPDX-License-Identifier: GPL-2.0
// 守护探针：保护Agent进程自身
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Agent的PID，由加载器注入
const volatile pid_t agent_pid = 0;

// 告警事件结构
struct alert_event {
    u32 pid;        // 攻击者PID
    u32 target_pid; // 目标PID
    u32 syscall;    // 系统调用号
    char comm[16];  // 攻击者进程名
    char details[64]; // 详细信息
};

// Ring buffer用于上报事件
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} alerts SEC(".maps");

// 检测：有人尝试kill Agent
SEC("tracepoint/syscalls/sys_enter_kill")
int trace_kill(struct trace_event_raw_sys_enter *ctx)
{
    pid_t target_pid = (pid_t)ctx->args[0];
    
    if (target_pid != agent_pid) {
        return 0;
    }
    
    struct alert_event *event;
    event = bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->target_pid = target_pid;
    event->syscall = 62; // SYS_kill
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_str(event->details, sizeof(event->details), 
                        "Attempt to kill Agent process");
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// 检测：有人尝试ptrace Agent
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    // ptrace(request, pid, ...)
    pid_t target_pid = (pid_t)ctx->args[1];
    
    if (target_pid != agent_pid) {
        return 0;
    }
    
    struct alert_event *event;
    event = bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->target_pid = target_pid;
    event->syscall = 101; // SYS_ptrace
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_str(event->details, sizeof(event->details),
                        "Attempt to ptrace Agent process");
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// 检测：有人删除BPF map（可能想破坏探针数据）
SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf_delete(struct trace_event_raw_sys_enter *ctx)
{
    int cmd = (int)ctx->args[0];
    
    // BPF_MAP_DELETE_ELEM = 3
    // BPF_MAP_FREEZE = ...
    // 这里简化处理，只关心删除操作
    if (cmd != 3 && cmd != 17) { // 17 = BPF_PROG_DETACH
        return 0;
    }
    
    struct alert_event *event;
    event = bpf_ringbuf_reserve(&alerts, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->target_pid = agent_pid;
    event->syscall = 321; // SYS_bpf
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    if (cmd == 3) {
        bpf_probe_read_str(event->details, sizeof(event->details),
                           "Attempt to delete BPF map entry");
    } else {
        bpf_probe_read_str(event->details, sizeof(event->details),
                           "Attempt to detach BPF program");
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

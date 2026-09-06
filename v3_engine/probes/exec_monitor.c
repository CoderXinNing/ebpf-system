// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "sentinel_common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// ============================================
// PID 关联 Map
// ============================================
struct pid_context {
    char comm[16];
    char cmdline[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct pid_context);
} pid_correlations SEC(".maps");

// exec 探针独立 Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} exec_events SEC(".maps");

// PPID 关联 Map（Key: pid, Value: ppid）
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u32);
} pid_ppid_map SEC(".maps");

// ============================================
// 读取父进程 TGID
// ============================================
static __always_inline __u32 get_parent_pid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return 0;
    }

    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if (!parent) {
        return 0;
    }

    return BPF_CORE_READ(parent, tgid);
}

// ============================================
// 读取父进程 comm（安全版本）
// ============================================
static __always_inline void get_parent_comm(char *buf, __u32 buf_len) {
    if (buf_len < 16) return;
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return;
    }

    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if (!parent) {
        return;
    }

    // 使用 bpf_probe_read_kernel_str 读取，避免 verifier 拒绝
    bpf_probe_read_kernel_str(buf, 16, &parent->comm);
    buf[15] = '\0';
}

// ============================================
// tracepoint 挂载（sys_enter_execve）
// ============================================
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *args) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u64 now = bpf_ktime_get_ns();

    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    // 白名单过滤
    __u64 whitelist_enabled = get_config_value(CONFIG_WHITELIST_ENABLED);
    if (whitelist_enabled == 1) {
        __u8 *allowed = bpf_map_lookup_elem(&sentinel_whitelist, comm);
        if (allowed && *allowed == 1) {
            return 0;
        }
    }

    // 读取命令行
    const char *filename = (const char *)args->args[0];
    if (!filename) {
        return 0;
    }

    // 分配事件
    struct sentinel_event_header *evt;
    evt = bpf_ringbuf_reserve(&exec_events, sizeof(struct sentinel_event_header), 0);
    if (!evt) {
        return 0;
    }

    // 填充事件头
    evt->pid = pid;
    evt->ppid = get_parent_pid();
    evt->uid = uid;
    evt->event_type = EVENT_EXEC;
    evt->timestamp = now;
    sentinel_strncpy(evt->comm, comm, sizeof(evt->comm));

    // 命令行
    __builtin_memset(evt->data, 0, sizeof(evt->data));
    bpf_probe_read_user_str(evt->data, 256, filename);
    evt->data[255] = '\0';

    // 父进程名
    get_parent_comm(evt->parent_comm, sizeof(evt->parent_comm));

    // correlation_key
    evt->correlation_key = make_correlation_key(pid);

    // 在提交前保存 ppid（Ring Buffer 提交后指针失效）
    __u32 parent_pid = evt->ppid;

    // 提交事件
    bpf_ringbuf_submit(evt, 0);

    // 更新 PID 关联 Map
    struct pid_context pctx = {};
    sentinel_strncpy(pctx.comm, comm, sizeof(pctx.comm));
    sentinel_strncpy(pctx.cmdline, evt->data, sizeof(pctx.cmdline));
    bpf_map_update_elem(&pid_correlations, &pid, &pctx, BPF_ANY);

    // 单独记录 PPID
    bpf_map_update_elem(&pid_ppid_map, &pid, &parent_pid, BPF_ANY);

    return 0;
}

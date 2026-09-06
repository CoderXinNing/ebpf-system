// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "sentinel_common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// ============================================
// PID 关联 Map（星轨支持：未来文件/网络探针反查进程上下文）
// Key: pid, Value: 进程上下文（comm + cmdline）
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

// ============================================
// 读取父进程 TGID 和 comm（CO-RE 标准写法）
// ============================================
static __always_inline __u32 get_parent_pid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return 0;
    }

    struct task_struct *parent = NULL;
    if (bpf_core_read(&parent, sizeof(parent), &task->real_parent) != 0) {
        return 0;
    }
    if (!parent) {
        return 0;
    }

    __u32 parent_tgid = 0;
    if (bpf_core_read(&parent_tgid, sizeof(parent_tgid), &parent->tgid) != 0) {
        return 0;
    }
    return parent_tgid;
}

static __always_inline void get_parent_comm(char *buf, __u32 buf_len) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return;
    }

    struct task_struct *parent = NULL;
    if (bpf_core_read(&parent, sizeof(parent), &task->real_parent) != 0) {
        return;
    }
    if (!parent) {
        return;
    }

    // 用 bpf_core_read 直接读 comm 数组
    if (bpf_core_read(buf, buf_len, &parent->comm) != 0) {
        buf[0] = '\0';
        return;
    }
    buf[buf_len - 1] = '\0';
}

// ============================================
// 白名单检查（LRU Hash，动态规则下发）
// ============================================
static __always_inline int is_whitelisted(const char *comm) {
    if (!comm) {
        return 0;
    }

    __u8 *allowed = bpf_map_lookup_elem(&sentinel_whitelist, comm);
    if (allowed && *allowed == 1) {
        return 1;
    }
    return 0;
}

// ============================================
// tracepoint 挂载（天然拿到 filename 和 argv）
// ============================================
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *args) {
    struct sentinel_event_header *evt;
    struct pid_context pctx = {};

    // 1. 获取基本信息
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // 2. 读取当前进程名
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    // 3. 白名单过滤
    if (is_whitelisted(comm)) {
        return 0;
    }

    // 4. 读取命令行（使用 ringbuf reserve 动态分配，避免栈上大数组）
    const char *filename = (const char *)args->args[0];
    if (!filename) {
        return 0;
    }

    evt = bpf_ringbuf_reserve(&sentinel_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;  // ring buffer 满
    }

    // 5. 填充事件头
    evt->pid = pid;
    evt->ppid = get_parent_pid();
    evt->uid = uid;
    evt->event_type = EVENT_EXEC;
    evt->timestamp = bpf_ktime_get_ns();
    sentinel_strncpy(evt->comm, comm, sizeof(evt->comm));

    // 6. 读取完整命令行到 data 字段（最多 256 字节）
    bpf_probe_read_user_str(evt->data, 256, filename);
    evt->data[255] = '\0';

    // 7. 填充父进程名到 parent_comm（统一 header 有这个字段）
    get_parent_comm(evt->parent_comm, sizeof(evt->parent_comm));

    // 8. 提交事件
    bpf_ringbuf_submit(evt, 0);

    // 9. 更新 PID 关联 Map（星轨支持）
    pctx.comm[0] = '\0';
    sentinel_strncpy(pctx.comm, comm, sizeof(pctx.comm));
    bpf_probe_read_user_str(pctx.cmdline, sizeof(pctx.cmdline), evt->data);
    bpf_map_update_elem(&pid_correlations, &pid, &pctx, BPF_ANY);

    return 0;
}

// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "sentinel_common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// file_access 独立 Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} file_events SEC(".maps");

// ============================================
// Agent 进程树懒惰加入（P1.9）
// 位置说明：必须放在 bpf_core_read.h include 之后
// ============================================
static __always_inline int is_agent_tree_or_join(__u32 pid) {
    if (pid == 0) return 0;
    if (is_agent_tree(pid)) return 1;

    // 懒惰加入：父在 agent_pids 则自己也加入
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    struct task_struct *parent = NULL;
    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    if (!parent) return 0;

    if (is_agent_tree_task(parent)) {
        add_current_to_agent_tree();
        return 1;
    }
    return 0;
}

// ============================================
// 敏感路径匹配（动态 map）
//
// 1. 精确匹配：sensitive_exact (HASH)
// 2. 前缀匹配：sensitive_prefixes (LPM_TRIE)
// ============================================
static __always_inline int is_sensitive_path(const char *filename) {
    if (!filename) return 0;

    // 只用一块 buffer（BPF 栈上限 512 字节）
    // lpm.path 同时用于 exact 查询（HASH 的 key 也是 char[256]）
    struct lpm_path_key lpm = {};
    long n = bpf_probe_read_user_str(lpm.path, sizeof(lpm.path), filename);
    if (n <= 0) {
        return 0;
    }
    lpm.path[255] = '\0';

    // 1. 精确匹配（HASH）：用 lpm.path 作为 key
    __u8 *exact_hit = bpf_map_lookup_elem(&sensitive_exact, lpm.path);
    if (exact_hit && *exact_hit == 1) {
        return 1;
    }

    // 2. 前缀匹配（LPM_TRIE）
    lpm.prefixlen = sizeof(lpm.path) * 8;  // 最大 bit 数，内核找最长匹配
    __u8 *prefix_hit = bpf_map_lookup_elem(&sensitive_prefixes, &lpm);
    if (prefix_hit && *prefix_hit == 1) {
        return 1;
    }

    return 0;
}

// ============================================
// Agent 进程树跟随（P1.9）
//
// ⚠️ 不用 sched_process_fork：
//   Go 的 exec.Command 底层用 vfork 语义的 clone
//   （CLONE_VM|CLONE_VFORK），不触发 sched_process_fork
//   改用 sched_process_exec（execve 一定触发），查父进程
//
//   exec: 父在 agent_pids → 当前进程加入
//   exit: 清理标记（防 pid 复用攻击）
// ============================================
SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx) {
    // exec 时查父进程：父在 agent_pids → 自己加入
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    struct task_struct *parent = NULL;
    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    if (!parent) return 0;

    if (is_agent_tree_task(parent)) {
        add_current_to_agent_tree();
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_exit(void *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    __u32 pid = 0;
    __u64 st = 0;
    read_task_pid_starttime(task, &pid, &st);
    if (pid == 0) return 0;

    struct pid_key key = {.pid = pid, .start_time_ticks = st};
    bpf_map_delete_elem(&agent_pids, &key);
    return 0;
}

// ============================================
// tracepoint 挂载（sys_enter_openat）
// ============================================
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *args) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u64 now = bpf_ktime_get_ns();

    // Agent 自身进程树过滤（P1.9，懒惰加入）
    if (is_agent_tree_or_join(pid)) {
        return 0;
    }

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

    // 读取文件名（openat 的第二个参数）
    const char *filename = (const char *)args->args[1];
    if (!filename) {
        return 0;
    }

    // 敏感路径过滤
    if (!is_sensitive_path(filename)) {
        return 0;
    }

    // 分配事件
    struct sentinel_event_header *evt;
    evt = bpf_ringbuf_reserve(&file_events, sizeof(struct sentinel_event_header), 0);
    if (!evt) {
        return 0;
    }

    // 填充事件头
    evt->pid = pid;
    evt->ppid = 0;
    evt->uid = uid;
    evt->event_type = EVENT_FILE;
    evt->timestamp = now;
    sentinel_strncpy(evt->comm, comm, sizeof(evt->comm));
    evt->parent_comm[0] = '\0';

    // 文件名
    __builtin_memset(evt->data, 0, sizeof(evt->data));
    bpf_probe_read_user_str(evt->data, 256, filename);
    evt->data[255] = '\0';

    // correlation_key
    evt->correlation_key = make_correlation_key(pid);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

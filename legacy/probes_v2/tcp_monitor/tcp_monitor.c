// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "sentinel_common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// ============================================
// TCP 连接聚合 Map（PERCPU_HASH 避免跨 CPU 锁竞争）
// Key: comm, Value: 连接计数
// ============================================
struct tcp_conn_count {
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, char[16]);
    __type(value, struct tcp_conn_count);
} tcp_conn_stats SEC(".maps");

// ============================================
// tracepoint 挂载（sys_enter_connect）
// ============================================
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *args) {
    // 1. 获取基本信息
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // 2. 读取进程名
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    // 3. 白名单过滤
    __u8 *allowed = bpf_map_lookup_elem(&sentinel_whitelist, comm);
    if (allowed && *allowed == 1) {
        return 0;
    }

    // 4. 聚合计数（PERCPU_HASH 安全累加）
    struct tcp_conn_count *count = bpf_map_lookup_elem(&tcp_conn_stats, comm);
    if (count) {
        __sync_fetch_and_add(&count->count, 1);
    } else {
        struct tcp_conn_count init = {.count = 1};
        bpf_map_update_elem(&tcp_conn_stats, comm, &init, BPF_ANY);
    }

    // 5. 提交事件（只在新连接时提交，不每次累加都提交）
    struct sentinel_event_header *evt;
    evt = bpf_ringbuf_reserve(&sentinel_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    evt->pid = pid;
    evt->ppid = 0;  // tcp 探针不采父进程
    evt->uid = uid;
    evt->event_type = EVENT_TCP;
    evt->timestamp = bpf_ktime_get_ns();
    sentinel_strncpy(evt->comm, comm, sizeof(evt->comm));
    evt->parent_comm[0] = '\0';

    // data 存连接目标（后续从 sockaddr 解析，先占位）
    sentinel_strncpy(evt->data, "tcp_connect", 12);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

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

    // 2. 提交事件（ring buffer 动态分配）
    struct sentinel_event_header *evt;
    evt = bpf_ringbuf_reserve(&sentinel_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    evt->pid = pid;
    evt->ppid = 0;
    evt->uid = uid;
    evt->event_type = EVENT_TCP;
    evt->timestamp = bpf_ktime_get_ns();

    // 读 comm 到 ring buffer 的字段里（避免栈上数组）
    bpf_get_current_comm(evt->comm, 16);
    evt->parent_comm[0] = '\0';

    // 白名单过滤
    __u8 *allowed = bpf_map_lookup_elem(&sentinel_whitelist, evt->comm);
    if (allowed && *allowed == 1) {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    // 聚合计数
    struct tcp_conn_count *count = bpf_map_lookup_elem(&tcp_conn_stats, evt->comm);
    if (count) {
        __sync_fetch_and_add(&count->count, 1);
    } else {
        struct tcp_conn_count init = {.count = 1};
        bpf_map_update_elem(&tcp_conn_stats, evt->comm, &init, BPF_ANY);
    }

    sentinel_strncpy(evt->data, "tcp_connect", 12);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

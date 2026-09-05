// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "sentinel_common.h"
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct pid_conn_stats {
    __u64 conn_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct pid_conn_stats);
} pid_conn_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *args) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct pid_conn_stats *stats = bpf_map_lookup_elem(&pid_conn_map, &pid);
    if (stats) {
        __sync_fetch_and_add(&stats->conn_count, 1);
    } else {
        struct pid_conn_stats init = {.conn_count = 1};
        bpf_map_update_elem(&pid_conn_map, &pid, &init, BPF_ANY);
    }

    return 0;
}

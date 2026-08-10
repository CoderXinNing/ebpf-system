// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct conn_stat {
    __u32 pid;
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, char[16]);
    __type(value, struct conn_stat);
} tcp_conn_stats SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct conn_stat *stat = bpf_map_lookup_elem(&tcp_conn_stats, comm);
    if (!stat) {
        struct conn_stat new_stat = {};
        new_stat.pid = bpf_get_current_pid_tgid() >> 32;
        new_stat.count = 1;
        bpf_map_update_elem(&tcp_conn_stats, comm, &new_stat, BPF_ANY);
    } else {
        stat->count++;
    }

    bpf_printk("TCP CONNECT: %s", comm);
    return 0;
}

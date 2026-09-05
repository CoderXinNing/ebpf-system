// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "sentinel_common.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2

char LICENSE[] SEC("license") = "GPL";

struct pid_conn_stats {
    __u32 recent_ports[4];
    __u32 recent_ips[4];
    __u64 conn_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct pid_conn_stats);
} pid_conn_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 标准写法：ctx->args[1] 是 sockaddr 指针
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    if (!addr) {
        return 0;
    }

    // 读取 sockaddr_in（用户态指针，必须用 bpf_probe_read_user）
    struct sockaddr_in addr_in;
    if (bpf_probe_read_user(&addr_in, sizeof(addr_in), addr) != 0) {
        return 0;
    }

    // 只处理 IPv4
    if (addr_in.sin_family != AF_INET) {
        return 0;
    }

    // 端口（网络字节序 → 主机字节序）
    __u16 port = bpf_ntohs(addr_in.sin_port);

    // IP（网络字节序，直接读）
    __u32 ip = addr_in.sin_addr.s_addr;

    // 更新统计
    struct pid_conn_stats *stats = bpf_map_lookup_elem(&pid_conn_map, &pid);
    if (stats) {
        __u32 idx = stats->conn_count % 4;
        stats->recent_ports[idx] = port;
        stats->recent_ips[idx] = ip;
        __sync_fetch_and_add(&stats->conn_count, 1);
    } else {
        struct pid_conn_stats init = {};
        init.recent_ports[0] = port;
        init.recent_ips[0] = ip;
        init.conn_count = 1;
        bpf_map_update_elem(&pid_conn_map, &pid, &init, BPF_ANY);
    }

    return 0;
}

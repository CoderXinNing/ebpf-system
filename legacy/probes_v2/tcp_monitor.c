// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "sentinel_common.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2

char LICENSE[] SEC("license") = "GPL";

// 连接统计（用于突变检测）
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

// 连接明细（星轨溯源用，最近 1000 条）
struct conn_detail {
    __u32 pid;
    __u32 daddr;      // 目标 IP
    __u16 dport;      // 目标端口
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000);
    __type(key, __u64);       // 自增序号
    __type(value, struct conn_detail);
} conn_details SEC(".maps");

// 序号计数器
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} detail_counter SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 标准写法：ctx->args[1] 是 sockaddr 指针
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    if (!addr) {
        return 0;
    }

    struct sockaddr_in addr_in;
    if (bpf_probe_read_user(&addr_in, sizeof(addr_in), addr) != 0) {
        return 0;
    }

    if (addr_in.sin_family != AF_INET) {
        return 0;
    }

    __u16 port = bpf_ntohs(addr_in.sin_port);
    __u32 ip = addr_in.sin_addr.s_addr;

    // 更新连接统计
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

    // 保存连接明细（星轨溯源）
    __u32 key0 = 0;
    __u64 *counter = bpf_map_lookup_elem(&detail_counter, &key0);
    if (counter) {
        __u64 seq = __sync_fetch_and_add(counter, 1);
        struct conn_detail detail = {
            .pid = pid,
            .daddr = ip,
            .dport = port,
            .timestamp = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&conn_details, &seq, &detail, BPF_ANY);
    }

    return 0;
}

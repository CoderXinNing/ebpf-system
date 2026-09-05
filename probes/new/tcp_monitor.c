// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "sentinel_common.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// ============================================
// PID 连接统计（LRU Hash，记录目标 IP 和端口）
// Key: PID, Value: 连接统计
// ============================================
struct pid_conn_stats {
    __u32 recent_ports[8];   // 最近 8 个目标端口
    __u32 recent_ips[8];     // 最近 8 个目标 IP（IPv4 低 32 位）
    __u64 conn_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);       // PID
    __type(value, struct pid_conn_stats);
} pid_conn_map SEC(".maps");

// ============================================
// tracepoint 挂载（sys_enter_connect）
// ============================================
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *args) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // 白名单过滤
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    __u8 *allowed = bpf_map_lookup_elem(&sentinel_whitelist, comm);
    if (allowed && *allowed == 1) {
        return 0;
    }

    // 读取 sockaddr（第 2 个参数）
    struct sockaddr *addr = (struct sockaddr *)args->args[1];
    if (!addr) {
        return 0;
    }

    // 读取端口和 IP
    __u16 port = 0;
    __u32 ip = 0;
    bpf_probe_read_kernel(&port, sizeof(port), &((struct sockaddr_in *)addr)->sin_port);
    bpf_probe_read_kernel(&ip, sizeof(ip), &((struct sockaddr_in *)addr)->sin_addr);
    port = bpf_ntohs(port);

    // 内网过滤（10/192.168/172.16/127）
    __u32 ip_net = ip & 0xFF000000;
    if (ip_net == 0x0A000000 ||      // 10.x
        ip_net == 0xAC100000 ||      // 172.16.x
        (ip & 0xFFFF0000) == 0xC0A80000 || // 192.168.x
        (ip & 0xFF000000) == 0x7F000000) { // 127.x
        return 0;  // 内网互访不上报
    }

    // 更新 PID 连接统计
    struct pid_conn_stats *stats = bpf_map_lookup_elem(&pid_conn_map, &pid);
    if (stats) {
        __sync_fetch_and_add(&stats->conn_count, 1);
        // 记录最近端口/IP（简单循环数组，最多 8 个）
        __u32 idx = stats->conn_count % 8;
        stats->recent_ports[idx] = port;
        stats->recent_ips[idx] = ip;
    } else {
        struct pid_conn_stats init = {};
        init.conn_count = 1;
        init.recent_ports[0] = port;
        init.recent_ips[0] = ip;
        bpf_map_update_elem(&pid_conn_map, &pid, &init, BPF_ANY);
    }

    return 0;  // 默认只计数，不上报
}

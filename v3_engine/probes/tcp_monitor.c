// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "sentinel_common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// ============================================
// TCP 连接聚合 Map（PERCPU_HASH 避免锁竞争）
// Key: pid, Value: 连接统计
// ============================================
struct tcp_conn_stats {
    __u64 count;
    __u64 last_seen_ns;
    __u32 recent_ports[4];
    __u32 recent_ips[4];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);          // pid
    __type(value, struct tcp_conn_stats);
} pid_conn_stats SEC(".maps");

// ============================================
// 连接明细 Map（星轨溯源用）
// Key: pid, Value: 最近一次五元组
// ============================================
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);          // pid
    __type(value, struct tcp_conn_detail);
} conn_details SEC(".maps");

// ============================================
// 解析 sockaddr 获取 IP 和端口
// ============================================
static __always_inline int parse_sockaddr(struct sockaddr *addr, struct tcp_conn_detail *detail) {
    if (!addr) return -1;
    
    // 分步读取 sockaddr_in（避免大结构体读取失败）
    __u16 sin_port = 0;
    __u32 sin_addr = 0;
    
    // 跳过 family(2字节)，读端口
    long ret1 = bpf_probe_read_user(&sin_port, 2, (void *)addr + 2);
    long ret2 = bpf_probe_read_user(&sin_addr, 4, (void *)addr + 4);
    if (ret1 != 0 || ret2 != 0) {
        bpf_printk("parse fail: ret1=%ld ret2=%ld", ret1, ret2);
        return -1;
    }
    
    bpf_printk("parse ok: addr=%llu port=%u ip=%u", (unsigned long long)addr, sin_port, sin_addr);
    detail->dst_port = __builtin_bswap16(sin_port);
    detail->dst_ip = __builtin_bswap32(sin_addr);
    
    detail->src_ip = 0;
    detail->src_port = 0;
    detail->protocol = 6; // TCP
    detail->padding[0] = 0;
    detail->padding[1] = 0;
    detail->padding[2] = 0;
    
    return 0;
}

// ============================================
// tracepoint 挂载（sys_enter_connect）
// ============================================
SEC("kprobe/__sys_connect")
int BPF_KPROBE(trace_connect, int fd, struct sockaddr *uservaddr, int addrlen) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u64 now = bpf_ktime_get_ns();
    
    // 1. 读取进程名
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // 2. 白名单过滤（如果启用）
    __u64 whitelist_enabled = get_config_value(CONFIG_WHITELIST_ENABLED);
    if (whitelist_enabled == 1) {
        __u8 *allowed = bpf_map_lookup_elem(&sentinel_whitelist, comm);
        if (allowed && *allowed == 1) {
            return 0;
        }
    }
    
    // 3. 解析目标地址
    struct tcp_conn_detail detail = {};
    if (uservaddr) {
        parse_sockaddr((struct sockaddr *)uservaddr, &detail);
    }
    
    // 4. 更新连接统计
    struct tcp_conn_stats *stats = bpf_map_lookup_elem(&pid_conn_stats, &pid);
    if (stats) {
        __sync_fetch_and_add(&stats->count, 1);
        stats->last_seen_ns = now;
    } else {
        struct tcp_conn_stats init = {.count = 1, .last_seen_ns = now};
        bpf_map_update_elem(&pid_conn_stats, &pid, &init, BPF_ANY);
        stats = bpf_map_lookup_elem(&pid_conn_stats, &pid);
    }

    // 更新最近端口和 IP（用于突变检测）
    if (stats && detail.dst_port != 0) {
        // 左移并插入新端口
        stats->recent_ports[3] = stats->recent_ports[2];
        stats->recent_ports[2] = stats->recent_ports[1];
        stats->recent_ports[1] = stats->recent_ports[0];
        stats->recent_ports[0] = detail.dst_port;

        // 左移并插入新 IP
        stats->recent_ips[3] = stats->recent_ips[2];
        stats->recent_ips[2] = stats->recent_ips[1];
        stats->recent_ips[1] = stats->recent_ips[0];
        stats->recent_ips[0] = detail.dst_ip;
    }
    
    // 5. 更新连接明细
    bpf_map_update_elem(&conn_details, &pid, &detail, BPF_ANY);
    
    // 6. 检查采集模式
    __u64 collect_mode = get_config_value(CONFIG_COLLECT_MODE);
    
    // 模式 0（计数）：只更新统计，不上报 Ring Buffer
    if (collect_mode == 0) {
        return 0;
    }
    
    // 模式 1（明细）：上报事件到 Ring Buffer
    struct sentinel_event_header *evt;
    evt = bpf_ringbuf_reserve(&sentinel_events, sizeof(struct sentinel_event_header), 0);
    if (!evt) {
        return 0; // Ring Buffer 满
    }
    
    evt->pid = pid;
    evt->ppid = 0;
    evt->uid = uid;
    evt->event_type = EVENT_TCP;
    evt->timestamp = now;
    sentinel_strncpy(evt->comm, comm, sizeof(evt->comm));
    evt->parent_comm[0] = '\0';
    
    // TCP 五元组内联编码进 data[256] 前 20 字节
    __builtin_memset(evt->data, 0, sizeof(evt->data));
    struct tcp_conn_detail *detail_ptr = (struct tcp_conn_detail *)evt->data;
    detail_ptr->src_ip = detail.src_ip;
    detail_ptr->dst_ip = detail.dst_ip;
    detail_ptr->src_port = detail.src_port;
    detail_ptr->dst_port = detail.dst_port;
    detail_ptr->protocol = detail.protocol;
    detail_ptr->padding[0] = 0;
    detail_ptr->padding[1] = 0;
    detail_ptr->padding[2] = 0;
    
    // 生成 correlation_key
    evt->correlation_key = make_correlation_key(pid);
    
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

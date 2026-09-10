// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "sentinel_common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// DNS 独立 Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} dns_events SEC(".maps");

// ============================================
// DNS 查询监控（kprobe on udp_sendmsg）
// 检测 DNS 隧道
// ============================================
SEC("kprobe/udp_sendmsg")
int trace_udp_sendmsg(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u64 now = bpf_ktime_get_ns();

    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    // 只关注 DNS 相关进程（systemd-resolved, dnsmasq, nscd）
    // 简化：只抓 53 端口的连接
    // 这里用 sendmsg 的 sockaddr 判断端口太复杂，先抓所有

    // 白名单过滤
    __u64 whitelist_enabled = get_config_value(CONFIG_WHITELIST_ENABLED);
    if (whitelist_enabled == 1) {
        __u8 *allowed = bpf_map_lookup_elem(&sentinel_whitelist, comm);
        if (allowed && *allowed == 1) {
            return 0;
        }
    }

    // 分配事件
    struct sentinel_event_header *evt;
    evt = bpf_ringbuf_reserve(&dns_events, sizeof(struct sentinel_event_header), 0);
    if (!evt) {
        return 0;
    }

    evt->pid = pid;
    evt->ppid = 0;
    evt->uid = uid;
    evt->event_type = EVENT_DNS;
    evt->timestamp = now;
    sentinel_strncpy(evt->comm, comm, sizeof(evt->comm));
    evt->parent_comm[0] = '\0';

    __builtin_memset(evt->data, 0, sizeof(evt->data));
    sentinel_strncpy(evt->data, "dns_query", 10);

    // 生成 correlation_key
    evt->correlation_key = make_correlation_key(pid);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

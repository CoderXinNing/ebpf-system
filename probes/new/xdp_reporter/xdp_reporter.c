// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "sentinel_common.h"
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

char LICENSE[] SEC("license") = "GPL";

// ============================================
// XDP 保底通道（Agent 挂掉时通过 UDP 报信）
// 默认 GenericMode，不拦截
// ============================================
SEC("xdp")
int xdp_reporter(struct xdp_md *ctx) {
    // 1. 读取数据包指针
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (!data || !data_end) {
        return XDP_PASS;  // 不拦截
    }

    // 2. 边界检查
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;  // 只处理 IPv4
    }

    // 3. 获取基本信息
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // 4. 提交事件（保底通道，只用 ring buffer 不额外处理）
    struct sentinel_event_header *evt;
    evt = bpf_ringbuf_reserve(&sentinel_events, sizeof(*evt), 0);
    if (!evt) {
        return XDP_PASS;
    }

    evt->pid = pid;
    evt->ppid = 0;
    evt->uid = uid;
    evt->event_type = EVENT_XDP;
    evt->timestamp = bpf_ktime_get_ns();

    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    sentinel_strncpy(evt->comm, comm, sizeof(evt->comm));
    evt->parent_comm[0] = '\0';

    // data 存网络事件摘要
    sentinel_strncpy(evt->data, "xdp_packet", 11);

    bpf_ringbuf_submit(evt, 0);
    return XDP_PASS;  // 始终放行，不拦截
}

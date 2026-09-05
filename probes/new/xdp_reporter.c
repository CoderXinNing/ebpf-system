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

    // 3. 提交事件（XDP 上下文无进程概念，pid/uid 置 0）
    struct sentinel_event_header *evt;
    evt = bpf_ringbuf_reserve(&sentinel_events, sizeof(*evt), 0);
    if (!evt) {
        return XDP_PASS;
    }

    evt->pid = 0;
    evt->ppid = 0;
    evt->uid = 0;
    evt->event_type = EVENT_XDP;
    evt->timestamp = bpf_ktime_get_ns();
    evt->comm[0] = 'x';
    evt->comm[1] = 'd';
    evt->comm[2] = 'p';
    evt->comm[3] = '\0';
    evt->parent_comm[0] = '\0';

    // data 存协议类型
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        sentinel_strncpy(evt->data, "ipv4", 5);
    } else {
        sentinel_strncpy(evt->data, "other", 6);
    }

    bpf_ringbuf_submit(evt, 0);
    return XDP_PASS;  // 始终放行，不拦截
}

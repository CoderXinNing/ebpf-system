// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "sentinel_common.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// XDP 独立 Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} xdp_events SEC(".maps");

SEC("xdp")
int xdp_reporter(struct xdp_md *ctx) {
    __u64 now = bpf_ktime_get_ns();
    
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 检查数据长度
    if (data + sizeof(__u32) > data_end) {
        return XDP_PASS;
    }
    
    // 分配事件
    struct sentinel_event_header *evt;
    evt = bpf_ringbuf_reserve(&xdp_events, sizeof(struct sentinel_event_header), 0);
    if (!evt) {
        return XDP_PASS;
    }
    
    evt->pid = 0;
    evt->ppid = 0;
    evt->uid = 0;
    evt->event_type = EVENT_XDP;
    evt->timestamp = now;
    evt->comm[0] = 'x';
    evt->comm[1] = 'd';
    evt->comm[2] = 'p';
    evt->comm[3] = '\0';
    evt->parent_comm[0] = '\0';
    
    __builtin_memset(evt->data, 0, sizeof(evt->data));
    bpf_printk("xdp: packet received");
    
    evt->correlation_key = 0;
    
    bpf_ringbuf_submit(evt, 0);
    return XDP_PASS;
}

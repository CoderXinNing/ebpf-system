// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "alert_common.h"
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// XDP 事件 ring buffer（Agent 读取）
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// 读取指针
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} alert_read_cnt SEC(".maps");

SEC("xdp")
int xdp_reporter(struct xdp_md *ctx) {
    __u32 key = 0;
    
    // 读 write_cnt
    __u32 *write_cnt = bpf_map_lookup_elem(&alert_write_cnt, &key);
    if (!write_cnt || *write_cnt == 0) return XDP_PASS;
    
    // 读 read_cnt
    __u32 *read_cnt = bpf_map_lookup_elem(&alert_read_cnt, &key);
    if (!read_cnt) return XDP_PASS;
    
    if (*read_cnt >= *write_cnt) return XDP_PASS;
    
    // 读告警
    __u32 idx = *read_cnt % ALERT_BUF_SIZE;
    struct alert_event *evt = bpf_map_lookup_elem(&alert_buffer, &idx);
    if (!evt || evt->pid == 0) {
        __sync_fetch_and_add(read_cnt, 1);
        return XDP_PASS;
    }
    
    // 写 ring buffer 让 Agent 上报
    struct alert_event *out = bpf_ringbuf_reserve(&events, sizeof(*out), 0);
    if (!out) {
        return XDP_PASS;
    }
    __builtin_memcpy(out, evt, sizeof(*evt));
    bpf_ringbuf_submit(out, 0);
    
    __sync_fetch_and_add(read_cnt, 1);
    
    // 关键：永远 PASS，不破坏流量
    return XDP_PASS;
}

// SPDX-License-Identifier: GPL-2.0
// XDP事件采集——写入ring buffer，用户态Agent读走上报
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// 事件结构
struct ebpf_event {
    __u64 timestamp;
    __u32 pid;
    __u32 event_type;
    char comm[16];
    char filename[64];
    char details[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// 统计：每N个包上报一次
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} pkt_count SEC(".maps");

SEC("xdp")
int xdp_reporter(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
    if (!count) return XDP_PASS;

    (*count)++;

    // 每100个包采集一次
    if (*count % 100 != 0) return XDP_PASS;

    struct ebpf_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return XDP_PASS;

    evt->timestamp = bpf_ktime_get_ns();
    evt->pid = 0;
    evt->event_type = 1; // XDP包计数
    __builtin_memcpy(evt->comm, "xdp", 4);
    __builtin_memcpy(evt->filename, "packet", 7);
    __builtin_memcpy(evt->details, "xdp probe", 10);

    bpf_ringbuf_submit(evt, 0);

    // 关键：原包放行，不影响网络
    return XDP_PASS;
}

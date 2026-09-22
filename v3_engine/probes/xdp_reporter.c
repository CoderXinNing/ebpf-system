// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "sentinel_common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// XDP 独立 Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} xdp_events SEC(".maps");

// XDP 包摘要结构（内联进 data）
struct pkt_summary {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 padding[3];
} __attribute__((packed));

SEC("xdp")
int xdp_reporter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. 以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // 只处理 IPv4
    if (eth->h_proto != bpf_htons(0x0800)) {
        return XDP_PASS;
    }

    // 2. IP 头
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    struct pkt_summary summary = {};
    summary.src_ip = ip->saddr;
    summary.dst_ip = ip->daddr;
    summary.protocol = ip->protocol;

    // 3. TCP/UDP 头
    __u32 ip_hdr_len = ip->ihl * 4;
    void *l4 = (void *)ip + ip_hdr_len;

    if (ip->protocol == 6) { // TCP
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }
        summary.src_port = tcp->source;
        summary.dst_port = tcp->dest;
    } else if (ip->protocol == 17) { // UDP
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }
        summary.src_port = udp->source;
        summary.dst_port = udp->dest;
    } else if (ip->protocol == 1) { // ICMP
        summary.src_port = 0;
        summary.dst_port = 0;
    } else {
        return XDP_PASS;
    }

    // 4. 分配事件
    struct sentinel_event_header *evt;
    evt = bpf_ringbuf_reserve(&xdp_events, sizeof(struct sentinel_event_header), 0);
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

    // 5. 摘要写入 data
    __builtin_memset(evt->data, 0, sizeof(evt->data));
    struct pkt_summary *summary_ptr = (struct pkt_summary *)evt->data;
    summary_ptr->src_ip = summary.src_ip;
    summary_ptr->dst_ip = summary.dst_ip;
    summary_ptr->src_port = summary.src_port;
    summary_ptr->dst_port = summary.dst_port;
    summary_ptr->protocol = summary.protocol;

    evt->correlation_key = 0;

    bpf_ringbuf_submit(evt, 0);
    return XDP_PASS;
}

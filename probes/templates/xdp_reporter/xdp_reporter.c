// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "alert_common.h"
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// 配置 Map：Go 端写入
struct xdp_config {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8   src_mac[6];
    __u8   dst_mac[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_config);
} xdp_config SEC(".maps");

// Per-CPU 读取指针
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
    
    // 读配置
    struct xdp_config *cfg = bpf_map_lookup_elem(&xdp_config, &key);
    if (!cfg) return XDP_PASS;
    
    // 读告警
    __u32 idx = *read_cnt % ALERT_BUF_SIZE;
    struct alert_event *evt = bpf_map_lookup_elem(&alert_buffer, &idx);
    if (!evt || evt->pid == 0) {
        __sync_fetch_and_add(read_cnt, 1);
        return XDP_PASS;
    }
    
    // 用原始包做模板，修改成告警包
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    
    // 交换 MAC（回复给发送方）
    __builtin_memcpy(eth->h_source, cfg->src_mac, 6);
    __builtin_memcpy(eth->h_dest, cfg->dst_mac, 6);
    eth->h_proto = bpf_htons(0x0800);  // IP
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 2 + sizeof(*evt));
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = 17;  // UDP
    ip->saddr = cfg->src_ip;
    ip->daddr = cfg->dst_ip;
    ip->check = 0;
    
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    
    udp->source = bpf_htons(cfg->src_port);
    udp->dest = bpf_htons(cfg->dst_port);
    udp->len = bpf_htons(sizeof(struct udphdr) + 2 + sizeof(*evt));
    udp->check = 0;  // 不校验，简化
    
    // 写魔数
    __u16 *magic = (void *)(udp + 1);
    if ((void *)(magic + 1) > data_end) return XDP_PASS;
    *magic = bpf_htons(ALERT_MAGIC);
    
    // 写告警数据
    char *payload = (void *)(magic + 1);
    if ((void *)(payload + sizeof(*evt)) > data_end) return XDP_PASS;
    __builtin_memcpy(payload, evt, sizeof(*evt));
    
    __sync_fetch_and_add(read_cnt, 1);
    
    return XDP_TX;
}

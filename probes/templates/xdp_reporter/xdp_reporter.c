// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8[36]);
} server_map SEC(".maps");

SEC("xdp")
int xdp_reporter(struct xdp_md *ctx) {
    __u32 key = 0;
    __u8 *cfg = bpf_map_lookup_elem(&server_map, &key);
    if (!cfg) return XDP_PASS;

    __u32 total_len = 14 + 20 + 8 + 8;
    if (bpf_xdp_adjust_head(ctx, 0 - (int)total_len) < 0) return XDP_PASS;

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u8 *pkt = data;
    if (pkt + total_len > (__u8 *)data_end) return XDP_DROP;

    // Eth
    for (int i = 0; i < 6; i++) { pkt[i] = cfg[18+i]; pkt[6+i] = cfg[12+i]; }
    pkt[12] = 0x08; pkt[13] = 0x00;

    // IP
    __u8 *ip = pkt + 14;
    ip[0] = 0x45; ip[1] = 0x00;
    __u16 ip_len = bpf_htons(20 + 8 + 8);
    ip[2] = ip_len & 0xff; ip[3] = (ip_len >> 8) & 0xff;
    for (int i = 4; i < 12; i++) ip[i] = 0;
    ip[8] = 64; ip[9] = 17;
    for (int i = 0; i < 4; i++) { ip[12+i] = cfg[i]; ip[16+i] = cfg[4+i]; }

    // UDP
    __u8 *udp = ip + 20;
    udp[0] = cfg[8]; udp[1] = cfg[9];
    udp[2] = cfg[10]; udp[3] = cfg[11];
    __u16 udp_len = bpf_htons(8 + 8);
    udp[4] = udp_len & 0xff; udp[5] = (udp_len >> 8) & 0xff;
    udp[6] = 0; udp[7] = 0;

    // Payload: "EBPFXD"
    __u8 *payload = udp + 8;
    payload[0] = 'E'; payload[1] = 'B'; payload[2] = 'P';
    payload[3] = 'F'; payload[4] = 'X'; payload[5] = 'D';
    payload[6] = 0; payload[7] = 0;

    return XDP_TX;
}

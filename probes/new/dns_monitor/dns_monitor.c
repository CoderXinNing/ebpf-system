// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "sentinel_common.h"
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// ============================================
// DNS 查询监控（kprobe on dns_query）
// 用于检测 DNS 隧道
// ============================================
SEC("kprobe/dns_query")
int trace_dns_query(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // 第二个参数是查询的域名
    const char *domain = (const char *)PT_REGS_PARM2(ctx);
    if (!domain) {
        return 0;
    }

    struct sentinel_event_header *evt;
    evt = bpf_ringbuf_reserve(&sentinel_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    evt->pid = pid;
    evt->ppid = 0;
    evt->uid = uid;
    evt->event_type = 6;  // EVENT_DNS
    evt->timestamp = bpf_ktime_get_ns();

    bpf_get_current_comm(evt->comm, 16);
    evt->parent_comm[0] = '\0';

    long ret = bpf_probe_read_kernel_str(evt->data, 256, domain);
    if (ret < 0) {
        evt->data[0] = '\0';
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

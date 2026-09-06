// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "sentinel_common.h"
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// ============================================
// DNS 相关监控（kprobe on dns_query）
// 如果 kprobe 不可用，回退到文件监控方式由 Go 端处理
// ============================================
SEC("kprobe/dns_query")
int trace_dns_query_kprobe(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    const char *name = (const char *)PT_REGS_PARM3(ctx);
    if (!name) {
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
    evt->event_type = 6;
    evt->timestamp = bpf_ktime_get_ns();

    bpf_get_current_comm(evt->comm, 16);
    evt->parent_comm[0] = '\0';

    long ret = bpf_probe_read_user_str(evt->data, 256, name);
    if (ret < 0) {
        evt->data[0] = '\0';
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

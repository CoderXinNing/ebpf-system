// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "sentinel_common.h"
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("uretprobe/readline")
int trace_readline(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // 读返回值（用户态字符串指针）
    const char *line = (const char *)ctx->ax;
    if (!line) {
        return 0;
    }

    // ring buffer 动态分配
    struct sentinel_event_header *evt;
    evt = bpf_ringbuf_reserve(&sentinel_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    evt->pid = pid;
    evt->ppid = 0;
    evt->uid = uid;
    evt->event_type = EVENT_BASH;
    evt->timestamp = bpf_ktime_get_ns();
    evt->comm[0] = 'b';
    evt->comm[1] = 'a';
    evt->comm[2] = 's';
    evt->comm[3] = 'h';
    evt->comm[4] = '\0';
    evt->parent_comm[0] = '\0';

    // 读用户输入
    long ret = bpf_probe_read_user_str(evt->data, 256, line);
    if (ret < 0) {
        evt->data[0] = '\0';
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

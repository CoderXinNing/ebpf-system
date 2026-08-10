// SPDX-License-Identifier: GPL-2.0
// uretprobe挂bash readline——捕获所有终端输入（包括内置命令）
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct bash_event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    char comm[16];
    char line[256];    // 用户输入的完整行
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("uretprobe/bash_readline")
int bash_readline(struct pt_regs *ctx)
{
    struct bash_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    evt->timestamp = bpf_ktime_get_ns();
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    // readline的返回值在rax寄存器，是指向输入字符串的指针
    char *line = (char *)ctx->ax;
    bpf_probe_read_user_str(evt->line, sizeof(evt->line), line);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

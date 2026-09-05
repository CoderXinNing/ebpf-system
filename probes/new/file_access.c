// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "sentinel_common.h"
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// ============================================
// 敏感文件路径前缀（可在 Go 端动态更新）
// ============================================
#define MAX_PATH_LEN 256

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *args) {
    // 1. 读取文件路径（第二个参数）
    const char *filename = (const char *)args->args[1];
    if (!filename) {
        return 0;  // NULL 保护
    }

    // 2. 读取进程信息
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // 3. ring buffer 动态分配
    struct sentinel_event_header *evt;
    evt = bpf_ringbuf_reserve(&sentinel_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    evt->pid = pid;
    evt->ppid = 0;
    evt->uid = uid;
    evt->event_type = 5;  // EVENT_FILE
    evt->timestamp = bpf_ktime_get_ns();

    // 读进程名
    bpf_get_current_comm(evt->comm, 16);
    evt->parent_comm[0] = '\0';

    // 读文件路径
    long ret = bpf_probe_read_user_str(evt->data, 256, filename);
    if (ret < 0) {
        evt->data[0] = '\0';
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

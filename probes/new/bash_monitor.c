// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "sentinel_common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// ============================================
// uprobe 挂载（bash readline 返回）
// 监控交互式命令输入
// ============================================
SEC("uretprobe/readline")
int trace_readline(struct pt_regs *ctx) {
    // 1. 获取基本信息
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // 2. 读取进程名
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    // 3. 只监控 bash（其他进程也可能用 readline，但当前聚焦 bash）
    if (comm[0] != 'b' || comm[1] != 'a' || comm[2] != 's' || comm[3] != 'h') {
        return 0;
    }

    // 4. 白名单过滤
    __u8 *allowed = bpf_map_lookup_elem(&sentinel_whitelist, comm);
    if (allowed && *allowed == 1) {
        return 0;
    }

    // 5. 读取返回值（readline 的返回字符串在 RAX 寄存器）
    const char *line = (const char *)ctx->ax;
    if (!line) {
        return 0;  // NULL 保护
    }

    // 6. 提交事件
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
    sentinel_strncpy(evt->comm, comm, sizeof(evt->comm));
    evt->parent_comm[0] = '\0';

    // 读取命令行输入（最多 256 字节）
    bpf_probe_read_user_str(evt->data, 256, line);
    evt->data[255] = '\0';

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

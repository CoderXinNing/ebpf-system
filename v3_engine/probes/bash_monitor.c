// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "sentinel_common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// bash 探针独立 Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} bash_events SEC(".maps");

// ============================================
// uretprobe 挂载（bash readline 返回）
// ============================================
SEC("uretprobe/readline")
int trace_readline(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u64 now = bpf_ktime_get_ns();

    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    // 只监控 bash
    if (comm[0] != 'b' || comm[1] != 'a' || comm[2] != 's' || comm[3] != 'h') {
        return 0;
    }

    // 白名单过滤
    __u64 whitelist_enabled = get_config_value(CONFIG_WHITELIST_ENABLED);
    if (whitelist_enabled == 1) {
        __u8 *allowed = bpf_map_lookup_elem(&sentinel_whitelist, comm);
        if (allowed && *allowed == 1) {
            return 0;
        }
    }

    // 读取返回值（readline 返回字符串在 AX 寄存器）
    const char *line = (const char *)PT_REGS_RC(ctx);
    if (!line) {
        return 0;
    }

    // 分配事件
    struct sentinel_event_header *evt;
    evt = bpf_ringbuf_reserve(&bash_events, sizeof(struct sentinel_event_header), 0);
    if (!evt) {
        return 0;
    }

    evt->pid = pid;
    evt->ppid = 0;
    evt->uid = uid;
    evt->event_type = EVENT_BASH;
    evt->timestamp = now;
    sentinel_strncpy(evt->comm, comm, sizeof(evt->comm));
    evt->parent_comm[0] = '\0';

    // 读取命令行输入
    __builtin_memset(evt->data, 0, sizeof(evt->data));
    bpf_probe_read_user_str(evt->data, 256, line);
    evt->data[255] = '\0';
    
    // 过滤空命令
    if (evt->data[0] == '\0') {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }
    
    // 过滤空命令
    if (evt->data[0] == '\0') {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    // correlation_key
    evt->correlation_key = make_correlation_key(pid);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

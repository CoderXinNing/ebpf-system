// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "sentinel_common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// file_access 独立 Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} file_events SEC(".maps");

// ============================================
// 敏感路径前缀匹配（C 层快速过滤）
// ============================================
static __always_inline int is_sensitive_path(const char *filename) {
    if (!filename) return 0;
    
    // 敏感路径前缀列表（可后续改为 Map 动态下发）
    static const char *sensitive_prefixes[] = {
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
        "/root/.ssh",
        "/home/",
        "/var/log/auth",
    };
    
    char path[64] = {};
    bpf_probe_read_user_str(path, 64, filename);
    
    for (int i = 0; i < 7; i++) {
        int matched = 1;
        for (int j = 0; j < 64; j++) {
            if (sensitive_prefixes[i][j] == '\0') break;
            if (path[j] != sensitive_prefixes[i][j]) {
                matched = 0;
                break;
            }
        }
        if (matched) return 1;
    }
    return 0;
}

// ============================================
// tracepoint 挂载（sys_enter_openat）
// ============================================
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *args) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u64 now = bpf_ktime_get_ns();

    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    // 白名单过滤
    __u64 whitelist_enabled = get_config_value(CONFIG_WHITELIST_ENABLED);
    if (whitelist_enabled == 1) {
        __u8 *allowed = bpf_map_lookup_elem(&sentinel_whitelist, comm);
        if (allowed && *allowed == 1) {
            return 0;
        }
    }

    // 读取文件名（openat 的第二个参数）
    const char *filename = (const char *)args->args[1];
    if (!filename) {
        return 0;
    }

    // 敏感路径过滤
    if (!is_sensitive_path(filename)) {
        return 0;
    }

    // 分配事件
    struct sentinel_event_header *evt;
    evt = bpf_ringbuf_reserve(&file_events, sizeof(struct sentinel_event_header), 0);
    if (!evt) {
        return 0;
    }

    // 填充事件头
    evt->pid = pid;
    evt->ppid = 0;
    evt->uid = uid;
    evt->event_type = EVENT_FILE;
    evt->timestamp = now;
    sentinel_strncpy(evt->comm, comm, sizeof(evt->comm));
    evt->parent_comm[0] = '\0';

    // 文件名
    __builtin_memset(evt->data, 0, sizeof(evt->data));
    bpf_probe_read_user_str(evt->data, 256, filename);
    evt->data[255] = '\0';

    // correlation_key
    evt->correlation_key = make_correlation_key(pid);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

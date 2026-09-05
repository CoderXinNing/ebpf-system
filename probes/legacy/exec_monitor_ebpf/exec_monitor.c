// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "../alert_common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct exec_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char comm[16];
    char filename[128];   // 完整命令行（argv拼接）
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[16]);
    __type(value, __u8);
} exec_whitelist SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    char comm[16] __attribute__((aligned(8)));
    bpf_get_current_comm(&comm, sizeof(comm));
    
    if (bpf_map_lookup_elem(&exec_whitelist, &comm)) {
        return 0;
    }

    // 心跳检测
    if (agent_is_dead()) {
        struct alert_event alert = {};
        alert.pid = bpf_get_current_pid_tgid() >> 32;
        alert.event_type = 1;
        alert.timestamp = bpf_ktime_get_ns();
        __builtin_memcpy(alert.comm, comm, sizeof(comm));
        
        __u64 argv_u64 = ctx->args[1];
        const char **argv = (const char **)argv_u64;
        if (argv) {
            // 读取 argv[0]（程序名）和 argv[1]（第一个参数）
            const char *arg0;
            bpf_probe_read_user(&arg0, sizeof(arg0), &argv[0]);
            if (arg0) {
                bpf_probe_read_user_str(alert.details, sizeof(alert.details), arg0);
            }
            // 拼接第一个参数
            const char *arg1;
            bpf_probe_read_user(&arg1, sizeof(arg1), &argv[1]);
            if (arg1) {
                int len = bpf_probe_read_user_str(alert.details + 64, 32, arg1);
                if (len > 0) {
                    alert.details[63] = ' ';
                }
            }
        }
        
        alert_push(&alert);
        return 0;
    }

    // 正常：写 ring buffer
    struct exec_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ppid = (bpf_get_current_pid_tgid() << 32) >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __builtin_memcpy(event->comm, comm, sizeof(event->comm));

    // 先清零缓冲区
    __builtin_memset(event->filename, 0, sizeof(event->filename));
    // 读 argv[0]（完整程序路径）
    __u64 argv_u64 = ctx->args[0];
    const char *filename_ptr = (const char *)argv_u64;
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename_ptr);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

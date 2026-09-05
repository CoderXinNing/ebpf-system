// SPDX-License-Identifier: GPL-2.0
#ifndef __SENTINEL_COMMON_H__
#define __SENTINEL_COMMON_H__

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ============================================
// 事件类型枚举（避免字符串比较，提升内核态性能）
// ============================================
#define EVENT_EXEC  1   // 进程启动
#define EVENT_BASH  2   // 交互命令
#define EVENT_TCP   3   // 外联连接
#define EVENT_XDP   4   // XDP 保底事件

// ============================================
// 统一事件头（packed 防止内存对齐错位）
// 总大小: 4+4+4+4+8+16+1024 = 1064 字节
// ============================================
struct sentinel_event_header {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 event_type;
    __u64 timestamp;
    char comm[16];
    char parent_comm[16];  // 父进程名（星轨支持）
    char data[256];        // 载荷（控制在 256 字节，避免栈溢出）
} __attribute__((packed));

// ============================================
// 共用 Ring Buffer（所有探针统一输出到这里）
// ============================================
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);  // 512KB
} sentinel_events SEC(".maps");

// ============================================
// 动态白名单 LRU Hash（规则下发，避免普通 HASH 的跨 CPU 锁竞争）
// ============================================
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, char[64]);
    __type(value, __u8);   // 1=允许 0=禁止
} sentinel_whitelist SEC(".maps");

// ============================================
// 心跳 Map（Agent 存活检测）
// ============================================
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sentinel_heartbeat SEC(".maps");

// ============================================
// 内核态安全推送函数（带 NULL 检查和长度校验）
// ============================================
static __always_inline int sentinel_push_event(struct sentinel_event_header *evt) {
    if (!evt) {
        return -1;  // NULL 指针保护
    }

    // 强制 NULL 终止，防止字符串越界
    evt->comm[15] = '\0';
    evt->data[255] = '\0';

    // 提交到 ring buffer
    long ret = bpf_ringbuf_output(&sentinel_events, evt, sizeof(*evt), 0);
    if (ret != 0) {
        return -1;  // ring buffer 满或失败
    }
    return 0;
}

// ============================================
// 安全字符串拷贝（限制长度，防越界）
// ============================================
static __always_inline void sentinel_strncpy(char *dst, const char *src, __u32 max_len) {
    if (!dst || !src) {
        return;  // NULL 保护
    }
    bpf_probe_read_kernel_str(dst, max_len, src);
    dst[max_len - 1] = '\0';  // 强制终止
}

#endif // __SENTINEL_COMMON_H__

// SPDX-License-Identifier: GPL-2.0
#ifndef SENTINEL_COMMON_H
#define SENTINEL_COMMON_H

#include <bpf/bpf_helpers.h>

// ============================================
// V3 统一事件头（304 字节，packed）
// 严禁修改前序字节偏移
// ============================================
struct sentinel_event_header {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 event_type;      // 1=exec 2=bash 3=tcp 4=xdp 5=file 6=dns
    __u64 timestamp;
    char comm[16];
    char parent_comm[16];
    char data[256];
    __u64 correlation_key; // (agent_hash << 32) | pid
} __attribute__((packed));

// ============================================
// 事件类型枚举
// ============================================
#define EVENT_EXEC  1
#define EVENT_BASH  2
#define EVENT_TCP   3
#define EVENT_XDP   4
#define EVENT_FILE  5
#define EVENT_DNS   6

// ============================================
// Config Map 统一配置枚举
// ============================================
enum config_key {
    CONFIG_COLLECT_MODE = 0,      // 采集模式：0=计数，1=明细
    CONFIG_WHITELIST_ENABLED = 1, // 白名单开关
    CONFIG_MAX_ENTRIES = 2,       // 最大连接数阈值
    CONFIG_AGENT_HASH = 3,        // Agent 哈希值
    CONFIG_OBSERVATION_LEVEL = 4, // 观察等级：0=PASSIVE, 1=REDUCED, 2=FULL
};

// 观察等级
#define OBS_PASSIVE  0
#define OBS_REDUCED  1
#define OBS_FULL     2

// ============================================
// Config Map 定义（所有探针统一使用）
// ============================================
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} config_map SEC(".maps");

// ============================================
// TCP 专有结构体（20 字节，内联进 data[256]）
// ============================================
struct tcp_conn_detail {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 padding[3];
} __attribute__((packed));

// ============================================
// 通用白名单 Map（所有探针共用）
// ============================================
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, char[16]);
    __type(value, __u8);
} sentinel_whitelist SEC(".maps");

// ============================================
// 敏感路径动态规则（file_access 使用）
//
// 双 map 设计原因：
//   LPM_TRIE 的 prefixlen 是"要求查询串至少有这么多位"。
//   精确路径 "/etc/shadow"（11字节）若存为含 \0 的 96 位前缀，
//   查询时只有 88 位 → 永远匹配不上 → 漏报。
//   故精确匹配用 HASH，前缀匹配用 LPM_TRIE。
// ============================================

// 精确匹配（用户选"监控文件"）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[256]);
    __type(value, __u8);
} sensitive_exact SEC(".maps");

// 前缀匹配（用户选"监控目录"，路径以 / 结尾）
struct lpm_path_key {
    __u32 prefixlen;   // 前缀 bit 数（path_len * 8）
    char  path[256];   // 路径
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_path_key);
    __type(value, __u8);
} sensitive_prefixes SEC(".maps");

// ============================================
// Ring Buffer（所有探针共用）
// ============================================
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024); // 512KB
} sentinel_events SEC(".maps");

// ============================================
// 工具函数：安全字符串复制
// ============================================
static __always_inline void sentinel_strncpy(char *dst, const char *src, __u32 len) {
    if (!dst || !src) return;
    bpf_probe_read_kernel_str(dst, len, src);
    dst[len - 1] = '\0';
}

// ============================================
// 工具函数：读取 config_map 值（优雅降级）
// ============================================
static __always_inline __u64 get_config_value(__u32 key) {
    __u64 *value = bpf_map_lookup_elem(&config_map, &key);
    if (value) {
        return *value;
    }
    return 0; // 优雅降级：Map 未初始化时返回 0
}

// ============================================
// 工具函数：生成 correlation_key
// ============================================
static __always_inline __u64 make_correlation_key(__u32 pid) {
    __u64 agent_hash = get_config_value(CONFIG_AGENT_HASH);
    if (agent_hash == 0) {
        return 0; // 优雅降级
    }
    __u32 hash = (__u32)(agent_hash & 0xFFFFFFFF);
    return ((__u64)hash << 32) | pid;
}

#endif // SENTINEL_COMMON_H

// SPDX-License-Identifier: GPL-2.0
#ifndef __ALERT_COMMON_H__
#define __ALERT_COMMON_H__

#include <bpf/bpf_helpers.h>

#define ALERT_MAGIC    0xEB9F
#define ALERT_BUF_SIZE 16
#define HEARTBEAT_TIMEOUT_NS 3000000000  // 3秒

struct alert_event {
    __u32 pid;
    __u32 event_type;
    __u64 timestamp;
    char comm[16];
    char details[96];
};

// 环形缓冲区
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, ALERT_BUF_SIZE);
    __type(key, __u32);
    __type(value, struct alert_event);
} alert_buffer SEC(".maps");

// 写入计数
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} alert_write_cnt SEC(".maps");

// 心跳时间戳（Go 端每 1 秒更新）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} agent_heartbeat SEC(".maps");

// 探针调用：写入告警
static __always_inline void alert_push(struct alert_event *evt) {
    __u32 key = 0;
    __u32 *cnt = bpf_map_lookup_elem(&alert_write_cnt, &key);
    if (!cnt) return;
    
    __u32 idx = *cnt % ALERT_BUF_SIZE;
    __sync_fetch_and_add(cnt, 1);
    
    bpf_map_update_elem(&alert_buffer, &idx, evt, BPF_ANY);
}

// 检查 Agent 是否失联（探针调用）
static __always_inline int agent_is_dead(void) {
    __u32 key = 0;
    __u64 *hb = bpf_map_lookup_elem(&agent_heartbeat, &key);
    if (!hb) return 0;
    if (*hb == 0) return 0;  // 还没初始化
    
    __u64 now = bpf_ktime_get_ns();
    if (now - *hb > HEARTBEAT_TIMEOUT_NS) {
        return 1;
    }
    return 0;
}

#endif

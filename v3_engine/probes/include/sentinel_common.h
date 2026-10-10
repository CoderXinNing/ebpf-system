// SPDX-License-Identifier: GPL-2.0
#ifndef SENTINEL_COMMON_H
#define SENTINEL_COMMON_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

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
    CONFIG_EXCLUDE_COMMS = 1, // 排除名单开关
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
} sentinel_exclude_comms SEC(".maps");

// ============================================
// TCP IP 排除名单（LPM_TRIE，支持 CIDR）
//
// 命名：sentinel_xip（短名），因内核 BPF map 名上限 15 字符，
//       sentinel_exclude_ips 会截成 sentinel_exclud，与上面撞名。
//       bpftool 调试时靠 ID 区分。
// 用途：tcp 探针独立 IP 维度排除（comm 维度对 tcp 无意义）
// ============================================

struct lpm_ip_key {
    __u32 prefixlen;   // CIDR 位数（0-32），0 表示匹配所有
    __u32 ip;          // 网络字节序 IPv4
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_ip_key);
    __type(value, __u8);
} sentinel_xip SEC(".maps");

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
// 命令排除（exec + bash 使用，v3 新增）
//
// 双 map 设计（与 sensitive_exact/prefixes 对齐）：
//   sentinel_xcmd_e: 精确匹配命令（HASH）
//   sentinel_xcmd_p: 前缀匹配命令（LPM_TRIE）
//
// 语义：
//   exec 侧命令 = argv[0]（可执行文件路径）
//   bash 侧命令 = readline 返回的用户输入
//
// ⚠️ 长度上限 255 字符（双重锁死）：
//   1. 事件头 data[256]，探针读取时 bpf_probe_read_user_str(_, 256, _)
//      超过 255 的部分在进 Map 之前就被截断
//   2. Map key 为 char[256]，规则写入时同样按 255 截断
//   → 超长命令的"精确匹配"本质失效，只能匹配前 255 字符
//   → 超长且变化多的命令请改用前缀匹配，或交给 Go 层做关键字包含
//
// 命名说明：内核 BPF map 名上限 15 字符。
//   sentinel_xcmd_exact  → 超限，故用 sentinel_xcmd_e
//   sentinel_xcmd_prefix → 超限，故用 sentinel_xcmd_p
// ============================================
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[256]);
    __type(value, __u8);
} sentinel_xcmd_e SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_path_key);
    __type(value, __u8);
} sentinel_xcmd_p SEC(".maps");

// ============================================
// TCP 进程/组合维度排除（v3 新增）
//
// sentinel_xcomm: 按 comm 排除（HASH）
//   语义：排除某进程发起的全部外联
//
// sentinel_xcombo: 按 (comm, ip) 组合排除（HASH）
//   语义：精确排除"进程 X 访问 IP Y"
//   key 布局：comm[16] + ip[4]（网络字节序），packed = 20 字节
//   限制：不支持 CIDR（组合查询固定精确匹配）
//   与 sentinel_xip 独立并存，任意命中即排除
//
// 命名说明：sentinel_xcomm 恰好 14 字符，未超限。
// ============================================
struct xcombo_key {
    char  comm[16];
    __u32 ip;      // 网络字节序 IPv4
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[16]);
    __type(value, __u8);
} sentinel_xcomm SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct xcombo_key);
    __type(value, __u8);
} sentinel_xcombo SEC(".maps");

// ============================================
// 命令排除判断（exec + bash 共用）
//
// 语义：
//   精确匹配 sentinel_xcmd_e → 命中
//   前缀匹配 sentinel_xcmd_p → 命中
//   任一命中即返回 1（调用方自行 return）
//
// 注意：
//   - 255 字符上限（事件头与 map key 双重限制）
//   - 前缀查询给最大 prefixlen（256*8），内核自动最长匹配
//   - 前缀规则写入时必须用实际长度（见 Go 侧 makeLPMKey）
// ============================================
static __always_inline int is_excluded_cmdline(const char *cmdline) {
    if (!cmdline) return 0;

    struct lpm_path_key key = {};
    long n = bpf_probe_read_user_str(key.path, sizeof(key.path), cmdline);
    if (n <= 0) return 0;
    key.path[255] = '\0';

    // 1. 精确匹配（HASH）
    __u8 *exact = bpf_map_lookup_elem(&sentinel_xcmd_e, key.path);
    if (exact && *exact == 1) return 1;

    // 2. 前缀匹配（LPM_TRIE）
    key.prefixlen = sizeof(key.path) * 8;
    __u8 *prefix = bpf_map_lookup_elem(&sentinel_xcmd_p, &key);
    if (prefix && *prefix == 1) return 1;

    return 0;
}



// ============================================
// Agent 自身进程树标记（P1.9）
//
// 用途：过滤 Agent 自身行为产生的噪声
// 生命周期：Agent 启动写自己 pid → fork hook 传播子进程 → exit hook 清理
// PID 复用防护：exit hook 移除，避免 pid 被攻击者复用后误过滤
// ============================================
// pid_key 复合键：pid + 启动时间（防 PID 复用）
// 对齐说明：packed，12 字节。Go 侧 binary.Write 也是紧凑序列化，匹配。
struct pid_key {
    __u32 pid;
    __u64 start_time_ticks;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct pid_key);
    __type(value, __u8);  // 1 = agent tree
} agent_pids SEC(".maps");

// read_task_pid_starttime 从 task_struct 读 pid + start_time（统一到 ticks）
//
// ⚠️ 精度说明：
//   task->start_time 是 ns（精确）
//   /proc/<pid>/stat 第 22 字段是 ticks
//   两边统一用 ticks。HZ=100 时 1 tick = 10000000 ns
static __always_inline void read_task_pid_starttime(struct task_struct *task,
                                                     __u32 *pid, __u64 *st_ticks) {
    *pid = 0;
    *st_ticks = 0;
    if (!task) return;
    bpf_core_read(pid, sizeof(*pid), &task->pid);
    __u64 st_ns = 0;
    bpf_core_read(&st_ns, sizeof(st_ns), &task->start_time);
    *st_ticks = st_ns / 10000000ULL;
}

// is_agent_tree_task 判断 task 是否在 agent_pids 里
static __always_inline int is_agent_tree_task(struct task_struct *task) {
    __u32 pid = 0;
    __u64 st = 0;
    read_task_pid_starttime(task, &pid, &st);
    if (pid == 0) return 0;

    struct pid_key key = {.pid = pid, .start_time_ticks = st};
    __u8 *v = bpf_map_lookup_elem(&agent_pids, &key);
    return v && *v == 1;
}

// is_agent_tree 判断当前 pid 是否在 agent_pids 里
static __always_inline int is_agent_tree(__u32 pid) {
    if (pid == 0) return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;
    return is_agent_tree_task(task);
}

// is_agent_tree_parent 判断当前进程的父进程 ppid 是否在 agent_pids 里
static __always_inline int is_agent_tree_parent(__u32 ppid) {
    if (ppid == 0) return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    struct task_struct *parent = NULL;
    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    if (!parent) return 0;

    __u32 parent_pid = 0;
    __u64 parent_st = 0;
    read_task_pid_starttime(parent, &parent_pid, &parent_st);
    if (parent_pid != ppid) return 0;

    struct pid_key key = {.pid = parent_pid, .start_time_ticks = parent_st};
    __u8 *v = bpf_map_lookup_elem(&agent_pids, &key);
    return v && *v == 1;
}

// add_current_to_agent_tree 把当前进程加入 agent_pids
static __always_inline void add_current_to_agent_tree(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return;
    __u32 pid = 0;
    __u64 st = 0;
    read_task_pid_starttime(task, &pid, &st);
    if (pid == 0) return;

    struct pid_key key = {.pid = pid, .start_time_ticks = st};
    __u8 v = 1;
    bpf_map_update_elem(&agent_pids, &key, &v, BPF_ANY);
}


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

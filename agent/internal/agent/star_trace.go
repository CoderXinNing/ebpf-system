package agent

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// StarTrace 星轨追踪上下文。
//
// 语义（重要，改前读）：
//   - 从触发进程 rootPid 出发，追踪：
//     向上：5 层祖先（激活时一次性算好，避免串到 systemd）
//     向下：rootPid 的所有子孙（通过 pidToPPid 实时推导）
//   - 只有命中"追踪集合"的事件才打 star 的 corrID，避免全机快照。
//
// 线程安全：
//   - Ancestors 激活后只读，无需锁
//   - pidToPPid 会被 exec 事件实时更新 + 周期 /proc 修正，加 treeMu
type StarTrace struct {
	CorrID    string
	RootPid   uint32
	Ancestors map[uint32]bool // 向上 5 层祖先（静态，激活时确定）
	StartAt   time.Time
	EndAt     time.Time

	treeMu    sync.RWMutex
	pidToPPid map[uint32]uint32 // Go 侧进程树（exec 事件实时更新 + /proc 定期修正）
}

// NewStarTrace 创建星轨追踪上下文
func NewStarTrace(corrID string, rootPid uint32, ancestors map[uint32]bool, ttl time.Duration) *StarTrace {
	if ttl <= 0 {
		ttl = StarTTL
	}
	now := time.Now()
	return &StarTrace{
		CorrID:    corrID,
		RootPid:   rootPid,
		Ancestors: ancestors,
		StartAt:   now,
		EndAt:     now.Add(ttl),
		pidToPPid: make(map[uint32]uint32),
	}
}

// IsExpired 星轨是否过期
func (st *StarTrace) IsExpired() bool {
	return time.Now().After(st.EndAt)
}

// Extend 延长星轨 TTL
func (st *StarTrace) Extend(d time.Duration) {
	st.EndAt = time.Now().Add(d)
}

// UpdateParent 更新进程树（exec 事件调用）
func (st *StarTrace) UpdateParent(pid, ppid uint32) {
	st.treeMu.Lock()
	st.pidToPPid[pid] = ppid
	st.treeMu.Unlock()
}

// RemovePid 移除已退出进程（防止 pid 复用导致误判）
func (st *StarTrace) RemovePid(pid uint32) {
	st.treeMu.Lock()
	delete(st.pidToPPid, pid)
	st.treeMu.Unlock()
}

// Matches 判断 pid 是否属于本星轨的追踪集合。
//
// 逻辑（严格）：
//  1. pid == RootPid → 命中
//  2. pid 向上追最多 10 层，路径上遇到 RootPid → 命中
//
// ⚠️ Ancestors 不参与匹配。
// 原因：Ancestors 含高 fan-out 祖先（如 systemd --user）时，
//
//	祖先的所有后代（兄弟分支）会被误判为星轨成员 → 全机快照。
//
// Ancestors 仅作攻击链展示标签，不参与过滤。
//
// 性能：纯 Go map 查找。典型 < 1μs。
func (st *StarTrace) Matches(pid uint32) bool {
	if pid == 0 {
		return false
	}
	if pid == st.RootPid {
		return true
	}

	st.treeMu.RLock()
	cur := pid
	hit := false
	for depth := 0; depth < 10; depth++ {
		ppid, ok := st.pidToPPid[cur]
		if !ok {
			break
		}
		if ppid == 0 || ppid == cur {
			break
		}
		if ppid == st.RootPid {
			hit = true
			break
		}
		cur = ppid
	}
	st.treeMu.RUnlock()
	return hit
}

// RebuildFromProc 从 /proc 扫描重建进程树（修正 exec 事件遗漏）
func (st *StarTrace) RebuildFromProc() error {
	newMap, err := LoadFullPidTree()
	if err != nil {
		return err
	}
	st.treeMu.Lock()
	st.pidToPPid = newMap
	st.treeMu.Unlock()
	return nil
}

// LoadFullPidTree 从 /proc 加载完整 pid→ppid 映射。
// 用于：(1) 激活时算 ancestors；(2) 周期修正 StarTrace。
func LoadFullPidTree() (map[uint32]uint32, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("读取 /proc 失败: %w", err)
	}
	result := make(map[uint32]uint32, len(entries))
	for _, e := range entries {
		pid64, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		statusPath := fmt.Sprintf("/proc/%s/status", e.Name())
		f, err := os.Open(statusPath)
		if err != nil {
			continue
		}
		ppid := parsePPidFromStatus(f)
		f.Close()
		if ppid > 0 {
			result[uint32(pid64)] = ppid
		}
	}
	return result, nil
}

// parsePPidFromStatus 从 /proc/<pid>/status 解析 PPid 字段
func parsePPidFromStatus(f *os.File) uint32 {
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PPid:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				v, err := strconv.ParseUint(parts[1], 10, 32)
				if err == nil {
					return uint32(v)
				}
			}
			return 0
		}
	}
	return 0
}

// BuildAncestors 向上追溯 5 层祖先（激活时调用）
func BuildAncestors(rootPid uint32, pidToPPid map[uint32]uint32) map[uint32]bool {
	ancestors := make(map[uint32]bool)
	cur := rootPid
	for depth := 0; depth < 5; depth++ {
		ppid, ok := pidToPPid[cur]
		if !ok {
			break
		}
		if ppid == 0 || ppid == cur {
			break
		}
		ancestors[ppid] = true
		cur = ppid
	}
	return ancestors
}

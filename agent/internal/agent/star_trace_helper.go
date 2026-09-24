package agent

import (
	"context"
	"encoding/json"
	"log"
	"time"
)

// currentStarCorrID 非阻塞读当前星轨 ID（无星轨返回空）
func (a *Agent) currentStarCorrID() string {
	a.starMu.RLock()
	defer a.starMu.RUnlock()
	if a.activeStar == nil {
		return ""
	}
	return a.activeStar.CorrID
}

// hasActiveStar 是否有活跃星轨
func (a *Agent) hasActiveStar() bool {
	a.starMu.RLock()
	defer a.starMu.RUnlock()
	return a.activeStar != nil
}

// determineCorrID 决定事件应该打的 corrID。
//
// 规则：
//  1. 有活跃星轨 且 pid 命中追踪集合 → 打星轨 ID
//  2. 否则 → 走默认逻辑（correlationManager）
func (a *Agent) determineCorrID(pid uint32, correlationKey uint64) string {
	a.starMu.RLock()
	st := a.activeStar
	a.starMu.RUnlock()

	if st != nil && st.Matches(pid) {
		return st.CorrID
	}
	if correlationKey != 0 && a.correlationManager != nil {
		return a.correlationManager.GetOrCreate(correlationKey)
	}
	return ""
}

// activateStar 激活星轨（由 heartbeat 收到命令时调用）
//
// payload 格式：{"corr_id":"...","root_pid":12345}
func (a *Agent) activateStar(payload string) {
	var cfg struct {
		CorrID  string `json:"corr_id"`
		RootPid uint32 `json:"root_pid"`
	}
	if err := json.Unmarshal([]byte(payload), &cfg); err != nil {
		log.Printf("⚠️ 星轨激活 payload 解析失败: %v (payload=%s)", err, payload)
		return
	}
	if cfg.CorrID == "" || cfg.RootPid == 0 {
		log.Printf("⚠️ 星轨激活参数无效: corrID=%q rootPid=%d", cfg.CorrID, cfg.RootPid)
		return
	}

	// 从 /proc 重建进程树，算 ancestors
	pidTree, err := LoadFullPidTree()
	if err != nil {
		log.Printf("⚠️ 加载进程树失败: %v（ancestors 为空）", err)
		pidTree = make(map[uint32]uint32)
	}
	ancestors := BuildAncestors(cfg.RootPid, pidTree)

	st := NewStarTrace(cfg.CorrID, cfg.RootPid, ancestors, 10*time.Minute)
	st.pidToPPid = pidTree

	a.starMu.Lock()
	a.activeStar = st
	a.starMu.Unlock()

	log.Printf("⭐ 星轨激活: corr=%s root_pid=%d ancestors=%d个",
		cfg.CorrID, cfg.RootPid, len(ancestors))
}

// checkStarExpire 检查星轨是否到期，到期则清空
func (a *Agent) checkStarExpire() {
	a.starMu.Lock()
	defer a.starMu.Unlock()
	if a.activeStar == nil {
		return
	}
	if a.activeStar.IsExpired() {
		log.Printf("⭐ 星轨到期: corr=%s", a.activeStar.CorrID)
		a.activeStar = nil
	}
}

// extendStar 延长当前星轨（Server 手动延长时调用）
func (a *Agent) extendStar(d time.Duration) {
	a.starMu.Lock()
	defer a.starMu.Unlock()
	if a.activeStar == nil {
		return
	}
	a.activeStar.Extend(d)
	log.Printf("⭐ 星轨延长: corr=%s 到期=%s",
		a.activeStar.CorrID, a.activeStar.EndAt.Format(time.RFC3339))
}

// rebuildStarPidTree 周期从 /proc 修正进程树（exec 事件可能遗漏）
func (a *Agent) rebuildStarPidTree() {
	a.starMu.RLock()
	st := a.activeStar
	a.starMu.RUnlock()
	if st == nil {
		return
	}
	if err := st.RebuildFromProc(); err != nil {
		log.Printf("⚠️ 星轨进程树重建失败: %v", err)
	}
}

// starRebuildLoop 周期修正星轨进程树（每 60 秒）
func (a *Agent) starRebuildLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.rebuildStarPidTree()
		}
	}
}

// updateStarPidTree exec 事件时更新进程树（供 StarTrace.Matches 使用）
func (a *Agent) updateStarPidTree(pid, ppid uint32) {
	a.starMu.RLock()
	st := a.activeStar
	a.starMu.RUnlock()
	if st != nil {
		st.UpdateParent(pid, ppid)
	}
}

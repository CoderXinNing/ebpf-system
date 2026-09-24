package agent

import (
	"context"
	"encoding/json"
	"log"
	"time"
)

// currentStarCorrID 返回任意一个活跃星轨 ID（兼容 flushEvents 的单值字段）
// 注：flushEvents 的 CorrelationId 是旧字段，多星轨下语义弱化，保留兼容
func (a *Agent) currentStarCorrID() string {
	a.starsMu.RLock()
	defer a.starsMu.RUnlock()
	for id := range a.stars {
		return id
	}
	return ""
}

// hasActiveStar 是否有任意活跃星轨
func (a *Agent) hasActiveStar() bool {
	a.starsMu.RLock()
	defer a.starsMu.RUnlock()
	return len(a.stars) > 0
}

// determineCorrID 决定事件应该打的 corrID。
//
// 规则（多星轨）：
//  1. 遍历所有活跃星轨，第一个命中追踪集合的 → 返回其 corrID
//  2. 都未命中 → 走默认 correlationManager 逻辑
//
// 说明：一个事件理论上可能命中多个星轨（进程树交叉），当前实现只取第一个。
// 若未来需要"一个事件打多个 corrID"，扩展 ProbeEvent 的 CorrelationId 为数组。
func (a *Agent) determineCorrID(pid uint32, correlationKey uint64) string {
	a.starsMu.RLock()
	for _, st := range a.stars {
		if st.Matches(pid) {
			a.starsMu.RUnlock()
			return st.CorrID
		}
	}
	a.starsMu.RUnlock()

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

	a.starsMu.Lock()
	// 容量控制：达到上限先清最旧的
	if len(a.stars) >= MaxActiveStars {
		var oldestID string
		var oldestTime time.Time
		for id, s := range a.stars {
			if oldestID == "" || s.StartAt.Before(oldestTime) {
				oldestID = id
				oldestTime = s.StartAt
			}
		}
		if oldestID != "" {
			log.Printf("⚠️ 星轨数达上限 %d，淘汰最旧: %s", MaxActiveStars, oldestID)
			delete(a.stars, oldestID)
		}
	}
	a.stars[cfg.CorrID] = st
	count := len(a.stars)
	a.starsMu.Unlock()

	log.Printf("⭐ 星轨激活: corr=%s root_pid=%d ancestors=%d个 (活跃=%d)",
		cfg.CorrID, cfg.RootPid, len(ancestors), count)
}

// checkStarExpire 遍历所有星轨，清理到期的
func (a *Agent) checkStarExpire() {
	a.starsMu.Lock()
	defer a.starsMu.Unlock()
	now := time.Now()
	for id, st := range a.stars {
		if now.After(st.EndAt) {
			log.Printf("⭐ 星轨到期: corr=%s", id)
			delete(a.stars, id)
		}
	}
}

// extendStar 延长指定星轨（Server 手动延长时调用）
func (a *Agent) extendStar(corrID string, d time.Duration) {
	a.starsMu.Lock()
	defer a.starsMu.Unlock()
	if st, ok := a.stars[corrID]; ok {
		st.Extend(d)
		log.Printf("⭐ 星轨延长: corr=%s 到期=%s", corrID, st.EndAt.Format(time.RFC3339))
	}
}

// rebuildStarPidTree 遍历所有星轨，从 /proc 修正进程树
func (a *Agent) rebuildStarPidTree() {
	a.starsMu.RLock()
	stars := make([]*StarTrace, 0, len(a.stars))
	for _, st := range a.stars {
		stars = append(stars, st)
	}
	a.starsMu.RUnlock()

	for _, st := range stars {
		if err := st.RebuildFromProc(); err != nil {
			log.Printf("⚠️ 星轨进程树重建失败 corr=%s: %v", st.CorrID, err)
		}
	}
}

// starRebuildLoop 周期修正星轨进程树（每 60 秒）
func (a *Agent) starRebuildLoop(ctx context.Context) {
	ticker := time.NewTicker(StarRebuildPeriod)
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

// updateStarPidTree exec 事件时更新所有星轨的进程树
func (a *Agent) updateStarPidTree(pid, ppid uint32) {
	a.starsMu.RLock()
	defer a.starsMu.RUnlock()
	for _, st := range a.stars {
		st.UpdateParent(pid, ppid)
	}
}

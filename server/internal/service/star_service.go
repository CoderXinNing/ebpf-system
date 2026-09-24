package service

import (
	"fmt"
	"sync"
	"time"
)

// CorrelationEntry 关联映射条目
type CorrelationEntry struct {
	CorrelationID string
	LastSeen      time.Time
}

// ActiveCorrelationMap 活跃关联映射池（带内存控制）
type ActiveCorrelationMap struct {
	mu      sync.RWMutex
	entries map[string]*CorrelationEntry
	maxSize int
	ttl     time.Duration
}

func NewActiveCorrelationMap(maxSize int, ttl time.Duration) *ActiveCorrelationMap {
	if maxSize <= 0 {
		maxSize = 5000
	}
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &ActiveCorrelationMap{
		entries: make(map[string]*CorrelationEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// GetOrCreate 获取或创建 correlation_id
func (m *ActiveCorrelationMap) GetOrCreate(key string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. 清理过期
	m.cleanupExpired()

	// 2. 已存在 → 复用
	if entry, ok := m.entries[key]; ok {
		entry.LastSeen = time.Now()
		return entry.CorrelationID
	}

	// 3. 容量控制：超出时淘汰最旧
	if len(m.entries) >= m.maxSize {
		m.evictOldest()
	}

	// 4. 生成新 ID
	corrID := fmt.Sprintf("corr_%d", time.Now().UnixNano())
	m.entries[key] = &CorrelationEntry{
		CorrelationID: corrID,
		LastSeen:      time.Now(),
	}
	return corrID
}

func (m *ActiveCorrelationMap) cleanupExpired() {
	now := time.Now()
	for key, entry := range m.entries {
		if now.Sub(entry.LastSeen) > m.ttl {
			delete(m.entries, key)
		}
	}
}

func (m *ActiveCorrelationMap) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	for key, entry := range m.entries {
		if oldestKey == "" || entry.LastSeen.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.LastSeen
		}
	}
	if oldestKey != "" {
		delete(m.entries, oldestKey)
	}
}

// GlobalCorrelationEntry 全局关联条目
type GlobalCorrelationEntry struct {
	GlobalID     string
	LocalCorrIDs map[string]bool // 多个 Agent 的 local_correlation_id
	LastSeen     time.Time
}

// GlobalCorrelationMap 跨主机全局关联池
type GlobalCorrelationMap struct {
	mu      sync.RWMutex
	entries map[string]*GlobalCorrelationEntry // key: 目标IP:端口 或 源IP
	maxSize int
	ttl     time.Duration
}

func NewGlobalCorrelationMap(maxSize int, ttl time.Duration) *GlobalCorrelationMap {
	if maxSize <= 0 {
		maxSize = 1000
	}
	if ttl <= 0 {
		ttl = 120 * time.Second
	}
	return &GlobalCorrelationMap{
		entries: make(map[string]*GlobalCorrelationEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// Merge 合并两个 Agent 的 correlation_id
func (m *GlobalCorrelationMap) Merge(dstIP string, dstPort uint16, localCorrID string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s:%d", dstIP, dstPort)

	if entry, ok := m.entries[key]; ok {
		entry.LocalCorrIDs[localCorrID] = true
		entry.LastSeen = time.Now()
		return entry.GlobalID
	}

	globalID := fmt.Sprintf("global_%d", time.Now().UnixNano())
	m.entries[key] = &GlobalCorrelationEntry{
		GlobalID:     globalID,
		LocalCorrIDs: map[string]bool{localCorrID: true},
		LastSeen:     time.Now(),
	}
	return globalID
}

// CorrPidEntry corrID → (agentID, pid) 反向索引条目
type CorrPidEntry struct {
	AgentID string
	Pid     int32
	SeenAt  time.Time
}

// StarActivationService 星轨激活服务
type StarActivationService struct {
	correlations *ActiveCorrelationMap
	globalMap    *GlobalCorrelationMap

	// corrToPid 反向索引：corrID → 触发进程。用于星轨激活时下发 root_pid
	corrMu    sync.RWMutex
	corrToPid map[string]CorrPidEntry
}

func NewStarActivationService() *StarActivationService {
	return &StarActivationService{
		correlations: NewActiveCorrelationMap(5000, 60*time.Second),
		globalMap:    NewGlobalCorrelationMap(1000, 120*time.Second),
		corrToPid:    make(map[string]CorrPidEntry),
	}
}

// GetGlobalID 查询全局 ID
func (s *StarActivationService) GetGlobalID(dstIP string, dstPort uint16) (string, bool) {
	key := fmt.Sprintf("%s:%d", dstIP, dstPort)
	s.globalMap.mu.RLock()
	defer s.globalMap.mu.RUnlock()
	if entry, ok := s.globalMap.entries[key]; ok {
		return entry.GlobalID, true
	}
	return "", false
}

// MergeGlobal 跨主机合并
func (s *StarActivationService) MergeGlobal(dstIP string, dstPort uint16, localCorrID string) string {
	return s.globalMap.Merge(dstIP, dstPort, localCorrID)
}

// HandleMutation 处理 Agent 上报的突变触发
func (s *StarActivationService) HandleMutation(agentID string, pid int32) string {
	key := fmt.Sprintf("%s:pid_%d", agentID, pid)
	corrID := s.correlations.GetOrCreate(key)

	// 记录反向索引，供下发星轨激活命令时使用（携带 root_pid）
	s.corrMu.Lock()
	s.corrToPid[corrID] = CorrPidEntry{
		AgentID: agentID,
		Pid:     pid,
		SeenAt:  time.Now(),
	}
	// 简单容量控制：超过 5000 条时清理最旧的
	if len(s.corrToPid) > 5000 {
		var oldestKey string
		var oldestTime time.Time
		for k, v := range s.corrToPid {
			if oldestKey == "" || v.SeenAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.SeenAt
			}
		}
		if oldestKey != "" {
			delete(s.corrToPid, oldestKey)
		}
	}
	s.corrMu.Unlock()

	return corrID
}

// GetPid 查询 corrID 对应的触发进程
func (s *StarActivationService) GetPid(corrID string) (agentID string, pid int32, ok bool) {
	s.corrMu.RLock()
	defer s.corrMu.RUnlock()
	v, exists := s.corrToPid[corrID]
	if !exists {
		return "", 0, false
	}
	return v.AgentID, v.Pid, true
}

// GetCorrelationID 查询某 key 的 correlation_id
func (s *StarActivationService) GetCorrelationID(agentID string, pid int32) (string, bool) {
	key := fmt.Sprintf("%s:pid_%d", agentID, pid)
	s.correlations.mu.RLock()
	defer s.correlations.mu.RUnlock()
	if entry, ok := s.correlations.entries[key]; ok {
		return entry.CorrelationID, true
	}
	return "", false
}

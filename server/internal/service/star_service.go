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
	GlobalID      string
	LocalCorrIDs  map[string]bool // 多个 Agent 的 local_correlation_id
	LastSeen      time.Time
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

// StarActivationService 星轨激活服务
type StarActivationService struct {
	correlations *ActiveCorrelationMap
	globalMap    *GlobalCorrelationMap
}

func NewStarActivationService() *StarActivationService {
	return &StarActivationService{
		correlations: NewActiveCorrelationMap(5000, 60*time.Second),
		globalMap:    NewGlobalCorrelationMap(1000, 120*time.Second),
	}
}

// MergeGlobal 跨主机合并
func (s *StarActivationService) MergeGlobal(dstIP string, dstPort uint16, localCorrID string) string {
	return s.globalMap.Merge(dstIP, dstPort, localCorrID)
}

// HandleMutation 处理 Agent 上报的突变触发
func (s *StarActivationService) HandleMutation(agentID string, pid int32) string {
	key := fmt.Sprintf("%s:pid_%d", agentID, pid)
	return s.correlations.GetOrCreate(key)
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

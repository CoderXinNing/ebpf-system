package agent

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"
)

// CorrelationEntry 关联映射条目
type CorrelationEntry struct {
	LocalCorrelationID string
	LastSeen           time.Time
	CreatedAt          time.Time
}

// CorrelationManager 管理 local_correlation_id 的生成和复用
type CorrelationManager struct {
	mu      sync.RWMutex
	entries map[uint64]*CorrelationEntry // key: correlation_key
	ttl     time.Duration
	agentID string
}

// NewCorrelationManager 创建关联管理器
func NewCorrelationManager(agentID string, ttl time.Duration) *CorrelationManager {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &CorrelationManager{
		entries: make(map[uint64]*CorrelationEntry),
		ttl:     ttl,
		agentID: agentID,
	}
}

// GetOrCreate 获取或创建 local_correlation_id
// 同 PID（correlation_key）在 TTL 内复用
func (m *CorrelationManager) GetOrCreate(correlationKey uint64) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// 清理过期
	for key, entry := range m.entries {
		if now.Sub(entry.LastSeen) > m.ttl {
			delete(m.entries, key)
			log.Printf("🧹 关联 ID 过期: key=%d id=%s", key, entry.LocalCorrelationID)
		}
	}

	// 已存在且未过期 → 复用
	if entry, ok := m.entries[correlationKey]; ok {
		entry.LastSeen = now
		return entry.LocalCorrelationID
	}

	// 生成新 ID
	corrID := generateLocalCorrelationID(m.agentID)
	m.entries[correlationKey] = &CorrelationEntry{
		LocalCorrelationID: corrID,
		LastSeen:           now,
		CreatedAt:          now,
	}
	log.Printf("⭐ 生成新关联 ID: key=%d id=%s", correlationKey, corrID)
	return corrID
}

// generateLocalCorrelationID 生成 local_correlation_id
// 格式：{Agent前8}-{秒级时间戳}-{随机4字节hex}
func generateLocalCorrelationID(agentID string) string {
	// 截取 Agent ID 前 8 位
	agentPrefix := agentID
	if len(agentPrefix) > 8 {
		agentPrefix = agentPrefix[:8]
	}

	// 秒级时间戳
	secTimestamp := time.Now().Unix()

	// 随机 4 字节
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		// crypto/rand 失败时降级用时间戳
		log.Printf("⚠️ crypto/rand 失败: %v", err)
		return fmt.Sprintf("%s-%d-fallback", agentPrefix, secTimestamp)
	}
	randomHex := hex.EncodeToString(randomBytes)

	return fmt.Sprintf("%s-%d-%s", agentPrefix, secTimestamp, randomHex)
}

// Get 查询现有 correlation_id（不创建）
func (m *CorrelationManager) Get(correlationKey uint64) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if entry, ok := m.entries[correlationKey]; ok {
		return entry.LocalCorrelationID, true
	}
	return "", false
}

// End 标记关联结束（PID 退出触发）
func (m *CorrelationManager) End(correlationKey uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry, ok := m.entries[correlationKey]; ok {
		log.Printf("🏁 关联结束: key=%d id=%s", correlationKey, entry.LocalCorrelationID)
		delete(m.entries, correlationKey)
	}
}

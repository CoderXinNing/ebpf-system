package agent

import (
	"log"
	"sync"
	"time"
)

// ObservationLevel 观察等级
type ObservationLevel int

const (
	ObsPassive ObservationLevel = iota // 仅保留极低成本状态
	ObsReduced                         // 只采摘要
	ObsFull                            // 完整采集
)

func (l ObservationLevel) String() string {
	switch l {
	case ObsPassive:
		return "passive"
	case ObsReduced:
		return "reduced"
	case ObsFull:
		return "full"
	}
	return "unknown"
}

// ObservationManager 观察等级管理器
type ObservationManager struct {
	mu       sync.RWMutex
	level    ObservationLevel
	lastUp   time.Time
	cooldown time.Duration // 升级后多久才降级
}

func NewObservationManager() *ObservationManager {
	return &ObservationManager{
		level:    ObsReduced, // 默认 REDUCED
		cooldown: 5 * time.Minute,
	}
}

// GetLevel 获取当前观察等级
func (m *ObservationManager) GetLevel() ObservationLevel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.level
}

// Upgrade 升级到 FULL（异常上下文触发）
func (m *ObservationManager) Upgrade(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.level != ObsFull {
		log.Printf("🔬 观察等级升级: %s → FULL (原因: %s)", m.level.String(), reason)
		m.level = ObsFull
		m.lastUp = time.Now()
	}
}

// Downgrade 降级到 REDUCED（证据收集完毕）
func (m *ObservationManager) Downgrade() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if time.Since(m.lastUp) < m.cooldown {
		return // 冷却期内不降级
	}
	if m.level == ObsFull {
		log.Printf("🔬 观察等级降级: FULL → REDUCED")
		m.level = ObsReduced
	}
}

// SetPassive 进入 PASSIVE 模式（用户设置）
func (m *ObservationManager) SetPassive() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.level = ObsPassive
}

// SetReduced 恢复到 REDUCED
func (m *ObservationManager) SetReduced() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.level = ObsReduced
}

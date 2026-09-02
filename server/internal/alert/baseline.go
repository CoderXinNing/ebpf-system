package alert

import (
	"log"
	"math"
	"os"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
)

// BaselineConfig 基线配置
type BaselineConfig struct {
	Learning struct {
		Mode             string  `toml:"mode"` // silent / report
		DurationMinutes  int     `toml:"duration_minutes"`
		ObserveMinutes   int     `toml:"observe_minutes"`
		Alpha            float64 `toml:"alpha"`
		Threshold        float64 `toml:"threshold"`
		ObserveThreshold float64 `toml:"observe_threshold"`
	} `toml:"learning"`
	Report struct {
		SendCurve        bool `toml:"send_curve"`
		SendCommandStats bool `toml:"send_command_stats"`
	} `toml:"report"`
	Protection struct {
		MaxEventsPerSecond int `toml:"max_events_per_second"`
		MaxTrackedItems    int `toml:"max_tracked_items"`
	} `toml:"protection"`
}

// EngineState 引擎状态
type EngineState int

const (
	StateLearning EngineState = iota // 学习中
	StateObserve                      // 观察期
	StateProtect                      // 防护中
)

func (s EngineState) String() string {
	switch s {
	case StateLearning:
		return "learning"
	case StateObserve:
		return "observe"
	case StateProtect:
		return "protect"
	}
	return "unknown"
}

// Feature 特征
type Feature struct {
	IP     string
	Key    string  // 如 "root:exec_per_hour" 或 "java:parent:conn_per_hour"
	Value  float64
}

// Baseline 单特征基线
type Baseline struct {
	EWMA    float64
	StdDev  float64
	Count   int
	Updated time.Time
}

// BaselineEngine 软基线引擎
type BaselineEngine struct {
	mu         sync.RWMutex
	baselines  map[string]*Baseline
	config     BaselineConfig
	state      EngineState
	startTime  time.Time
	eventCount int
	lastEvent  time.Time

	// 熔断限流
	eventsThisSecond int
	secondStart      time.Time

	// 探测健康
	probeOnline bool
}

func NewBaselineEngine(configPath string) *BaselineEngine {
	engine := &BaselineEngine{
		baselines: make(map[string]*Baseline),
		config: BaselineConfig{
			Learning: struct {
				Mode             string  `toml:"mode"`
				DurationMinutes  int     `toml:"duration_minutes"`
				ObserveMinutes   int     `toml:"observe_minutes"`
				Alpha            float64 `toml:"alpha"`
				Threshold        float64 `toml:"threshold"`
				ObserveThreshold float64 `toml:"observe_threshold"`
			}{
				Mode:             "silent",
				DurationMinutes:  7 * 24 * 60, // 7天
				ObserveMinutes:   48,           // 48小时
				Alpha:            0.3,
				Threshold:        3.0,
				ObserveThreshold: 4.0,
			},
			Report: struct {
				SendCurve        bool `toml:"send_curve"`
				SendCommandStats bool `toml:"send_command_stats"`
			}{},
			Protection: struct {
				MaxEventsPerSecond int `toml:"max_events_per_second"`
				MaxTrackedItems    int `toml:"max_tracked_items"`
			}{
				MaxEventsPerSecond: 10000,
				MaxTrackedItems:    10000,
			},
		},
		state:       StateLearning,
		startTime:   time.Now(),
		lastEvent:   time.Now(),
		probeOnline: true,
	}

	if data, err := os.ReadFile(configPath); err == nil {
		if _, err := toml.Decode(string(data), &engine.config); err != nil {
			log.Printf("⚠️ 基线配置解析失败: %v", err)
		}
	}

	log.Printf("📋 软基线引擎: 模式=%s 学习%d分钟 观察%d分钟 α=%.2f 阈值%.1fσ",
		engine.config.Learning.Mode,
		engine.config.Learning.DurationMinutes,
		engine.config.Learning.ObserveMinutes,
		engine.config.Learning.Alpha,
		engine.config.Learning.Threshold)

	return engine
}

// UpdateState 更新状态机
func (b *BaselineEngine) UpdateState() {
	elapsed := time.Since(b.startTime)
	learnDuration := time.Duration(b.config.Learning.DurationMinutes) * time.Minute
	observeDuration := time.Duration(b.config.Learning.ObserveMinutes) * time.Minute

	newState := b.state
	if elapsed < learnDuration {
		newState = StateLearning
	} else if elapsed < learnDuration+observeDuration {
		newState = StateObserve
	} else {
		newState = StateProtect
	}

	if newState != b.state {
		log.Printf("🔄 基线引擎状态: %s → %s", b.state.String(), newState.String())
		b.state = newState
	}
}

// GetState 获取当前状态
func (b *BaselineEngine) GetState() EngineState {
	b.UpdateState()
	return b.state
}

// IsLearning 是否学习期
func (b *BaselineEngine) IsLearning() bool {
	return b.GetState() == StateLearning
}

// RemainingTime 当前状态剩余时间
func (b *BaselineEngine) RemainingTime() time.Duration {
	elapsed := time.Since(b.startTime)
	learnDuration := time.Duration(b.config.Learning.DurationMinutes) * time.Minute
	observeDuration := time.Duration(b.config.Learning.ObserveMinutes) * time.Minute

	switch b.GetState() {
	case StateLearning:
		return learnDuration - elapsed
	case StateObserve:
		return learnDuration + observeDuration - elapsed
	default:
		return 0
	}
}

// CircuitBreaker 熔断限流：检查是否允许处理
func (b *BaselineEngine) CircuitBreaker() bool {
	now := time.Now()
	if now.Sub(b.secondStart) >= time.Second {
		b.secondStart = now
		b.eventsThisSecond = 0
	}
	b.eventsThisSecond++
	if b.eventsThisSecond > b.config.Protection.MaxEventsPerSecond {
		return false // 熔断
	}
	return true
}

// Update 更新特征并判断异常
func (b *BaselineEngine) Update(feature Feature) (bool, float64) {
	// 熔断保护
	if !b.CircuitBreaker() {
		return false, 0
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.lastEvent = time.Now()
	b.eventCount++

	key := feature.IP + ":" + feature.Key

	baseline, exists := b.baselines[key]
	if !exists {
		// OOM Guard：最多追踪 N 个特征
		if len(b.baselines) >= b.config.Protection.MaxTrackedItems {
			// 简化版：随机淘汰（后续可改 LRU）
			for k := range b.baselines {
				delete(b.baselines, k)
				break
			}
		}
		baseline = &Baseline{
			EWMA:    feature.Value,
			StdDev:  1.0,
			Count:   0,
			Updated: time.Now(),
		}
		b.baselines[key] = baseline
		return false, 0
	}

	alpha := b.config.Learning.Alpha
	oldEWMA := baseline.EWMA
	oldStdDev := baseline.StdDev

	// 先算 Z-Score（用旧基线）
	if oldStdDev < 0.001 {
		oldStdDev = 0.001
	}
	zScore := (feature.Value - oldEWMA) / oldStdDev

	// 学习期直接更新，不告警
	if b.IsLearning() {
		baseline.EWMA = alpha*feature.Value + (1-alpha)*oldEWMA
		baseline.StdDev = math.Sqrt(alpha*math.Pow(feature.Value-baseline.EWMA, 2) + (1-alpha)*math.Pow(oldStdDev, 2))
		baseline.Count++
		baseline.Updated = time.Now()
		return false, 0
	}

	// 根据状态选阈值
	threshold := b.config.Learning.Threshold
	if b.GetState() == StateObserve {
		threshold = b.config.Learning.ObserveThreshold
	}

	log.Printf("📈 Z-Score: %s z=%.2f ewma=%.2f std=%.2f value=%.2f",
		feature.Key, zScore, oldEWMA, oldStdDev, feature.Value)

	if math.Abs(zScore) > threshold {
		log.Printf("🚨 基线异常: %s z=%.2f 阈值%.1f ewma=%.2f value=%.2f",
			feature.Key, zScore, threshold, oldEWMA, feature.Value)
		// 防污染：异常值不更新基线
		return true, zScore
	}

	// 正常值才更新基线
	baseline.EWMA = alpha*feature.Value + (1-alpha)*oldEWMA
	baseline.StdDev = math.Sqrt(alpha*math.Pow(feature.Value-baseline.EWMA, 2) + (1-alpha)*math.Pow(oldStdDev, 2))
	baseline.Count++
	baseline.Updated = time.Now()
	return false, zScore
}

// IsProbeOnline 探针健康检查
func (b *BaselineEngine) IsProbeOnline() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// 连续 5 分钟无事件则判定探针离线
	if time.Since(b.lastEvent) > 5*time.Minute {
		if b.probeOnline {
			b.probeOnline = false
			log.Printf("🚨 探针可能失效: 已 %v 无事件", time.Since(b.lastEvent))
		}
		return false
	}
	if !b.probeOnline {
		b.probeOnline = true
		log.Printf("✅ 探针恢复: 收到新事件")
	}
	return true
}

// GetBaselines 获取所有基线（用于上报/展示）
func (b *BaselineEngine) GetBaselines() map[string]*Baseline {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make(map[string]*Baseline)
	for k, v := range b.baselines {
		result[k] = v
	}
	return result
}

// Persist 基线持久化（Agent 本地落盘）
func (b *BaselineEngine) Persist() {
	b.mu.RLock()
	defer b.mu.RUnlock()
	// TODO: 写入 agent/data/baseline.db
	log.Printf("💾 基线快照: %d 个特征", len(b.baselines))
}


// ForceProtectMode 强制进入防护状态（测试用）
func (b *BaselineEngine) ForceProtectMode() {
	b.state = StateProtect
	b.startTime = time.Now().Add(-time.Duration(b.config.Learning.DurationMinutes+1) * time.Minute)
	log.Printf("🧪 强制防护模式（跳过学习期）")
}

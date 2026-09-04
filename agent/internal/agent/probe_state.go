package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/CoderXinNing/ebpf-system/agent/internal/actor"
	"github.com/CoderXinNing/ebpf-system/agent/internal/baseline"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
)

// ProbeState 是所有需要并发保护的状态集合。
// 所有字段只能由 ProbeStateActor 的 handler 访问。
type ProbeState struct {
	probeStatus           map[string]string        // probe_name -> "loaded" / "failed: reason"
	probePaths            map[string]string        // probe_name -> path from Server
	baselineCount         map[string]int           // 窗口计数
	falsePositiveFeatures map[string]bool          // 误报特征黑名单
	baselineEngine        *baseline.BaselineEngine // 基线引擎引用（只读）

	// 非阻塞读取缓存（心跳定时器直接读，无需 Ask）
	cacheMu       sync.RWMutex
	statusJSON    string // 缓存的探针状态 JSON
	activeCount   int32  // 缓存的活跃探针数
}

func newProbeState(baselineEngine *baseline.BaselineEngine) *ProbeState {
	return &ProbeState{
		probeStatus:           make(map[string]string),
		probePaths:            make(map[string]string),
		baselineCount:         make(map[string]int),
		falsePositiveFeatures: make(map[string]bool),
		baselineEngine:        baselineEngine,
		statusJSON:            "{}",
	}
}

// ---- 消息类型定义 ----

type msgSetProbeStatus struct {
	name   string
	status string
}

type msgSetProbePath struct {
	name string
	path string
}

type msgGetProbePath struct {
	name string
}

type msgAddFalsePositive struct {
	feature string
}

type msgIncrementBaseline struct {
	key string
}

type msgFlushBaselineWindow struct {
	ipAddr string
}

// ---- ProbeStateActor 的 handler ----

func probeStateHandler(state interface{}, msg actor.Message) interface{} {
	s := state.(*ProbeState)

	switch m := msg.(type) {
	case msgSetProbeStatus:
		s.probeStatus[m.name] = m.status
		s.refreshCache()

	case msgSetProbePath:
		s.probePaths[m.name] = m.path
		s.refreshCache()

	case msgGetProbePath:
		return s.probePaths[m.name]

	case msgAddFalsePositive:
		s.falsePositiveFeatures[m.feature] = true

	case msgIncrementBaseline:
		s.baselineCount[m.key]++

	case msgFlushBaselineWindow:
		return s.flushBaselineWindowLocked(m.ipAddr, s.baselineEngine)
	}

	return s
}

// refreshCache 在状态变化时更新缓存（handler goroutine 内调用）
func (s *ProbeState) refreshCache() {
	// 用 json.Marshal 替代手写拼接
	data, err := json.Marshal(s.probeStatus)
	if err != nil {
		data = []byte("{}")
	}

	// 统计活跃探针数（状态为 "loaded" 或 "loading"）
	count := int32(0)
	for _, status := range s.probeStatus {
		if status == "loaded" || status == "loading" {
			count++
		}
	}

	s.cacheMu.Lock()
	s.statusJSON = string(data)
	s.activeCount = count
	s.cacheMu.Unlock()
}

// GetProbeStatusJSON 非阻塞读取缓存的探针状态 JSON
func (s *ProbeState) GetProbeStatusJSON() string {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	return s.statusJSON
}

// GetActiveProbeCount 非阻塞读取缓存的活跃探针数
func (s *ProbeState) GetActiveProbeCount() int32 {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	return s.activeCount
}

// ---- 锁内方法（只在 handler goroutine 内调用） ----

func (s *ProbeState) flushBaselineWindowLocked(ipAddr string, baselineEngine *baseline.BaselineEngine) []*pb.ProbeEvent {
	if len(s.baselineCount) == 0 {
		return nil
	}

	events := make([]*pb.ProbeEvent, 0, len(s.baselineCount))
	for key, count := range s.baselineCount {
		if s.falsePositiveFeatures[key] {
			delete(s.baselineCount, key)
			continue
		}
		isAnomaly, zScore := s.baselineEngine.Update(baseline.Feature{
			IP:    ipAddr,
			Key:   key,
			Value: float64(count),
		})
		if isAnomaly {
			parts := strings.Split(key, ":")
			user := parts[0]
			metric := parts[1]
			events = append(events, &pb.ProbeEvent{
				ProbeName: "baseline_anomaly",
				Timestamp: time.Now().Unix(),
				EventType: "baseline_anomaly",
				Comm:      user,
				Filename:  metric,
				Details:   fmt.Sprintf("%s 基线异常: %s=%d z=%.2f", user, metric, count, zScore),
			})
		}
		delete(s.baselineCount, key)
	}
	return events
}

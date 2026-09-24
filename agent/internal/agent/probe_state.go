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

// ProbeDetail 单个探针的详细运行状态（自检机制用）
type ProbeDetail struct {
	Status              string    `json:"status"`
	Reason              string    `json:"reason,omitempty"`
	LastEventAt         time.Time `json:"last_event_at"`
	LastCheckAt         time.Time `json:"last_check_at"`
	SelfTestOK          bool      `json:"selftest_ok"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	LoadedAt            time.Time `json:"loaded_at"`
}

// ProbeState 是所有需要并发保护的状态集合。
// 所有字段只能由 ProbeStateActor 的 handler 访问。
type ProbeState struct {
	probeStatus           map[string]string
	probePaths            map[string]string
	probeDetails          map[string]*ProbeDetail
	baselineCount         map[string]int
	falsePositiveFeatures map[string]bool
	baselineEngine        *baseline.BaselineEngine

	// 非阻塞读取缓存（心跳定时器直接读，无需 Ask）
	cacheMu     sync.RWMutex
	statusJSON  string
	detailsJSON string
	statusMap   map[string]string
	activeCount int32
}

func newProbeState(baselineEngine *baseline.BaselineEngine) *ProbeState {
	return &ProbeState{
		probeStatus:           make(map[string]string),
		probePaths:            make(map[string]string),
		probeDetails:          make(map[string]*ProbeDetail),
		baselineCount:         make(map[string]int),
		falsePositiveFeatures: make(map[string]bool),
		baselineEngine:        baselineEngine,
		statusJSON:            "{}",
		detailsJSON:           "{}",
		statusMap:             make(map[string]string),
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

// ---- 自检机制消息 ----

// msgRunSelfTestCheck 自检循环提交一次检查结果给 actor。
// 状态判定（连续失败计数、loaded-silent 切换）完全在 actor 内完成。
type msgRunSelfTestCheck struct {
	name        string
	lastEventAt time.Time
	selfTestOK  bool
	unsupported bool
}

type msgGetProbeDetails struct{}

type msgGetProbeDetail struct {
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
		d := s.probeDetails[m.name]
		if d == nil {
			d = &ProbeDetail{LoadedAt: time.Now()}
			s.probeDetails[m.name] = d
		}
		d.Status = m.status
		d.ConsecutiveFailures = 0
		s.refreshCache()

	case msgSetProbePath:
		s.probePaths[m.name] = m.path
		s.refreshCache()

	case msgGetProbePath:
		return s.probePaths[m.name]

	case msgRunSelfTestCheck:
		s.handleSelfTestCheck(m)

	case msgGetProbeDetails:
		snapshot := make(map[string]ProbeDetail, len(s.probeDetails))
		for k, v := range s.probeDetails {
			snapshot[k] = *v
		}
		return snapshot

	case msgGetProbeDetail:
		if d := s.probeDetails[m.name]; d != nil {
			cp := *d
			return &cp
		}
		return (*ProbeDetail)(nil)

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
	data, err := json.Marshal(s.probeStatus)
	if err != nil {
		data = []byte("{}")
	}
	detailsData, err := json.Marshal(s.probeDetails)
	if err != nil {
		detailsData = []byte("{}")
	}

	count := int32(0)
	statusMap := make(map[string]string, len(s.probeStatus))
	for k, v := range s.probeStatus {
		statusMap[k] = v
		if v == "loaded" || v == "loading" {
			count++
		}
	}

	s.cacheMu.Lock()
	s.statusJSON = string(data)
	s.detailsJSON = string(detailsData)
	s.statusMap = statusMap
	s.activeCount = count
	s.cacheMu.Unlock()
}

// handleSelfTestCheck 处理一次自检结果（handler goroutine 内调用，状态机唯一写者）
func (s *ProbeState) handleSelfTestCheck(m msgRunSelfTestCheck) {
	d := s.probeDetails[m.name]
	if d == nil {
		d = &ProbeDetail{LoadedAt: time.Now()}
		s.probeDetails[m.name] = d
	}
	d.LastCheckAt = time.Now()
	if !m.lastEventAt.IsZero() {
		d.LastEventAt = m.lastEventAt
	}

	switch {
	case m.unsupported:
		d.Status = "loaded-no-activity"
		d.Reason = "该探针不支持自检"
		d.SelfTestOK = false
		d.ConsecutiveFailures = 0
	case m.selfTestOK:
		d.Status = "loaded"
		d.Reason = ""
		d.SelfTestOK = true
		d.ConsecutiveFailures = 0
	default:
		d.SelfTestOK = false
		d.ConsecutiveFailures++
		if d.ConsecutiveFailures >= 2 {
			d.Status = "loaded-silent"
			d.Reason = "连续2次自检未收到事件"
		}
	}
	s.refreshCache()
}

// GetProbeStatusJSON 非阻塞读取缓存的探针状态 JSON
func (s *ProbeState) GetProbeStatusJSON() string {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	return s.statusJSON
}

// GetProbeDetailsJSON 非阻塞读取缓存的探针详情 JSON
func (s *ProbeState) GetProbeDetailsJSON() string {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	return s.detailsJSON
}

// GetActiveProbeCount 非阻塞读取缓存的活跃探针数
func (s *ProbeState) GetActiveProbeCount() int32 {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	return s.activeCount
}

// GetProbeStatus 非阻塞读取单个探针的当前状态
func (s *ProbeState) GetProbeStatus(name string) string {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	return s.statusMap[name]
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
				Details:   fmt.Sprintf("[参考] %s 基线异常: %s=%d z=%.2f", user, metric, count, zScore),
			})
		}
		delete(s.baselineCount, key)
	}
	return events
}

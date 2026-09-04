package agent

import (
	"fmt"
	"strings"
	"time"

	"github.com/CoderXinNing/ebpf-system/agent/internal/actor"
	"github.com/CoderXinNing/ebpf-system/agent/internal/baseline"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
)

// ProbeState 是所有需要并发保护的状态集合。
// 所有字段只能由 ProbeStateActor 的 handler 访问。
type ProbeState struct {
	probeStatus           map[string]string       // probe_name -> "loaded" / "failed: reason"
	probePaths            map[string]string       // probe_name -> path from Server
	baselineCount         map[string]int          // 窗口计数
	falsePositiveFeatures map[string]bool         // 误报特征黑名单
	baselineEngine        *baseline.BaselineEngine // 基线引擎引用（只读）
}

func newProbeState(baselineEngine *baseline.BaselineEngine) *ProbeState {
	return &ProbeState{
		probeStatus:           make(map[string]string),
		probePaths:            make(map[string]string),
		baselineCount:         make(map[string]int),
		falsePositiveFeatures: make(map[string]bool),
		baselineEngine:        baselineEngine,
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
	name    string
	replyCh chan string
}

type msgAddFalsePositive struct {
	feature string
}

type msgIncrementBaseline struct {
	key string
}

type msgFlushBaselineWindow struct {
	ipAddr  string
	replyCh chan []*pb.ProbeEvent
}

type msgGetProbeStatusJSON struct {
	replyCh chan string
}

// ---- ProbeStateActor 的 handler ----

func probeStateHandler(state interface{}, msg actor.Message) interface{} {
	s := state.(*ProbeState)

	switch m := msg.(type) {
	case msgSetProbeStatus:
		s.probeStatus[m.name] = m.status

	case msgSetProbePath:
		s.probePaths[m.name] = m.path

	case msgGetProbePath:
		return s.probePaths[m.name]

	case msgAddFalsePositive:
		s.falsePositiveFeatures[m.feature] = true

	case msgIncrementBaseline:
		s.baselineCount[m.key]++

	case msgFlushBaselineWindow:
		return s.flushBaselineWindowLocked(m.ipAddr, s.baselineEngine)

	case msgGetProbeStatusJSON:
		// 返回 JSON 字符串作为 Ask 的响应
		return s.getProbeStatusJSONLocked()
	}

	return s
}

// ---- 锁内方法（只在 handler goroutine 内调用） ----

func (s *ProbeState) flushBaselineWindowLocked(ipAddr string, baselineEngine *baseline.BaselineEngine) []*pb.ProbeEvent {
	if len(s.baselineCount) == 0 {
		return nil
	}

	events := make([]*pb.ProbeEvent, 0, len(s.baselineCount))
	for key, count := range s.baselineCount {
		// 跳过误报特征
		if s.falsePositiveFeatures[key] {
			delete(s.baselineCount, key)
			continue
		}
		// key 格式: user:metric
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

func (s *ProbeState) getProbeStatusJSONLocked() string {
	if len(s.probeStatus) == 0 {
		return "{}"
	}
	parts := make([]string, 0, len(s.probeStatus))
	for name, status := range s.probeStatus {
		parts = append(parts, fmt.Sprintf(`"%s":"%s"`, name, status))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

package agent

import (
	"sync"
	"time"
)

// IdentityBaseline 身份基线
// 学习 User → Process 的正常映射，检测异常
type IdentityBaseline struct {
	mu sync.RWMutex

	// user → 该用户常跑的进程（comm）及计数
	userProcessMap map[string]map[string]*ProcessStat

	// 学习期配置
	learningDuration time.Duration
	startTime        time.Time
}

type ProcessStat struct {
	Count       int
	FirstSeen   time.Time
	LastSeen    time.Time
}

func NewIdentityBaseline(learningDuration time.Duration) *IdentityBaseline {
	return &IdentityBaseline{
		userProcessMap:   make(map[string]map[string]*ProcessStat),
		learningDuration: learningDuration,
		startTime:        time.Now(),
	}
}

// Record 记录一次 User → Process 事件
// 返回是否异常（学习期后才会检测）
func (b *IdentityBaseline) Record(user string, process string) (bool, string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// 获取用户进程表
	processMap, ok := b.userProcessMap[user]
	if !ok {
		processMap = make(map[string]*ProcessStat)
		b.userProcessMap[user] = processMap
	}

	// 更新统计
	stat, ok := processMap[process]
	if !ok {
		stat = &ProcessStat{
			Count:     1,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		processMap[process] = stat
	} else {
		stat.Count++
		stat.LastSeen = time.Now()
	}

	// 学习期内不检测
	if time.Since(b.startTime) < b.learningDuration {
		return false, ""
	}

	// 检测：进程是"第一次见"且学习期已过 → 异常
	if stat.Count == 1 {
		return true, user + " 首次执行 " + process
	}

	return false, ""
}

// GetLearnedProcesses 获取某用户已学习的进程列表
func (b *IdentityBaseline) GetLearnedProcesses(user string) []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	processMap, ok := b.userProcessMap[user]
	if !ok {
		return nil
	}

	processes := make([]string, 0, len(processMap))
	for p := range processMap {
		processes = append(processes, p)
	}
	return processes
}

package alert

import (
	"log"
	"sync"
	"time"
)

// CorrelatedEvent 关联事件
type CorrelatedEvent struct {
	IP        string
	PID       uint32
	Events    []EventRecord
	StartTime time.Time
}

// EventRecord 事件记录
type EventRecord struct {
	Source    string // execve / bash_input / tcp_connect / xdp
	Comm      string
	Details   string
	PPID      uint32
	Timestamp time.Time
}

// CorrelationEngine 上下文关联引擎
type CorrelationEngine struct {
	mu         sync.RWMutex
	windows    map[string][]EventRecord // IP -> 事件链
	window     time.Duration
	maxSize    int
	dedupMap   map[string]time.Time // 去重：IP+类型 -> 上次告警时间
	dedupWindow time.Duration
}

func NewCorrelationEngine(windowSeconds int) *CorrelationEngine {
	return &CorrelationEngine{
		windows:    make(map[string][]EventRecord),
		window:     time.Duration(windowSeconds) * time.Second,
		maxSize:    50,
		dedupMap:   make(map[string]time.Time),
		dedupWindow: 30 * time.Second,
	}
}

// AddEvent 添加事件到关联窗口
func (c *CorrelationEngine) AddEvent(ip string, pid uint32, ppid uint32, source, comm, details string) *CorrelatedEvent {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	chain := c.windows[ip]
	chain = append(chain, EventRecord{
		Source:    source,
		Comm:      comm,
		Details:   details,
		PPID:      ppid,
		Timestamp: now,
	})

	// 清理过期事件（超过窗口期）
	cutoff := now.Add(-c.window)
	valid := chain[:0]
	for _, e := range chain {
		if e.Timestamp.After(cutoff) {
			valid = append(valid, e)
		}
	}
	chain = valid

	// 限制大小
	if len(chain) > c.maxSize {
		chain = chain[len(chain)-c.maxSize:]
	}

	c.windows[ip] = chain

	// 返回完整行为链用于关联判断
	return &CorrelatedEvent{
		IP:        ip,
		PID:       pid,
		Events:    append([]EventRecord{}, chain...),
		StartTime: chain[0].Timestamp,
	}
}

// GetChain 获取指定主机+进程的行为链
func (c *CorrelationEngine) GetChain(ip string, pid uint32) []EventRecord {
	c.mu.RLock()
	defer c.mu.RUnlock()

	chain := c.windows[ip]

	// 清理过期
	cutoff := time.Now().Add(-c.window)
	valid := chain[:0]
	for _, e := range chain {
		if e.Timestamp.After(cutoff) {
			valid = append(valid, e)
		}
	}
	return valid
}

// Cleanup 定期清理所有过期窗口
func (c *CorrelationEngine) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := time.Now().Add(-c.window * 2)

	for ip, chain := range c.windows {
		valid := chain[:0]
		for _, e := range chain {
			if e.Timestamp.After(cutoff) {
				valid = append(valid, e)
			}
		}
		if len(valid) == 0 {
			delete(c.windows, ip)
		} else {
			c.windows[ip] = valid
		}
	}
}

// CheckCorrelation 检查行为链是否匹配关联规则
// 规则示例：exec + tcp + exec 同 PID 10 秒内
func (c *CorrelationEngine) CheckCorrelation(chain *CorrelatedEvent) bool {
	if chain == nil || len(chain.Events) < 2 {
		return false
	}

	hasExec := false
	hasTCP := false
	hasBash := false

	for _, e := range chain.Events {
		switch e.Source {
		case "execve":
			hasExec = true
		case "tcp_connect":
			hasTCP = true
		case "bash_input":
			hasBash = true
		}
	}

	// 去重：同 IP + 同类型 30 秒内只报一次
	dedupKey := chain.IP + ":exec_tcp"
	if hasExec && hasTCP {
		if c.isDuplicate(dedupKey) {
			return false
		}
		log.Printf("🔗 关联告警: %s PID=%d 执行命令+外联", chain.IP, chain.PID)
		return true
	}
	dedupKey = chain.IP + ":exec_bash"
	if hasExec && hasBash {
		if c.isDuplicate(dedupKey) {
			return false
		}
		log.Printf("🔗 关联告警: %s PID=%d 执行命令+终端输入", chain.IP, chain.PID)
		return true
	}
	return false
}


func (c *CorrelationEngine) isDuplicate(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	last, exists := c.dedupMap[key]
	if exists && time.Since(last) < c.dedupWindow {
		return true
	}
	c.dedupMap[key] = time.Now()
	return false
}

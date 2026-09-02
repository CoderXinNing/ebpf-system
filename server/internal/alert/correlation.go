package alert

import (
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
)

// CorrelationConfig 关联配置
type CorrelationConfig struct {
	Window struct {
		Seconds      int `toml:"seconds"`
		DedupSeconds int `toml:"dedup_seconds"`
	} `toml:"window"`
	Blacklist         []struct{ Comm string } `toml:"blacklist"`
	SensitiveKeywords []struct{ Value string } `toml:"sensitive_keywords"`
}

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
	mu          sync.RWMutex
	windows     map[string][]EventRecord // IP -> 事件链
	window      time.Duration
	maxSize     int
	dedupMap    map[string]time.Time // 去重：IP+类型 -> 上次告警时间
	dedupWindow time.Duration
	blacklist   map[string]bool
	sensitive   []string
}

func NewCorrelationEngine(configPath string) *CorrelationEngine {
	engine := &CorrelationEngine{
		windows:     make(map[string][]EventRecord),
		window:      10 * time.Second,
		maxSize:     50,
		dedupMap:    make(map[string]time.Time),
		dedupWindow: 30 * time.Second,
		blacklist:   make(map[string]bool),
		sensitive:   []string{},
	}

	engine.loadConfig(configPath)
	return engine
}

func (c *CorrelationEngine) loadConfig(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("⚠️ 关联配置读取失败，使用默认: %v", err)
		return
	}

	var config CorrelationConfig
	if _, err := toml.Decode(string(data), &config); err != nil {
		log.Printf("⚠️ 关联配置解析失败: %v", err)
		return
	}

	c.window = time.Duration(config.Window.Seconds) * time.Second
	c.dedupWindow = time.Duration(config.Window.DedupSeconds) * time.Second

	for _, b := range config.Blacklist {
		c.blacklist[b.Comm] = true
	}
	for _, s := range config.SensitiveKeywords {
		c.sensitive = append(c.sensitive, s.Value)
	}

	log.Printf("📋 关联引擎配置: 窗口%ds 去重%ds 黑名单%d 敏感词%d",
		config.Window.Seconds, config.Window.DedupSeconds, len(c.blacklist), len(c.sensitive))
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

	hasTCP := false
	hasBash := false
	hasBlacklistedExec := false

	for _, e := range chain.Events {
		switch e.Source {
		case "execve":
			// 从 Details 提取命令名，检查黑名单
			cmdName := extractCommandName(e.Details)
			if cmdName != "" && c.blacklist[cmdName] {
				log.Printf("🔍 exec黑名单命中: cmd=%s", cmdName)
				hasBlacklistedExec = true
			}
		case "tcp_connect":
			hasTCP = true
		case "bash_input":
			hasBash = true
		}
	}

	// 只有可疑进程的 exec+tcp 才告警
	dedupKey := chain.IP + ":exec_tcp"
	if hasBlacklistedExec && hasTCP {
		if c.isDuplicate(dedupKey) {
			return false
		}
		log.Printf("🔗 关联告警: %s PID=%d 可疑执行+外联", chain.IP, chain.PID)
		return true
	}

	// exec+bash 需要 bash 输入包含敏感词
	dedupKey = chain.IP + ":exec_bash"
	if hasBlacklistedExec && hasBash {
		sensitive := false
		for _, e := range chain.Events {
			if e.Source == "bash_input" {
				details := strings.ToLower(e.Details)
				for _, kw := range c.sensitive {
					if strings.Contains(details, kw) {
						sensitive = true
						break
					}
				}
				if sensitive {
					break
				}
			}
		}
		if sensitive {
			if c.isDuplicate(dedupKey) {
				return false
			}
			log.Printf("🔗 关联告警: %s PID=%d 可疑执行+敏感终端输入", chain.IP, chain.PID)
			return true
		}
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


// extractCommandName 从 details 提取命令名
// "root: /usr/bin/curl -s http://..." -> "curl"
// "root: curl -s ..." -> "curl"
func extractCommandName(details string) string {
	// 去掉用户名前缀
	if idx := strings.Index(details, ":"); idx > 0 {
		details = details[idx+1:]
	}
	details = strings.TrimSpace(details)

	// 取路径最后一段
	parts := strings.Fields(details)
	if len(parts) == 0 {
		return ""
	}
	cmd := parts[0]
	if idx := strings.LastIndex(cmd, "/"); idx >= 0 {
		cmd = cmd[idx+1:]
	}
	return cmd
}

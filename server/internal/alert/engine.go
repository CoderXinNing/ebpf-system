package alert

import (
	"os"
	"regexp"
	"sync"
	"time"
	"log"
	"strings"

	"github.com/BurntSushi/toml"
)

type Rule struct {
	Name        string      `yaml:"name"`
	Severity    string      `yaml:"severity"`
	Description string      `yaml:"description"`
	Conditions  []Condition `yaml:"conditions"`
	Frequency   *Frequency  `yaml:"frequency,omitempty"`
	Source      string      `yaml:"source,omitempty"`
}

type Condition struct {
	Field string `yaml:"field"`
	Op    string `yaml:"op"`
	Value string `yaml:"value"`
}

type Frequency struct {
	Count     int `yaml:"count"`
	WindowSec int `yaml:"window_sec"`
}

type Alert struct {
	ID          string
	RuleName    string
	Severity    string
	Description string
	AgentID     string
	PID         int32
	Comm        string
	Filename    string
	Details     string
	Time        time.Time
}

type Engine struct {
	dedupMap  map[string]time.Time
	mu         sync.RWMutex
	rules      []Rule
	rulesPath  string
	freqCount  map[string][]time.Time // 频率统计
	OnAlert    func(Alert)
}

func NewEngine(rulesPath string, callback func(Alert)) *Engine {
	e := &Engine{
		dedupMap:  make(map[string]time.Time),
		freqCount: make(map[string][]time.Time),
		OnAlert:   callback,
	}
	e.rulesPath = rulesPath
	e.loadRules(rulesPath)

	// 启动规则热加载：每 3 秒检查文件变化
	go e.watchRules()

	return e
}

// watchRules 监听规则文件变化，自动热加载
func (e *Engine) watchRules() {
	var lastMod time.Time

	if info, err := os.Stat(e.rulesPath); err == nil {
		lastMod = info.ModTime()
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		info, err := os.Stat(e.rulesPath)
		if err != nil {
			continue
		}

		if info.ModTime() != lastMod {
			lastMod = info.ModTime()
			log.Println("🔄 检测到规则文件变化，热加载中...")
			e.loadRules(e.rulesPath)
		}
	}
}

func (e *Engine) loadRules(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var config struct {
		Rules []Rule `yaml:"rules"`
	}
	if _, err := toml.Decode(string(data), &config); err != nil {
		log.Printf("⚠️ 告警规则解析失败: %v", err)
		return
	}

	e.mu.Lock()
	e.rules = config.Rules
	e.mu.Unlock()

	log.Printf("📋 告警规则加载: %d条", len(config.Rules))
}

// CheckEvent 检查事件是否触发告警
func (e *Engine) CheckEvent(agentID string, pid int32, comm, cmdline, filename, source string) {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	for _, rule := range rules {
		if !e.matchRule(rule, comm, cmdline, filename, source) {
			continue
		}

		// 频率检测
		if rule.Frequency != nil {
			key := agentID + ":" + rule.Name
			e.mu.Lock()
			e.freqCount[key] = append(e.freqCount[key], time.Now())
			// 清理旧记录
			cutoff := time.Now().Add(-time.Duration(rule.Frequency.WindowSec) * time.Second)
			var recent []time.Time
			for _, t := range e.freqCount[key] {
				if t.After(cutoff) {
					recent = append(recent, t)
				}
			}
			e.freqCount[key] = recent
			count := len(recent)
			e.mu.Unlock()

			if count < rule.Frequency.Count {
				continue
			}
		}

		// 匹配成功，产生告警
		comm = strings.TrimRight(comm, string(rune(0)))
		filename = strings.TrimRight(filename, string(rune(0)))
		alert := Alert{
			ID:          time.Now().Format("20060102150405") + "-" + rule.Name,
			RuleName:    rule.Name,
			Severity:    rule.Severity,
			Description: rule.Description,
			AgentID:     agentID,
			PID:         pid,
			Comm:        strings.TrimRight(comm, "\x00"),
			Filename:    strings.TrimRight(filename, "\x00"),
			Details:     strings.TrimRight(cmdline, "\x00"),
			Time:        time.Now(),
		}

		// 去重：同规则+同Agent 30秒内不重复告警
		dedupKey := agentID + ":" + rule.Name
		e.mu.Lock()
		lastTime, exists := e.dedupMap[dedupKey]
		if exists && time.Since(lastTime) < 30*time.Second {
			e.mu.Unlock()
			continue
		}
		e.dedupMap[dedupKey] = time.Now()
		e.mu.Unlock()

		if e.OnAlert != nil {
			e.OnAlert(alert)
		}
	}
}

func (e *Engine) matchRule(rule Rule, comm, cmdline, filename, source string) bool {
	// 来源过滤
	if rule.Source != "" && source != rule.Source {
		return false
	}

	for _, cond := range rule.Conditions {
		fieldValue := ""
		switch cond.Field {
		case "comm":
			fieldValue = strings.Trim(comm, "\x00")
		case "cmdline":
			fieldValue = strings.Trim(cmdline, "\x00")
		case "filename":
			fieldValue = strings.Trim(filename, "\x00")
		default:
			continue
		}
		switch cond.Op {
		case "eq":
			if fieldValue != cond.Value {
				return false
			}
		case "regex":
			matched, _ := regexp.MatchString(cond.Value, fieldValue)
			if !matched {
				return false
			}
		case "contains":
			if !strings.Contains(fieldValue, cond.Value) {
				return false
			}
		}
	}

	return true
}

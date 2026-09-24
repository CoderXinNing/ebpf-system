package framework

import (
	"context"
	"errors"
	"fmt"

	probe "github.com/CoderXinNing/ebpf-system/agent/internal/probe"
)

// Rule 是动态下发的规则（黑白名单）
type Rule struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Op    string `json:"op"` // add / remove / clear
}

// Probe 是所有 eBPF 探针必须实现的统一接口
type Probe interface {
	// Name 返回探针名称（如 "exec_monitor"）
	Name() string

	// Init 加载 eBPF 程序并初始化（不挂载）
	Init() error

	// Attach 挂载到内核
	Attach() error

	// UpdateRules 动态更新规则（黑白名单）
	UpdateRules(rules []Rule) error

	// Stop 卸载探针并清理资源
	Stop() error
}

// Manager 管理所有探针的注册和生命周期
type Manager struct {
	probes map[string]Probe
}

func NewManager() *Manager {
	return &Manager{
		probes: make(map[string]Probe),
	}
}

// Register 注册探针
func (m *Manager) Register(p Probe) {
	m.probes[p.Name()] = p
}

// Get 按名称获取探针
func (m *Manager) Get(name string) (Probe, bool) {
	p, ok := m.probes[name]
	return p, ok
}

// List 列出所有已注册探针
func (m *Manager) List() []Probe {
	result := make([]Probe, 0, len(m.probes))
	for _, p := range m.probes {
		result = append(result, p)
	}
	return result
}

// Start 启动指定探针
func (m *Manager) Start(ctx context.Context, name string) error {
	p, ok := m.probes[name]
	if !ok {
		return fmt.Errorf("探针 %s 未注册", name)
	}
	if err := p.Init(); err != nil {
		return fmt.Errorf("探针 %s 初始化失败: %w", name, err)
	}
	if err := p.Attach(); err != nil {
		return fmt.Errorf("探针 %s 挂载失败: %w", name, err)
	}
	return nil
}

// Stop 停止指定探针
func (m *Manager) Stop(name string) error {
	p, ok := m.probes[name]
	if !ok {
		return fmt.Errorf("探针 %s 未注册", name)
	}
	return p.Stop()
}

// SelfTestOptions 自检动作参数（由 Agent 层从配置构建）
type SelfTestOptions struct {
	TCPTarget         string
	XDPFallbackTarget string
	FileTarget        string
}

// SelfTester 可选接口：探针实现一个"已知能被自己捕获的行为"。
// 用于自检机制，检测 attach 成功但静默失败（loaded-silent）的探针。
type SelfTester interface {
	// SelfTestAction 执行一个应该被本探针捕获的动作。
	// 返回 nil 或 ErrSelfTestExpected 表示动作已执行，进入事件对比流程；
	// 返回 ErrSelfTestActionFailed 表示动作本身失败（命令未执行）。
	SelfTestAction(opts SelfTestOptions) error
}

var (
	// ErrSelfTestExpected 预期失败：动作已执行，探针应捕获到事件
	ErrSelfTestExpected = errors.New("selftest: 预期失败（动作已执行，探针应捕获）")
	// ErrSelfTestActionFailed 动作本身失败：命令未执行
	ErrSelfTestActionFailed = errors.New("selftest: 动作本身失败（命令未执行）")
)

// PreChecker 可选接口：探针在加载前做环境预检查。
//
// 不实现 → 走宽松默认（只靠 SHA256 + 加载时错误兜底）。
// 实现   → 环境不满足时拒绝加载，状态标 unsupported: <reason>。
//
// 自定义探针建议：
//  1. 直接不实现，走宽松默认（最省事）
//  2. 实现并调用 framework.CommonPreCheck(caps)，5 行覆盖通用检查
//  3. 实现 + 完全自定义（精细控制）
type PreChecker interface {
	// PreCheck 在 Init/Attach 之前调用。
	// 返回 nil 表示环境满足；返回 error 会被标记为 "unsupported: <reason>"。
	// 探针自己最懂自己的需求，caps 只提供通用环境信息。
	PreCheck(caps *probe.AgentCapabilities) error
}

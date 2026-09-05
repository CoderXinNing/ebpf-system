package framework

import (
	"context"
	"fmt"
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

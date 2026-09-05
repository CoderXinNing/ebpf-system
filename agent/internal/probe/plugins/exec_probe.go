package plugins

import (
	"github.com/CoderXinNing/ebpf-system/agent/internal/ebpf"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/framework"
)

// ExecProbe 是 exec_monitor 探针的适配器
type ExecProbe struct {
	objPath  string
	callback ebpf.ExecCallback
	loaded   bool
}

func NewExecProbe(objPath string, callback ebpf.ExecCallback) *ExecProbe {
	return &ExecProbe{
		objPath:  objPath,
		callback: callback,
	}
}

func (p *ExecProbe) Name() string { return "exec_monitor" }

func (p *ExecProbe) Init() error {
	return nil // 加载在 Attach 里做
}

func (p *ExecProbe) Attach() error {
	if err := ebpf.LoadExecMonitor(p.objPath, p.callback); err != nil {
		return err
	}
	p.loaded = true
	return nil
}

func (p *ExecProbe) UpdateRules(rules []framework.Rule) error {
	// exec_monitor 的白名单通过 BPF Map 更新
	// 当前先返回 nil，等动态规则通道做完再实现
	return nil
}

func (p *ExecProbe) Stop() error {
	// exec_monitor 的持久化 pin 在 Shutdown 里统一清理
	p.loaded = false
	return nil
}

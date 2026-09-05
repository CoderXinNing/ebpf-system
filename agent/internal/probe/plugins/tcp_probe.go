package plugins

import (
	"github.com/CoderXinNing/ebpf-system/agent/internal/ebpf"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/framework"
)

// TCPProbe 是 tcp_monitor 探针的适配器
type TCPProbe struct {
	objPath  string
	callback ebpf.TCPCallback
	loaded   bool
}

func NewTCPProbe(objPath string, callback ebpf.TCPCallback) *TCPProbe {
	return &TCPProbe{
		objPath:  objPath,
		callback: callback,
	}
}

func (p *TCPProbe) Name() string { return "tcp_monitor" }

func (p *TCPProbe) Init() error { return nil }

func (p *TCPProbe) Attach() error {
	if err := ebpf.LoadTCPMonitor(p.objPath, p.callback); err != nil {
		return err
	}
	p.loaded = true
	return nil
}

func (p *TCPProbe) UpdateRules(rules []framework.Rule) error {
	return nil
}

func (p *TCPProbe) Stop() error {
	p.loaded = false
	return nil
}

package plugins

import (
	"github.com/CoderXinNing/ebpf-system/agent/internal/ebpf"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/framework"
)

// XDPProbe 是 xdp_reporter 探针的适配器
type XDPProbe struct {
	cfg      ebpf.XDPConfig
	callback func(ebpf.XDPEvent)
	handle   *ebpf.XDPHandle
}

func NewXDPProbe(cfg ebpf.XDPConfig, callback func(ebpf.XDPEvent)) *XDPProbe {
	return &XDPProbe{
		cfg:      cfg,
		callback: callback,
	}
}

func (p *XDPProbe) Name() string { return "xdp_reporter" }

func (p *XDPProbe) Init() error { return nil }

func (p *XDPProbe) Attach() error {
	handle, err := ebpf.LoadXDPReporter(p.cfg, p.callback)
	if err != nil {
		return err
	}
	p.handle = handle
	return nil
}

func (p *XDPProbe) UpdateRules(rules []framework.Rule) error {
	return nil
}

func (p *XDPProbe) Stop() error {
	if p.handle != nil {
		p.handle.Close()
		p.handle = nil
	}
	return nil
}

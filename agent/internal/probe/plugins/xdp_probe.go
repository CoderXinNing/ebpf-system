package plugins

import (
	"log"

	"github.com/CoderXinNing/ebpf-system/agent/internal/v3_loader"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/framework"
)

// XDPProbe V3 XDP 探针适配器
type XDPProbe struct {
	cfg      v3_loader.XDPConfig
	callback func(pid uint32, comm string, details string)
	loaded   bool
	probe    *v3_loader.XDPProbe
}

func NewXDPProbe(cfg v3_loader.XDPConfig, callback func(pid uint32, comm string, details string)) *XDPProbe {
	return &XDPProbe{
		cfg:      cfg,
		callback: callback,
	}
}

func (p *XDPProbe) Name() string { return "xdp_reporter" }

func (p *XDPProbe) Init() error { return nil }

func (p *XDPProbe) Attach() error {
	p.probe = v3_loader.NewXDPProbe(p.cfg, func(header *v3_loader.SentinelEventHeader) {
		if p.callback != nil {
			p.callback(header.PID, v3_loader.CString(header.Comm[:]), v3_loader.CString(header.Data[:]))
		}
	})

	if err := p.probe.Load("v3_engine/probes/xdp_reporter.o", p.cfg); err != nil {
		return err
	}

	p.loaded = true
	log.Printf("✅ V3 XDP 探针已通过插件框架加载")
	return nil
}

func (p *XDPProbe) UpdateRules(rules []framework.Rule) error {
	return nil
}

func (p *XDPProbe) Stop() error {
	if p.probe != nil {
		p.probe.Close()
		p.probe = nil
	}
	p.loaded = false
	return nil
}

var _ framework.Probe = (*XDPProbe)(nil)

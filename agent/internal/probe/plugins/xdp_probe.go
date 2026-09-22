package plugins

import (
	"fmt"
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
	p.probe = v3_loader.NewXDPProbe(p.cfg, func(header *v3_loader.SentinelEventHeader, summary *v3_loader.XDPPacketSummary) {
		if p.callback != nil {
			// 五元组信息编码进 details
			details := fmt.Sprintf("%d.%d.%d.%d:%d → %d.%d.%d.%d:%d proto=%d",
				(summary.SrcIP>>24)&0xFF, (summary.SrcIP>>16)&0xFF, (summary.SrcIP>>8)&0xFF, summary.SrcIP&0xFF, summary.SrcPort,
				(summary.DstIP>>24)&0xFF, (summary.DstIP>>16)&0xFF, (summary.DstIP>>8)&0xFF, summary.DstIP&0xFF, summary.DstPort,
				summary.Protocol)
			p.callback(header.PID, v3_loader.CString(header.Comm[:]), details)
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

package plugins

import (
	"errors"
	"fmt"
	"log"
	"os/exec"

	"github.com/CoderXinNing/ebpf-system/agent/internal/paths"
	probe "github.com/CoderXinNing/ebpf-system/agent/internal/probe"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/framework"
	"github.com/CoderXinNing/ebpf-system/agent/internal/v3_loader"
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

	if err := p.probe.Load(paths.Probe("xdp_reporter.o"), p.cfg); err != nil {
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

func (p *XDPProbe) SelfTestAction(opts framework.SelfTestOptions) error {
	gw := getDefaultGateway()
	if gw == "" {
		gw = opts.XDPFallbackTarget
		if gw == "" {
			gw = "8.8.8.8"
		}
	}
	cmd := exec.Command("bash", "-c",
		"exec -a agent-selftest ping -c1 -W1 "+gw)
	err := cmd.Run()
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		log.Printf("🔬 [SELFTEST][EXPECTED] XDP 自检 ping 未通 (exit=%d)", exitErr.ExitCode())
		return nil
	}
	return fmt.Errorf("%w: %v", framework.ErrSelfTestActionFailed, err)
}

var _ framework.SelfTester = (*XDPProbe)(nil)

// PreCheck xdp_reporter 环境预检查：依赖 CO-RE（BTF）+ 物理网卡配置。
func (p *XDPProbe) PreCheck(caps *probe.AgentCapabilities) error {
	if err := framework.CommonPreCheck(caps); err != nil {
		return framework.WrapReason("xdp_reporter", err.Error())
	}
	if p.cfg.Iface == "" {
		return framework.WrapReason("xdp_reporter", "未配置网卡（xdp.iface）")
	}
	return nil
}

var _ framework.PreChecker = (*XDPProbe)(nil)

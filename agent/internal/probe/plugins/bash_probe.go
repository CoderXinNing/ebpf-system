package plugins

import (
	"log"

	"github.com/CoderXinNing/ebpf-system/agent/internal/v3_loader"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/framework"
)

// BashProbe 是 V3 bash 探针的适配器
type BashProbe struct {
	objPath   string
	bashPath  string
	callback  func(pid uint32, comm string, line string, correlationKey uint64)
	loaded    bool
	probe     *v3_loader.BashProbe
	agentHash uint32
}

func NewBashProbe(objPath string, bashPath string, agentHash uint32, callback func(pid uint32, comm string, line string, correlationKey uint64)) *BashProbe {
	return &BashProbe{
		objPath:   objPath,
		bashPath:  bashPath,
		callback:  callback,
		agentHash: agentHash,
	}
}

func (p *BashProbe) Name() string { return "bash_monitor" }

func (p *BashProbe) Init() error { return nil }

func (p *BashProbe) Attach() error {
	p.probe = v3_loader.NewBashProbe(p.objPath, p.bashPath, p.agentHash, func(header *v3_loader.SentinelEventHeader, line string) {
		if p.callback != nil {
			p.callback(header.PID, v3_loader.CString(header.Comm[:]), line, header.CorrelationKey)
		}
	})

	if err := p.probe.Load(); err != nil {
		return err
	}

	p.loaded = true
	log.Printf("✅ V3 bash 探针已通过插件框架加载")
	return nil
}

func (p *BashProbe) UpdateRules(rules []framework.Rule) error {
	return nil
}

func (p *BashProbe) Stop() error {
	if p.probe != nil {
		p.probe.Close()
		p.probe = nil
	}
	p.loaded = false
	return nil
}

var _ framework.Probe = (*BashProbe)(nil)

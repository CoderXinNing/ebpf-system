package plugins

import (
	"fmt"
	"log"

	"github.com/CoderXinNing/ebpf-system/agent/internal/v3_loader"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/framework"
)

// ExecProbe 是 V3 exec 探针的适配器
type ExecProbe struct {
	objPath   string
	callback  func(pid uint32, comm string, cmdline string)
	loaded    bool
	probe     *v3_loader.ExecProbe
	agentHash uint32
}

func NewExecProbe(objPath string, agentHash uint32, callback func(pid uint32, comm string, cmdline string)) *ExecProbe {
	return &ExecProbe{
		objPath:   objPath,
		callback:  callback,
		agentHash: agentHash,
	}
}

func (p *ExecProbe) Name() string { return "exec_monitor" }

func (p *ExecProbe) Init() error { return nil }

func (p *ExecProbe) Attach() error {
	p.probe = v3_loader.NewExecProbe(p.objPath, p.agentHash, func(header *v3_loader.SentinelEventHeader, cmdline string) {
		if p.callback != nil {
			p.callback(header.PID, v3_loader.CString(header.Comm[:]), cmdline)
		}
	})

	if err := p.probe.Load(); err != nil {
		return err
	}

	p.loaded = true
	log.Printf("✅ V3 exec 探针已通过插件框架加载")
	return nil
}

func (p *ExecProbe) UpdateRules(rules []framework.Rule) error {
	return nil
}

func (p *ExecProbe) Stop() error {
	if p.probe != nil {
		p.probe.Close()
		p.probe = nil
	}
	p.loaded = false
	return nil
}

// 确保实现 framework.Probe 接口
var _ framework.Probe = (*ExecProbe)(nil)
var _ = fmt.Sprintf

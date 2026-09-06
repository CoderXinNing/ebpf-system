package plugins

import (
	"fmt"
	"log"

	"github.com/CoderXinNing/ebpf-system/agent/internal/v3_loader"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/framework"
)

// TCPProbe 是 V3 TCP 探针的适配器
type TCPProbe struct {
	objPath   string
	callback  func(pid uint32, comm string, count uint64)
	loaded    bool
	probe     *v3_loader.TCPProbe
	agentHash uint32
}

func NewTCPProbe(objPath string, agentHash uint32, callback func(pid uint32, comm string, count uint64)) *TCPProbe {
	return &TCPProbe{
		objPath:   objPath,
		callback:  callback,
		agentHash: agentHash,
	}
}

func (p *TCPProbe) Name() string { return "tcp_monitor" }

func (p *TCPProbe) Init() error { return nil }

func (p *TCPProbe) Attach() error {
	p.probe = v3_loader.NewTCPProbe(p.objPath, p.agentHash, func(header *v3_loader.SentinelEventHeader, detail *v3_loader.TCPConnDetail) {
		// V3 事件回调：默认计数模式，明细模式下触发
		if p.callback != nil {
			p.callback(header.PID, v3_loader.CString(header.Comm[:]), 1)
		}
	})

	if err := p.probe.Load(); err != nil {
		return err
	}

	p.loaded = true
	log.Printf("✅ V3 TCP 探针已通过插件框架加载")
	return nil
}

func (p *TCPProbe) UpdateRules(rules []framework.Rule) error {
	return nil
}

func (p *TCPProbe) Stop() error {
	if p.probe != nil {
		p.probe.Close()
		p.probe = nil
	}
	p.loaded = false
	return nil
}

// SetCollectMode 动态切换采集模式
func (p *TCPProbe) SetCollectMode(mode uint64) error {
	if p.probe == nil {
		return fmt.Errorf("探针未加载")
	}
	return p.probe.SetCollectMode(mode)
}

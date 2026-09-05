package plugins

import (
	"github.com/CoderXinNing/ebpf-system/agent/internal/ebpf"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/framework"
)

// BashProbe 是 bash_monitor 探针的适配器
type BashProbe struct {
	objPath  string
	bashPath string
	callback ebpf.BashCallback
	loaded   bool
}

func NewBashProbe(objPath string, bashPath string, callback ebpf.BashCallback) *BashProbe {
	return &BashProbe{
		objPath:  objPath,
		bashPath: bashPath,
		callback: callback,
	}
}

func (p *BashProbe) Name() string { return "bash_monitor" }

func (p *BashProbe) Init() error { return nil }

func (p *BashProbe) Attach() error {
	if err := ebpf.LoadBashMonitorV2(p.objPath, p.bashPath, func(evt ebpf.BashEventV2) {
		var comm [16]byte
		copy(comm[:], evt.Header.Comm)
		p.callback(ebpf.BashEvent{PID: evt.Header.PID, UID: evt.Header.UID, Comm: comm}, "", evt.Line)
	}); err != nil {
		return err
	}
	p.loaded = true
	return nil
}

func (p *BashProbe) UpdateRules(rules []framework.Rule) error {
	return nil
}

func (p *BashProbe) Stop() error {
	p.loaded = false
	return nil
}

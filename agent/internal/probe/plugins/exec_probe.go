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

func (p *ExecProbe) Init() error { return nil }

func (p *ExecProbe) Attach() error {
	if err := ebpf.LoadExecMonitorV2(p.objPath, func(evt ebpf.ExecEventV2) {
		// 正确转换 V2 事件到 V1 格式
		var comm [16]byte
		copy(comm[:], evt.Header.Comm)
		var filename [256]byte
		copy(filename[:], evt.Cmdline)

		p.callback(ebpf.ExecEvent{
			PID:      evt.Header.PID,
			PPID:     evt.Header.PPID,
			UID:      evt.Header.UID,
			Comm:     comm,
			Filename: filename,
		}, evt.Cmdline)
	}); err != nil {
		return err
	}
	p.loaded = true
	return nil
}

func (p *ExecProbe) UpdateRules(rules []framework.Rule) error {
	return nil
}

func (p *ExecProbe) Stop() error {
	p.loaded = false
	return nil
}

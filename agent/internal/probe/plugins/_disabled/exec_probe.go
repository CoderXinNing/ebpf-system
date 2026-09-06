package plugins

import (
	"runtime"

	agentebpf "github.com/CoderXinNing/ebpf-system/agent/internal/ebpf"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/framework"
)

// ExecProbe 是 exec_monitor 探针的适配器
type ExecProbe struct {
	objPath  string
	callback agentebpf.ExecCallback
	loaded   bool
	link     *agentebpf.ManualTracepointLink // 显式持有，防止 GC 回收
}

func NewExecProbe(objPath string, callback agentebpf.ExecCallback) *ExecProbe {
	return &ExecProbe{
		objPath:  objPath,
		callback: callback,
	}
}

func (p *ExecProbe) Name() string { return "exec_monitor" }

func (p *ExecProbe) Init() error { return nil }

func (p *ExecProbe) Attach() error {
	var tp *agentebpf.ManualTracepointLink
	tp, err := agentebpf.LoadExecMonitorV2(p.objPath, func(evt agentebpf.ExecEventV2) {
		var comm [16]byte
		copy(comm[:], evt.Header.Comm)
		var filename [256]byte
		copy(filename[:], evt.Cmdline)
		p.callback(agentebpf.ExecEvent{
			PID:      evt.Header.PID,
			PPID:     evt.Header.PPID,
			UID:      evt.Header.UID,
			Comm:     comm,
			Filename: filename,
		}, evt.Cmdline)
	})
	if err != nil {
		return err
	}
	p.link = tp
	p.loaded = true
	runtime.KeepAlive(p)
	runtime.KeepAlive(tp)
	return nil
}

func (p *ExecProbe) UpdateRules(rules []framework.Rule) error { return nil }

func (p *ExecProbe) Stop() error {
	if p.link != nil {
		p.link.Close()
		p.link = nil
	}
	p.loaded = false
	return nil
}

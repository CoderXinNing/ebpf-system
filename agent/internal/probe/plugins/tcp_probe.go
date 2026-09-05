package plugins

import (
	"github.com/cilium/ebpf"
	agentebpf "github.com/CoderXinNing/ebpf-system/agent/internal/ebpf"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/framework"
)

// TCPProbe 是 tcp_monitor 探针的适配器
type TCPProbe struct {
	objPath     string
	callback    func(pid uint32, comm string, count uint64)
	loaded      bool
	pidConnMap  *ebpf.Map
	connDetails *ebpf.Map
}

func NewTCPProbe(objPath string, callback func(pid uint32, comm string, count uint64)) *TCPProbe {
	return &TCPProbe{
		objPath:  objPath,
		callback: callback,
	}
}

func (p *TCPProbe) Name() string { return "tcp_monitor" }

func (p *TCPProbe) Init() error { return nil }

func (p *TCPProbe) Attach() error {
	pidConnMap, connDetails, err := agentebpf.LoadTCPMonitorV2(p.objPath, func(evt agentebpf.TCPEventV2) {
		// 默认只计数不上报
	})
	if err != nil {
		return err
	}
	p.pidConnMap = pidConnMap
	p.connDetails = connDetails
	p.loaded = true
	return nil
}

func (p *TCPProbe) UpdateRules(rules []framework.Rule) error {
	return nil
}

func (p *TCPProbe) Stop() error {
	p.loaded = false
	p.pidConnMap = nil
	p.connDetails = nil
	return nil
}

// GetPidConnMap 返回 PID 连接统计 Map（供突变检测使用）
func (p *TCPProbe) GetPidConnMap() *ebpf.Map {
	return p.pidConnMap
}

// GetConnDetails 返回连接明细 Map（供星轨溯源使用）
func (p *TCPProbe) GetConnDetails() *ebpf.Map {
	return p.connDetails
}

package plugins

import (
	"log"

	probe "github.com/CoderXinNing/ebpf-system/agent/internal/probe"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/framework"
	"github.com/CoderXinNing/ebpf-system/agent/internal/v3_loader"
)

// FileProbe 是 V3 file_access 探针的适配器
type FileProbe struct {
	objPath   string
	callback  func(pid uint32, comm string, filename string, correlationKey uint64)
	loaded    bool
	probe     *v3_loader.FileProbe
	agentHash uint32
}

func NewFileProbe(objPath string, agentHash uint32, callback func(pid uint32, comm string, filename string, correlationKey uint64)) *FileProbe {
	return &FileProbe{
		objPath:   objPath,
		callback:  callback,
		agentHash: agentHash,
	}
}

func (p *FileProbe) Name() string { return "file_access" }

func (p *FileProbe) Init() error { return nil }

func (p *FileProbe) Attach() error {
	p.probe = v3_loader.NewFileProbe(p.objPath, p.agentHash, func(header *v3_loader.SentinelEventHeader, filename string) {
		if p.callback != nil {
			p.callback(header.PID, v3_loader.CString(header.Comm[:]), filename, header.CorrelationKey)
		}
	})

	if err := p.probe.Load(); err != nil {
		return err
	}

	p.loaded = true
	log.Printf("✅ V3 file_access 探针已通过插件框架加载")
	return nil
}

func (p *FileProbe) UpdateRules(rules []framework.Rule) error {
	return nil
}

func (p *FileProbe) Stop() error {
	if p.probe != nil {
		p.probe.Close()
		p.probe = nil
	}
	p.loaded = false
	return nil
}

var _ framework.Probe = (*FileProbe)(nil)

// 注：FileProbe 不实现 framework.SelfTester。
//
// 原因：file_access 探针只上报【敏感路径】的访问事件。自检动作必须走敏感路径
// 才能产生可观测事件，但这会触发"密码文件读取"等真实告警 —— 自检与告警相互矛盾。
//
// 替代：file_access 天然有持续流量（Agent 资产采集、系统进程读敏感文件），
// 通过"最近有事件"即可判断其存活，无需人工自检。
//
// 状态：自动标记为 loaded-no-activity（与 bash_monitor 一致）。
//
// TODO：未来若引入 Agent 侧 PID 过滤（识别自身进程），可重新实现 SelfTestAction。

// PreCheck file_access 环境预检查：依赖 CO-RE（BTF）+ tracepoint 目录。
func (p *FileProbe) PreCheck(caps *probe.AgentCapabilities) error {
	if err := framework.CommonPreCheck(caps); err != nil {
		return framework.WrapReason("file_access", err.Error())
	}
	return nil
}

var _ framework.PreChecker = (*FileProbe)(nil)

package plugins

import (
	"log"

	"github.com/CoderXinNing/ebpf-system/agent/internal/v3_loader"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/framework"
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

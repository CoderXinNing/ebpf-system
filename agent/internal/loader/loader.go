package loader

import (
	"log"

	// 导入探针包，触发init注册
	_ "github.com/CoderXinNing/ebpf-system/agent/internal/loader/exec_monitor"

	"github.com/CoderXinNing/ebpf-system/agent/internal/loader/registry"
)

// LoadByName 根据名称加载探针
func LoadByName(name string, callback func(registry.Event)) (registry.ProbeInstance, error) {
	meta, err := registry.Get(name)
	if err != nil {
		return nil, err
	}
	log.Printf("📥 加载探针: %s (%s)", meta.Name, meta.Description)
	return meta.Factory(callback)
}

// ListProbes 列出所有可用探针
func ListProbes() []*registry.ProbeMeta {
	return registry.List()
}

// 保留别名
type Probe struct {
	Instance registry.ProbeInstance
}

func (p *Probe) Stop() {
	if p.Instance != nil {
		p.Instance.Stop()
	}
}

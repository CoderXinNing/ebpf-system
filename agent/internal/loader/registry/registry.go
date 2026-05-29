package registry

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf/link"
)

// Event 通用事件（探针上报的原始数据）
type Event struct {
	PID       uint32
	Comm      string
	Filename  string
	Details   string
}

// ProbeFactory 探针工厂函数类型
// 接收事件回调，返回ProbeInstance
type ProbeFactory func(callback func(Event)) (ProbeInstance, error)

// ProbeInstance 探针实例接口
type ProbeInstance interface {
	Stop() error
}

// ProbeMeta 探针元信息
type ProbeMeta struct {
	Name        string
	Description string
	Version     string
	HookType    string   // tracepoint/kprobe/XDP
	HookPoint   string   // syscalls/sys_enter_execve
	Factory     ProbeFactory
}

var (
	mu       sync.RWMutex
	registry = make(map[string]*ProbeMeta)
)

// Register 注册探针
func Register(meta *ProbeMeta) {
	mu.Lock()
	defer mu.Unlock()
	registry[meta.Name] = meta
}

// Get 获取探针
func Get(name string) (*ProbeMeta, error) {
	mu.RLock()
	defer mu.RUnlock()
	meta, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("探针未注册: %s", name)
	}
	return meta, nil
}

// List 列出所有注册的探针
func List() []*ProbeMeta {
	mu.RLock()
	defer mu.RUnlock()
	list := make([]*ProbeMeta, 0, len(registry))
	for _, meta := range registry {
		list = append(list, meta)
	}
	return list
}

// GenericProbe 通用探针包装
type GenericProbe struct {
	Name string
	Objs interface{ Close() error }
	Link link.Link
}

func (p *GenericProbe) Stop() error {
	if p.Link != nil {
		p.Link.Close()
	}
	if p.Objs != nil {
		p.Objs.Close()
	}
	return nil
}

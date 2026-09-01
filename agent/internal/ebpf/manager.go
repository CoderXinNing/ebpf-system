package ebpf

import (
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
)

// ProbeSpec 通用探针定义
type ProbeSpec struct {
	Name    string   // 探针名
	ObjPath string   // .o 文件路径
	PinBase string   // pin 根目录
	Maps    []string // 需要 pin 的 map 名（eBPF 里定义的名字）
}

// PinPaths 返回探针相关 pin 路径
func (p *ProbeSpec) PinPaths() map[string]string {
	paths := make(map[string]string)
	paths["prog"] = p.PinBase + "/" + p.Name + "_prog"
	for _, m := range p.Maps {
		paths[m] = p.PinBase + "/" + p.Name + "_" + m
	}
	return paths
}

// ShouldReload 检查 .o 是否比 pin 新
func (p *ProbeSpec) ShouldReload() bool {
	pinInfo, err := os.Stat(p.PinBase + "/" + p.Name + "_prog")
	if err != nil {
		return true // pin 不存在，需要加载
	}
	objInfo, err := os.Stat(p.ObjPath)
	if err != nil {
		return false // .o 不存在，继续用 pin
	}
	return objInfo.ModTime().After(pinInfo.ModTime())
}

// CleanPins 清理所有 pin 文件
func (p *ProbeSpec) CleanPins() {
	for _, path := range p.PinPaths() {
		os.Remove(path)
	}
	log.Printf("🧹 已清理 %s 的 pin 文件", p.Name)
}

// Prepare 准备加载：决定复用、重载还是清理
func (p *ProbeSpec) Prepare() (mode string) {
	if p.ShouldReload() {
		p.CleanPins()
		return "load"
	}
	if _, err := os.Stat(p.PinBase + "/" + p.Name + "_prog"); err == nil {
		return "reuse"
	}
	return "load"
}

// LoadCollection 加载 .o 并返回 Collection（不自动 pin，由调用方决定）
func (p *ProbeSpec) LoadCollection() (*ebpf.Collection, error) {
	spec, err := ebpf.LoadCollectionSpec(p.ObjPath)
	if err != nil {
		return nil, fmt.Errorf("加载spec失败: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("加载collection失败: %w", err)
	}
	return coll, nil
}

// PinCollection 把 Collection 里的程序和 map pin 到 bpffs
func (p *ProbeSpec) PinCollection(coll *ebpf.Collection) error {
	os.MkdirAll(p.PinBase, 0755)
	paths := p.PinPaths()

	for name, prog := range coll.Programs {
		if name == p.Name {
			if err := prog.Pin(paths["prog"]); err != nil {
				log.Printf("⚠️ Pin 程序 %s 失败: %v", p.Name, err)
			} else {
				log.Printf("📌 %s 程序已pin", p.Name)
			}
		}
	}
	for mapName, m := range coll.Maps {
		if path, ok := paths[mapName]; ok {
			if err := m.Pin(path); err != nil {
				log.Printf("⚠️ Pin map %s 失败: %v", mapName, err)
			}
		}
	}
	return nil
}

// LoadPinnedCollection 从 pin 文件加载 Collection
func (p *ProbeSpec) LoadPinnedCollection() (*ebpf.Collection, error) {
	coll := &ebpf.Collection{
		Programs: make(map[string]*ebpf.Program),
		Maps:     make(map[string]*ebpf.Map),
	}
	paths := p.PinPaths()

	prog, err := ebpf.LoadPinnedProgram(paths["prog"], nil)
	if err != nil {
		return nil, fmt.Errorf("加载pin程序失败: %w", err)
	}
	coll.Programs[p.Name] = prog

	for mapName, path := range paths {
		if mapName == "prog" {
			continue
		}
		m, err := ebpf.LoadPinnedMap(path, nil)
		if err != nil {
			continue // map 可能没 pin，跳过
		}
		coll.Maps[mapName] = m
	}
	return coll, nil
}

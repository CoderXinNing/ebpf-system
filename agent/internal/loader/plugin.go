package loader

import (
	"fmt"
	"encoding/base64"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"gopkg.in/yaml.v3"
)

type PluginMeta struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Desc    string   `json:"description"`
	Hooks   []string `json:"hooks"`
}

type PluginConfig struct {
	Name        string   `yaml:"name"`
	Version     string   `yaml:"version"`
	Description string   `yaml:"description"`
	HookType    string   `yaml:"hook_type"`
	Hooks       []string `yaml:"hooks"`
	RingbufMap  string   `yaml:"ringbuf_map"`
}

type PluginInstance struct {
	Config PluginConfig
	Coll   *ebpf.Collection
	Links  []link.Link
	Reader *ringbuf.Reader
}

type PluginManager struct {
	pluginsDir string
	plugins    map[string]*PluginInstance
	callback   func(name string, raw []byte)
}

func NewPluginManager(dir string, callback func(name string, raw []byte)) *PluginManager {
	return &PluginManager{
		pluginsDir: dir,
		plugins:    make(map[string]*PluginInstance),
		callback:   callback,
	}
}

func (pm *PluginManager) ScanAndLoad() error {
	if _, err := os.Stat(pm.pluginsDir); os.IsNotExist(err) {
		log.Printf("📁 插件目录不存在，跳过: %s", pm.pluginsDir)
		return nil
	}

	entries, err := os.ReadDir(pm.pluginsDir)
	if err != nil {
		return fmt.Errorf("扫描插件目录失败: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() { continue }
		pluginPath := filepath.Join(pm.pluginsDir, entry.Name())
		configPath := filepath.Join(pluginPath, "probe.yaml")
		objPath := filepath.Join(pluginPath, "probe.bpf.o")
		if _, err := os.Stat(configPath); os.IsNotExist(err) { continue }
		if _, err := os.Stat(objPath); os.IsNotExist(err) { continue }
		if err := pm.loadPlugin(entry.Name(), configPath, objPath); err != nil {
			log.Printf("⚠️ 加载插件 %s 失败: %v", entry.Name(), err)
		}
	}

	log.Printf("🧩 已加载 %d 个外部插件", len(pm.plugins))
	return nil
}

func (pm *PluginManager) loadPlugin(name, configPath, objPath string) error {
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置失败: %w", err)
	}
	var cfg PluginConfig
	if err := yaml.Unmarshal(configData, &cfg); err != nil {
		return fmt.Errorf("解析配置失败: %w", err)
	}

	// 用NewCollection加载，保留programs在map里
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("加载字节码失败: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("创建collection失败: %w", err)
	}

	// Attach
	var links []link.Link
	for _, hook := range cfg.Hooks {
		parts := strings.SplitN(hook, "/", 2)
		if len(parts) != 2 {
			coll.Close()
			return fmt.Errorf("hook格式错误: %s", hook)
		}
		category, hookName := parts[0], parts[1]

		// 取第一个program
		var prog *ebpf.Program
		for _, p := range coll.Programs {
			prog = p
			break
		}
		if prog == nil {
			coll.Close()
			return fmt.Errorf("字节码中没有program")
		}

		l, err := link.Tracepoint(category, hookName, prog, nil)
		if err != nil {
			coll.Close()
			return fmt.Errorf("attach失败: %w", err)
		}
		links = append(links, l)
	}

	// Ringbuf reader
	var reader *ringbuf.Reader
	if cfg.RingbufMap != "" {
		if m, ok := coll.Maps[cfg.RingbufMap]; ok {
			reader, err = ringbuf.NewReader(m)
			if err != nil {
				coll.Close()
				return fmt.Errorf("创建reader失败: %w", err)
			}
		}
	}

	inst := &PluginInstance{Config: cfg, Coll: coll, Links: links, Reader: reader}
	pm.plugins[name] = inst

	if reader != nil {
		go pm.readEvents(name, inst)
	}

	log.Printf("✅ 插件已加载: %s (hooks: %v)", cfg.Name, cfg.Hooks)
	return nil
}

func (pm *PluginManager) readEvents(name string, inst *PluginInstance) {
	for {
		record, err := inst.Reader.Read()
		if err != nil {
			return
		}
		pm.callback(name, record.RawSample)
	}
}

func (pm *PluginManager) ListPlugins() []PluginMeta {
	list := make([]PluginMeta, 0, len(pm.plugins))
	for _, inst := range pm.plugins {
		list = append(list, PluginMeta{Name: inst.Config.Name, Version: inst.Config.Version, Desc: inst.Config.Description, Hooks: inst.Config.Hooks})
	}
	return list
}

func (pm *PluginManager) Close() {
	for name, inst := range pm.plugins {
		if inst.Reader != nil { inst.Reader.Close() }
		for _, l := range inst.Links { l.Close() }
		inst.Coll.Close()
		log.Printf("📤 插件已卸载: %s", name)
	}
}

// LoadSingle 加载单个插件
func (pm *PluginManager) LoadSingle(name string) error {
	pluginPath := filepath.Join(pm.pluginsDir, name)
	configPath := filepath.Join(pluginPath, "probe.yaml")
	objPath := filepath.Join(pluginPath, "probe.bpf.o")

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("插件 %s 不存在", name)
	}
	if _, err := os.Stat(objPath); os.IsNotExist(err) {
		return fmt.Errorf("插件 %s 缺少 probe.bpf.o", name)
	}

	// 先卸载旧版本
	if _, exists := pm.plugins[name]; exists {
		pm.Unload(name)
	}

	return pm.loadPlugin(name, configPath, objPath)
}

// Unload 卸载插件
func (pm *PluginManager) Unload(name string) error {
	inst, exists := pm.plugins[name]
	if !exists {
		return fmt.Errorf("插件 %s 未加载", name)
	}

	if inst.Reader != nil { inst.Reader.Close() }
	for _, l := range inst.Links { l.Close() }
	inst.Coll.Close()
	delete(pm.plugins, name)
	os.RemoveAll(filepath.Join(pm.pluginsDir, name))
	log.Printf("📤 插件已卸载: %s", name)
	return nil
}

// InstallProbe 安装并加载插件（接收Server下发的文件）
func (pm *PluginManager) InstallProbe(name string, data []byte, configYAML string) error {
	pluginPath := filepath.Join(pm.pluginsDir, name)
	os.MkdirAll(pluginPath, 0755)

	// 写入 probe.bpf.o
	objPath := filepath.Join(pluginPath, "probe.bpf.o")
	// base64解码
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err == nil {
		data = decoded
	}
	if err := os.WriteFile(objPath, data, 0644); err != nil {
		return fmt.Errorf("写入字节码失败: %w", err)
	}

	// 写入 probe.yaml
	configPath := filepath.Join(pluginPath, "probe.yaml")
	if err := os.WriteFile(configPath, []byte(configYAML), 0644); err != nil {
		return fmt.Errorf("写入配置失败: %w", err)
	}

	log.Printf("📦 插件已安装: %s", name)

	// 立即加载
	return pm.LoadSingle(name)
}

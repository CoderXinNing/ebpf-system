package config

import (
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

// AgentConfig Agent完整配置
type AgentConfig struct {
	XDP              XDPConfig        `toml:"xdp"`
	Agent    AgentSection    `toml:"agent"`
	Autoload []ProbeConfig   `toml:"autoload"`
}

// AgentSection Agent基础配置
type AgentSection struct {
	Name              string        `toml:"name"`
	Server            string        `toml:"server"`
	RetryDelay        time.Duration `toml:"retry_delay"`
	HeartbeatInterval time.Duration `toml:"heartbeat_interval"`
	CollectInterval   time.Duration `toml:"collect_interval"`
}
type ProbeConfig struct {
	Name    string `toml:"name"`
	ID      string `toml:"id"`
	Enabled bool   `toml:"enabled"`
	Path    string `toml:"path"`  // .o 文件路径，为空时用默认
}

// DefaultConfig 返回默认配置
func DefaultConfig() *AgentConfig {
	return &AgentConfig{
		Agent: AgentSection{
			Name:              "",
			Server:            "127.0.0.1:50051",
			RetryDelay:        5 * time.Second,
			HeartbeatInterval: 10 * time.Second,
		CollectInterval:   300 * time.Second,
		},
	}
}

// Load 从文件加载配置
func Load(path string) (*AgentConfig, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	if _, err := toml.Decode(string(data), cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 校验
	if cfg.Agent.Server == "" {
		return nil, fmt.Errorf("server地址不能为空")
	}

	return cfg, nil
}

// GenerateDefault 生成默认配置文件
func GenerateDefault(path string) error {
	cfg := DefaultConfig()
	cfg.Autoload = []ProbeConfig{
		{Name: "exec_monitor", ID: "auto-exec-001", Enabled: false,
			Path: "probes/templates/exec_monitor_ebpf/exec_monitor.o"},
	}

	data, err := toml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
func UpdateGroup(group string) {}

type XDPConfig struct {
	Enabled    bool   `toml:"enabled"`
	Iface      string `toml:"iface"`
	ServerIP   string `toml:"server_ip"`
	ServerPort int    `toml:"server_port"`
}

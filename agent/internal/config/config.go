package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// AgentConfig Agent完整配置
type AgentConfig struct {
	Agent    AgentSection    `yaml:"agent"`
	Autoload []ProbeConfig   `yaml:"autoload"`
}

// AgentSection Agent基础配置
type AgentSection struct {
	Name              string        `yaml:"name"`
	Server            string        `yaml:"server"`
	RetryDelay        time.Duration `yaml:"retry_delay"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	Group             string        `yaml:"group"`
	CollectInterval   time.Duration `yaml:"collect_interval"`
}
type ProbeConfig struct {
	Name    string `yaml:"name"`
	ID      string `yaml:"id"`
	Enabled bool   `yaml:"enabled"`
}

// DefaultConfig 返回默认配置
func DefaultConfig() *AgentConfig {
	return &AgentConfig{
		Agent: AgentSection{
			Name:              "",
			Server:            "127.0.0.1:50051",
			RetryDelay:        5 * time.Second,
			HeartbeatInterval: 10 * time.Second,
		Group:             "默认组",
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

	if err := yaml.Unmarshal(data, cfg); err != nil {
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
		{Name: "exec_monitor", ID: "auto-exec-001", Enabled: false},
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

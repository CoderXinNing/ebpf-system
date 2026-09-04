package config

import (
	"fmt"
	"log"

	"github.com/BurntSushi/toml"
)

// Config 是 Server 端统一配置
type Config struct {
	Server   ServerConfig   `toml:"server"`
	Database DatabaseConfig `toml:"database"`
	TLS      TLSConfig      `toml:"tls"`
	Log      LogConfig      `toml:"log"`
}

type ServerConfig struct {
	HTTPPort int    `toml:"http_port"`
	GRPCPort int    `toml:"grpc_port"`
	Token    string `toml:"token"`
}

type DatabaseConfig struct {
	Path string `toml:"path"` // SQLite 路径（Phase 3 迁移 PSQL 后替换）
}

type TLSConfig struct {
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
	CAFile   string `toml:"ca_file"`
}

type LogConfig struct {
	Level  string `toml:"level"`
	Format string `toml:"format"` // "text" 或 "json"
}

// Load 从 TOML 文件加载配置。文件不存在时返回默认配置。
func Load(path string) *Config {
	cfg := &Config{
		Server: ServerConfig{
			HTTPPort: 8080,
			GRPCPort: 50051,
		},
		Database: DatabaseConfig{
			Path: "sentinel.db",
		},
		TLS: TLSConfig{
			CertFile: "certs/server.crt",
			KeyFile:  "certs/server.key",
			CAFile:   "certs/ca.crt",
		},
		Log: LogConfig{
			Level:  "info",
			Format: "text",
		},
	}

	if _, err := toml.DecodeFile(path, cfg); err != nil {
		log.Printf("⚠️ 配置文件读取失败，使用默认配置: %v", err)
	}
	return cfg
}

// Validate 检查配置合法性
func (c *Config) Validate() error {
	if c.Server.HTTPPort <= 0 || c.Server.HTTPPort > 65535 {
		return fmt.Errorf("无效的 HTTP 端口: %d", c.Server.HTTPPort)
	}
	if c.Server.GRPCPort <= 0 || c.Server.GRPCPort > 65535 {
		return fmt.Errorf("无效的 gRPC 端口: %d", c.Server.GRPCPort)
	}
	if c.Database.Path == "" {
		return fmt.Errorf("数据库路径不能为空")
	}
	return nil
}

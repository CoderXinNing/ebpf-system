// Package paths 统一管理 Server 的文件路径。
//
// 设计：
//   - 根路径通过环境变量 ASTERTRACK_ROOT 注入
//   - 未设置时用当前工作目录
package paths

import (
	"os"
	"path/filepath"
)

const envRoot = "ASTERTRACK_ROOT"

var root = "."

// Init 初始化根路径（env > cwd）
func Init() {
	if env := os.Getenv(envRoot); env != "" {
		root = env
		return
	}
	cwd, err := os.Getwd()
	if err != nil {
		root = "."
		return
	}
	root = cwd
}

// Root 返回项目根路径
func Root() string { return root }

// Join 拼接根路径与子路径
func Join(parts ...string) string {
	return filepath.Join(append([]string{root}, parts...)...)
}

// CertsDir 证书目录
func CertsDir() string { return Join("certs") }

// Cert 证书文件路径
func Cert(name string) string { return filepath.Join(CertsDir(), name) }

// ConfigsDir 配置目录
func ConfigsDir() string { return Join("server", "configs") }

// Config 配置文件路径
func Config(name string) string { return filepath.Join(ConfigsDir(), name) }

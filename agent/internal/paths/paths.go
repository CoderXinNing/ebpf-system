// Package paths 统一管理 Agent 的文件路径。
//
// 设计：
//   - 根路径通过环境变量 ASTERTRACK_ROOT 注入（容器/生产）
//   - 未设置时用当前工作目录（开发）
//   - BPF pin 路径固定（/sys/fs/bpf/...），与 root 无关
//
// 使用前必须调用 Init()。未调用时退化为 "."（不会崩，但可能找不到文件）。
package paths

import (
	"os"
	"path/filepath"
)

const envRoot = "ASTERTRACK_ROOT"

var root = "."

// Init 初始化根路径。优先级：环境变量 > cwd。
// 必须在任何路径使用之前调用。
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

// ========== eBPF 探针 ==========

// ProbesDir eBPF 探针目录
func ProbesDir() string { return Join("v3_engine", "probes") }

// Probe .o 文件路径
func Probe(name string) string { return filepath.Join(ProbesDir(), name) }

// ========== 证书 ==========

// CertsDir 证书目录
func CertsDir() string { return Join("certs") }

// Cert 证书文件路径
func Cert(name string) string { return filepath.Join(CertsDir(), name) }

// ========== Agent 数据 ==========

// AgentDataDir Agent 数据目录
func AgentDataDir() string { return Join("agent", "data") }

// AgentIDFile agent.id 路径
func AgentIDFile() string { return filepath.Join(AgentDataDir(), "agent.id") }

// BaselineFile baseline.json 路径
func BaselineFile() string { return filepath.Join(AgentDataDir(), "baseline.json") }

// ========== 动态规则缓存 ==========

// RulesCacheFile 规则内容缓存路径（canonical JSON）
func RulesCacheFile() string { return filepath.Join(AgentDataDir(), "rules.json") }

// RulesSigFile 规则签名缓存路径
func RulesSigFile() string { return filepath.Join(AgentDataDir(), "rules.sig") }

// ProbeListCacheFile 探针名单旧明文缓存路径（迁移用，新版本不再写）
func ProbeListCacheFile() string { return filepath.Join(AgentDataDir(), "probes.json") }

// ProbeListEncFile 探针名单加密缓存路径（离线保命模式用）
//
// 内容：Server 最后一次下发的探针名单 + SHA256。
// 与 rules.enc 同套加密：AES-GCM + HKDF(machine-id + agent.id)。
// 视为安全资产：防御能力清单 + .o SHA256。
func ProbeListEncFile() string { return filepath.Join(AgentDataDir(), "probes.enc") }

// RulesEncFile 规则加密缓存路径（Phase 3）
// 格式：[nonce(12) | ciphertext | tag(16)]，AES-GCM
// 密钥源：/etc/machine-id + agent.id → HKDF-SHA256 → 32 字节
func RulesEncFile() string { return filepath.Join(AgentDataDir(), "rules.enc") }

// ========== BPF pin（固定路径，与 root 无关）==========

// PinBase BPF pin 基路径
func PinBase() string { return "/sys/fs/bpf/ebpf-sentinel" }

// PinMap BPF map pin 路径
func PinMap(name string) string { return filepath.Join(PinBase(), name) }

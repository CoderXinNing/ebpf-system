// Package rules 规则内容结构 + canonical JSON（Server 签 / Agent 验，必须一致）。
//
// ⚠️ 关键：canonical 序列化规范
//
//	Server 和 Agent 各自序列化同一份规则，必须字节级一致，否则验签失败。
//	规范：JSON 字段固定顺序（结构体定义顺序），无空格，无多余转义。
//
// ⚠️ 新增字段时：
//   - 追加到结构体末尾（不修改已有字段顺序）
//   - 老 Agent 忽略新字段（json 反序列化兼容），但要重新验签
package rules

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// RuleSet 动态规则集合（当前只含敏感路径，未来扩展 TCP/XDP 等）
type RuleSet struct {
	Version        int64           `json:"version"`
	SensitivePaths *SensitivePaths `json:"sensitive_paths,omitempty"`
	// 未来扩展：
	// TCPMonitor   *TCPMonitor   `json:"tcp_monitor,omitempty"`
	// XDPReporter  *XDPReporter  `json:"xdp_reporter,omitempty"`
}

// SensitivePaths file_access 探针的敏感路径规则
type SensitivePaths struct {
	ExactPaths  []string `json:"exact_paths"`
	PrefixPaths []string `json:"prefix_paths"`
}

// Constants 硬性限制（Server 校验 + Agent 兜底）
const (
	MaxPathLen = 255  // 单路径最大长度（LPM_TRIE key 的 path 字段 256 字节，需留 \0）
	MaxEntries = 1024 // 单类型最大条数
)

// Canonical 把 RuleSet 序列化为 canonical JSON（用于签名）。
//
// 实现：直接 json.Marshal（Go 的 struct 字段顺序是定义顺序，稳定）。
// 约束：结构体字段必须固定顺序，新增只能追加。
func Canonical(rs *RuleSet) ([]byte, error) {
	data, err := json.Marshal(rs)
	if err != nil {
		return nil, fmt.Errorf("canonical 序列化失败: %w", err)
	}
	return data, nil
}

// Hash 返回 canonical JSON 的 SHA256 十六进制
func Hash(rs *RuleSet) (string, error) {
	data, err := Canonical(rs)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:]), nil
}

// Validate 校验规则（Server 配置时 + Agent 加载时都要过）
func Validate(rs *RuleSet) error {
	if rs == nil {
		return fmt.Errorf("规则为空")
	}
	if rs.Version <= 0 {
		return fmt.Errorf("version 必须 > 0")
	}
	if rs.SensitivePaths != nil {
		sp := rs.SensitivePaths
		if len(sp.ExactPaths) > MaxEntries {
			return fmt.Errorf("exact_paths 超限: %d > %d", len(sp.ExactPaths), MaxEntries)
		}
		if len(sp.PrefixPaths) > MaxEntries {
			return fmt.Errorf("prefix_paths 超限: %d > %d", len(sp.PrefixPaths), MaxEntries)
		}
		for _, p := range sp.ExactPaths {
			if p == "" || len(p) > MaxPathLen {
				return fmt.Errorf("exact_paths 无效（长度 %d）: %q", len(p), p)
			}
		}
		for _, p := range sp.PrefixPaths {
			if p == "" || len(p) > MaxPathLen {
				return fmt.Errorf("prefix_paths 无效（长度 %d）: %q", len(p), p)
			}
			if p[len(p)-1] != '/' {
				return fmt.Errorf("prefix_paths 必须以 / 结尾: %q", p)
			}
		}
	}
	return nil
}

// Package rules 规则内容结构 + canonical JSON（Server 签 / Agent 验，必须一致）。
//
// ⚠️ 关键：canonical 序列化规范
//
//	Server 和 Agent 各自序列化同一份规则，必须字节级一致，否则验签失败。
//	规范：JSON 字段固定顺序（结构体定义顺序），无空格。
//
// ⚠️ 新增字段时：
//   - 追加到结构体末尾
//   - 老 Agent 忽略新字段（json 反序列化兼容）
//
// 结构演进：
//
//	v1: sensitive_paths（扁平，遗留）
//	v2: 探针分节 + 每节 rules/whitelist
package rules

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// RuleSet 动态规则集合
type RuleSet struct {
	Version int64 `json:"version"`

	// v1（遗留，只读兼容）
	SensitivePaths *SensitivePaths `json:"sensitive_paths,omitempty"`

	// v2（新结构，按探针分节）
	FileAccess *FileAccessRules `json:"file_access,omitempty"`
	Exec       *ExecRules       `json:"exec,omitempty"`
	TCP        *TCPRules        `json:"tcp,omitempty"`
}

// SensitivePaths v1 遗留结构（file_access 敏感路径）
type SensitivePaths struct {
	ExactPaths  []string `json:"exact_paths"`
	PrefixPaths []string `json:"prefix_paths"`
}

// ========== v2 结构 ==========

// FileAccessRules file_access 探针规则
type FileAccessRules struct {
	Rules     *FileAccessRulesInner `json:"rules,omitempty"`
	Whitelist *FileAccessWhitelist  `json:"whitelist,omitempty"`
}

type FileAccessRulesInner struct {
	SensitiveExact  []string `json:"sensitive_exact,omitempty"`
	SensitivePrefix []string `json:"sensitive_prefix,omitempty"`
}

type FileAccessWhitelist struct {
	ExcludeComms []string `json:"exclude_comms,omitempty"`
}

// ExecRules exec 探针规则
type ExecRules struct {
	Rules     *ExecRulesInner `json:"rules,omitempty"`
	Whitelist *ExecWhitelist  `json:"whitelist,omitempty"`
}

type ExecRulesInner struct {
	MinCmdlineLen int `json:"min_cmdline_len,omitempty"`
}

type ExecWhitelist struct {
	ExcludeComms []string `json:"exclude_comms,omitempty"`
}

// TCPRules tcp 探针规则
type TCPRules struct {
	Rules     *TCPRulesInner `json:"rules,omitempty"`
	Whitelist *TCPWhitelist  `json:"whitelist,omitempty"`
}

type TCPRulesInner struct {
	SensitivePorts []uint16 `json:"sensitive_ports,omitempty"`
}

type TCPWhitelist struct {
	ExcludeIPs []string `json:"exclude_ips,omitempty"`
}

// ========== 常量 ==========

const (
	MaxPathLen = 255  // 单路径最大长度
	MaxEntries = 1024 // 单类型最大条数
)

// ========== Canonical / Hash ==========

func Canonical(rs *RuleSet) ([]byte, error) {
	data, err := json.Marshal(rs)
	if err != nil {
		return nil, fmt.Errorf("canonical 序列化失败: %w", err)
	}
	return data, nil
}

func Hash(rs *RuleSet) (string, error) {
	data, err := Canonical(rs)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:]), nil
}

// ========== Validate ==========

// Validate 校验规则（Server 配置时 + Agent 加载时都要过）
//
// 兼容 v1（SensitivePaths）和 v2（FileAccess/Exec/TCP）
func Validate(rs *RuleSet) error {
	if rs == nil {
		return fmt.Errorf("规则为空")
	}
	if rs.Version <= 0 {
		return fmt.Errorf("version 必须 > 0")
	}

	// v1 遗留校验
	if rs.SensitivePaths != nil {
		if err := validateSensitivePaths(rs.SensitivePaths); err != nil {
			return err
		}
	}

	// v2 校验
	if rs.FileAccess != nil {
		if err := validateFileAccess(rs.FileAccess); err != nil {
			return err
		}
	}
	if rs.Exec != nil {
		if err := validateExec(rs.Exec); err != nil {
			return err
		}
	}
	if rs.TCP != nil {
		if err := validateTCP(rs.TCP); err != nil {
			return err
		}
	}

	return nil
}

func validateSensitivePaths(sp *SensitivePaths) error {
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
	return nil
}

func validateFileAccess(fa *FileAccessRules) error {
	if fa.Rules == nil {
		return nil
	}
	r := fa.Rules
	if len(r.SensitiveExact) > MaxEntries {
		return fmt.Errorf("file_access.rules.sensitive_exact 超限: %d > %d", len(r.SensitiveExact), MaxEntries)
	}
	if len(r.SensitivePrefix) > MaxEntries {
		return fmt.Errorf("file_access.rules.sensitive_prefix 超限: %d > %d", len(r.SensitivePrefix), MaxEntries)
	}
	for _, p := range r.SensitiveExact {
		if p == "" || len(p) > MaxPathLen {
			return fmt.Errorf("file_access.rules.sensitive_exact 无效: %q", p)
		}
	}
	for _, p := range r.SensitivePrefix {
		if p == "" || len(p) > MaxPathLen {
			return fmt.Errorf("file_access.rules.sensitive_prefix 无效: %q", p)
		}
		if p[len(p)-1] != '/' {
			return fmt.Errorf("file_access.rules.sensitive_prefix 必须以 / 结尾: %q", p)
		}
	}
	if fa.Whitelist != nil {
		if len(fa.Whitelist.ExcludeComms) > MaxEntries {
			return fmt.Errorf("file_access.whitelist.exclude_comms 超限")
		}
	}
	return nil
}

func validateExec(e *ExecRules) error {
	if e.Whitelist != nil {
		if len(e.Whitelist.ExcludeComms) > MaxEntries {
			return fmt.Errorf("exec.whitelist.exclude_comms 超限")
		}
	}
	return nil
}

func validateTCP(t *TCPRules) error {
	if t.Rules != nil {
		if len(t.Rules.SensitivePorts) > MaxEntries {
			return fmt.Errorf("tcp.rules.sensitive_ports 超限")
		}
	}
	if t.Whitelist != nil {
		if len(t.Whitelist.ExcludeIPs) > MaxEntries {
			return fmt.Errorf("tcp.whitelist.exclude_ips 超限")
		}
	}
	return nil
}

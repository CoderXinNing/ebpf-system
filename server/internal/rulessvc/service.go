// Package rulessvc 规则签名/发布服务（Server 侧）。
//
// 职责：
//   - 加载 CA 私钥（用于签名）
//   - 校验规则内容
//   - canonical JSON + hash + 签名
//   - 写入 DB
package rulessvc

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/CoderXinNing/ebpf-system/internal/rules"
	"github.com/CoderXinNing/ebpf-system/internal/rulesign"
	"github.com/CoderXinNing/ebpf-system/server/internal/repository/psql"
)

// Service 规则发布服务
type Service struct {
	repo     *psql.PSQL
	caKeyPEM []byte // CA 私钥 PEM
}

// New 创建服务。caKeyPath 通常是 certs/ca.key
func New(repo *psql.PSQL, caKeyPath string) (*Service, error) {
	keyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("读取 CA 私钥失败: %w", err)
	}
	return &Service{repo: repo, caKeyPEM: keyPEM}, nil
}

// Publish 发布新版本规则（校验 → canonical → hash → 签名 → 写 DB）
func (s *Service) Publish(ctx context.Context, rs *rules.RuleSet, createdBy string) (int64, error) {
	// 版本自增（如果未指定）——必须在 Validate 前，否则 rs.Version=0 会被校验拦死
	if rs.Version <= 0 {
		cur, _, err := s.repo.GetAgentRulesVersion(ctx)
		if err != nil {
			return 0, err
		}
		rs.Version = cur + 1
	}

	if err := rules.Validate(rs); err != nil {
		return 0, fmt.Errorf("规则校验失败: %w", err)
	}

	canonical, err := rules.Canonical(rs)
	if err != nil {
		return 0, err
	}

	sha256hex, err := rules.Hash(rs)
	if err != nil {
		return 0, err
	}

	sig, err := rulesign.Sign(s.caKeyPEM, canonical)
	if err != nil {
		return 0, fmt.Errorf("签名失败: %w", err)
	}

	if err := s.repo.InsertAgentRules(ctx, rs.Version, canonical, sha256hex, sig, createdBy); err != nil {
		return 0, err
	}

	log.Printf("📋 规则已发布: version=%d sha256=%s... created_by=%s",
		rs.Version, sha256hex[:16], createdBy)
	return rs.Version, nil
}

// GetVersion 返回当前规则的 version + sha256（供 Agent 快速比对）
// 无规则时返回 (0, "", nil)
func (s *Service) GetVersion(ctx context.Context) (int64, string, error) {
	return s.repo.GetAgentRulesVersion(ctx)
}

// GetFull 返回当前完整规则（content + signature）
// 无规则时返回 (nil, nil)
func (s *Service) GetFull(ctx context.Context) (*psql.AgentRuleRecord, error) {
	return s.repo.GetLatestAgentRules(ctx)
}

// RebuildFromDB 从 DB 读排除名单表 + 现有规则，合并成新 RuleSet 并 Publish
//
// 用途：探针排除名单 handler 的 Add/Remove 后调用，把变化同步到 agent_rules
func (s *Service) RebuildFromDB(ctx context.Context, createdBy string) error {
	// 1. 读三维度排除名单
	excludeComms, err := s.repo.ListProbeExcludeComms(ctx)
	if err != nil {
		return fmt.Errorf("读 exec+bash 排除名单失败: %w", err)
	}
	fileAccessComms, err := s.repo.ListFileAccessExcludeComms(ctx)
	if err != nil {
		return fmt.Errorf("读 file_access 排除名单失败: %w", err)
	}
	tcpIPs, err := s.repo.ListExcludeIPs(ctx)
	if err != nil {
		return fmt.Errorf("读 tcp IP 排除名单失败: %w", err)
	}

	// 2. 读当前最新 RuleSet（保留 file_access 等其他规则）
	rec, err := s.repo.GetLatestAgentRules(ctx)
	if err != nil {
		return fmt.Errorf("读当前规则失败: %w", err)
	}

	var rs *rules.RuleSet
	if rec != nil && len(rec.Content) > 0 {
		var loaded rules.RuleSet
		if err := json.Unmarshal(rec.Content, &loaded); err != nil {
			return fmt.Errorf("解析现有规则失败: %w", err)
		}
		rs = &loaded
	} else {
		// 无现有规则：用默认基础
		rs = defaultRules()
	}

	// 3. 合并 exec+bash 共享 comm 排除
	//    （bash 无独立 JSON 节，读 rs.Exec.Exclude；见 PROJECT-STATUS #11）
	if rs.Exec == nil {
		rs.Exec = &rules.ExecRules{}
	}
	rs.Exec.Exclude = &rules.ExecExclude{
		Comms: excludeComms,
	}

	// 4. 合并 file_access 独立 comm 排除
	if rs.FileAccess == nil {
		rs.FileAccess = &rules.FileAccessRules{}
	}
	rs.FileAccess.Exclude = &rules.FileAccessExclude{
		Comms: fileAccessComms,
	}

	// 5. 合并 tcp 独立 IP 排除
	if rs.TCP == nil {
		rs.TCP = &rules.TCPRules{}
	}
	rs.TCP.Exclude = &rules.TCPExclude{
		IPs: tcpIPs,
	}

	// 6. 清空 Version，让 Publish 自动自增
	rs.Version = 0

	// 7. Publish
	_, err = s.Publish(ctx, rs, createdBy)
	return err
}

// defaultRules 首次无规则时的默认内容
func defaultRules() *rules.RuleSet {
	return &rules.RuleSet{
		FileAccess: &rules.FileAccessRules{
			Rules: &rules.FileAccessRulesInner{
				SensitiveExact: []string{
					"/etc/shadow",
					"/etc/passwd",
					"/etc/sudoers",
				},
				SensitivePrefix: []string{
					"/root/.ssh/",
					"/home/",
					"/var/log/auth/",
				},
			},
		},
		TCP: &rules.TCPRules{
			Rules: &rules.TCPRulesInner{
				SensitivePorts: []uint16{22, 3389, 445, 21, 1433, 3306, 6379, 5985, 8080, 8443},
			},
		},
	}
}

// EnsureDefault 首次启动时若无规则，自举默认规则
func (s *Service) EnsureDefault(ctx context.Context) error {
	version, _, err := s.repo.GetAgentRulesVersion(ctx)
	if err != nil {
		return err
	}
	if version > 0 {
		return nil // 已有规则
	}

	log.Printf("📋 首次启动：初始化默认规则（v2 结构）")
	def := &rules.RuleSet{
		Version: 1,
		FileAccess: &rules.FileAccessRules{
			Rules: &rules.FileAccessRulesInner{
				SensitiveExact: []string{
					"/etc/shadow",
					"/etc/passwd",
					"/etc/sudoers",
				},
				SensitivePrefix: []string{
					"/root/.ssh/",
					"/home/",
					"/var/log/auth/",
				},
			},
		},
		TCP: &rules.TCPRules{
			Rules: &rules.TCPRulesInner{
				SensitivePorts: []uint16{22, 3389, 445, 21, 1433, 3306, 6379, 5985, 8080, 8443},
			},
		},
	}
	_, err = s.Publish(ctx, def, "system:init")
	return err
}

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
	if err := rules.Validate(rs); err != nil {
		return 0, fmt.Errorf("规则校验失败: %w", err)
	}

	// 版本自增（如果未指定）
	if rs.Version <= 0 {
		cur, _, err := s.repo.GetAgentRulesVersion(ctx)
		if err != nil {
			return 0, err
		}
		rs.Version = cur + 1
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

// EnsureDefault 首次启动时若无规则，自举默认规则
func (s *Service) EnsureDefault(ctx context.Context) error {
	version, _, err := s.repo.GetAgentRulesVersion(ctx)
	if err != nil {
		return err
	}
	if version > 0 {
		return nil // 已有规则
	}

	log.Printf("📋 首次启动：初始化默认规则")
	def := &rules.RuleSet{
		Version: 1,
		SensitivePaths: &rules.SensitivePaths{
			ExactPaths: []string{
				"/etc/shadow",
				"/etc/passwd",
				"/etc/sudoers",
			},
			PrefixPaths: []string{
				"/root/.ssh/",
				"/home/",
				"/var/log/auth/",
			},
		},
	}
	_, err = s.Publish(ctx, def, "system:init")
	return err
}

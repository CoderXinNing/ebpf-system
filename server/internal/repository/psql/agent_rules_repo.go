package psql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/CoderXinNing/ebpf-system/internal/rules"
	"github.com/jackc/pgx/v5"
)

// AgentRuleRecord agent_rules 表的一行
type AgentRuleRecord struct {
	ID        int64
	Version   int64
	Content   []byte // canonical JSON
	SHA256    string
	Signature string
	CreatedBy string
}

// GetLatestAgentRules 取当前生效规则（version 最大）
// 无记录时返回 nil, nil
func (p *PSQL) GetLatestAgentRules(ctx context.Context) (*AgentRuleRecord, error) {
	row := p.pool.QueryRow(ctx,
		`SELECT id, version, content, sha256, signature, COALESCE(created_by, '')
		 FROM agent_rules ORDER BY version DESC LIMIT 1`)

	var rec AgentRuleRecord
	if err := row.Scan(&rec.ID, &rec.Version, &rec.Content, &rec.SHA256, &rec.Signature, &rec.CreatedBy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("查询 agent_rules 失败: %w", err)
	}
	return &rec, nil
}

// InsertAgentRules 插入新版本（version 由调用方决定，通常 = 当前最大 + 1）
func (p *PSQL) InsertAgentRules(ctx context.Context, version int64, content []byte, sha256, signature, createdBy string) error {
	// 校验 content 是合法 JSON
	if !json.Valid(content) {
		return fmt.Errorf("content 不是合法 JSON")
	}

	_, err := p.pool.Exec(ctx,
		`INSERT INTO agent_rules (version, content, sha256, signature, created_by)
		 VALUES ($1, $2, $3, $4, $5)`,
		version, content, sha256, signature, createdBy)
	if err != nil {
		return fmt.Errorf("插入 agent_rules 失败: %w", err)
	}
	return nil
}

// GetAgentRulesVersion 只取 version + sha256（供 Agent 快速比对）
func (p *PSQL) GetAgentRulesVersion(ctx context.Context) (int64, string, error) {
	row := p.pool.QueryRow(ctx,
		`SELECT version, sha256 FROM agent_rules ORDER BY version DESC LIMIT 1`)

	var version int64
	var sha256 string
	if err := row.Scan(&version, &sha256); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, "", nil
		}
		return 0, "", fmt.Errorf("查询规则版本失败: %w", err)
	}
	return version, sha256, nil
}

// 确保 rules 包被引用（未来解耦时可移除）
var _ = rules.MaxPathLen

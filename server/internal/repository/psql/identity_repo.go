package psql

import (
	"context"
	"fmt"
	"time"
)

// GetAgentPublicKeyHash 获取 Agent 公钥哈希（L3 Key Binding）
func (p *PSQL) GetAgentPublicKeyHash(ctx context.Context, agentID string) ([]byte, error) {
	var hash []byte
	err := p.pool.QueryRow(ctx,
		`SELECT public_key_hash FROM agents WHERE agent_id = $1`,
		agentID).Scan(&hash)
	if err != nil {
		return nil, fmt.Errorf("查询公钥哈希失败: %w", err)
	}
	return hash, nil
}

// IsAgentRevoked 检查 Agent 是否已撤销（L4 Revocation）
func (p *PSQL) IsAgentRevoked(ctx context.Context, agentID string) (bool, error) {
	var revokedAt *time.Time
	err := p.pool.QueryRow(ctx,
		`SELECT revoked_at FROM agents WHERE agent_id = $1`,
		agentID).Scan(&revokedAt)
	if err != nil {
		return false, fmt.Errorf("查询撤销状态失败: %w", err)
	}
	return revokedAt != nil, nil
}

// GetAgentCertExpiresAt 获取证书过期时间
func (p *PSQL) GetAgentCertExpiresAt(ctx context.Context, agentID string) (*time.Time, error) {
	var expiresAt *time.Time
	err := p.pool.QueryRow(ctx,
		`SELECT cert_expires_at FROM agents WHERE agent_id = $1`,
		agentID).Scan(&expiresAt)
	if err != nil {
		return nil, fmt.Errorf("查询证书过期时间失败: %w", err)
	}
	return expiresAt, nil
}

// RevokeAgent 撤销 Agent（L4）
func (p *PSQL) RevokeAgent(ctx context.Context, agentID string) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE agents SET revoked_at = NOW() WHERE agent_id = $1 AND revoked_at IS NULL`,
		agentID)
	if err != nil {
		return fmt.Errorf("撤销 Agent 失败: %w", err)
	}
	return nil
}

// IsAgentExists 检查 Agent 是否已注册
func (p *PSQL) IsAgentExists(ctx context.Context, agentID string) (bool, error) {
	var exists bool
	err := p.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = $1)`,
		agentID).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

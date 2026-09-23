package psql

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// EnrollmentToken 注册 Token
type EnrollmentToken struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	GroupID    *int64     `json:"group_id"`
	MaxUses    int        `json:"max_uses"`
	UsedCount  int        `json:"used_count"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

// GenerateToken 生成注册 Token
// 返回明文 token（仅此一次），数据库只存 hash
func (p *PSQL) GenerateToken(ctx context.Context, name string, groupID *int64, maxUses int, ttl time.Duration, createdBy string) (string, error) {
	if maxUses <= 0 {
		maxUses = 1
	}

	// 生成 24 字节随机 → 48 hex 字符
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("生成随机数失败: %w", err)
	}
	token := "ATK-" + hex.EncodeToString(raw)

	// 计算 hash
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	expiresAt := time.Now().Add(ttl)

	_, err := p.pool.Exec(ctx,
		`INSERT INTO enrollment_tokens (token_hash, name, group_id, max_uses, expires_at, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		tokenHash, name, groupID, maxUses, expiresAt, createdBy)
	if err != nil {
		return "", fmt.Errorf("保存 Token 失败: %w", err)
	}

	return token, nil
}

// ListTokens 列出所有 Token
func (p *PSQL) ListTokens(ctx context.Context) ([]*EnrollmentToken, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, name, group_id, max_uses, used_count, expires_at, created_by, created_at, revoked_at
		 FROM enrollment_tokens ORDER BY id DESC LIMIT 100`)
	if err != nil {
		return nil, fmt.Errorf("查询 Token 列表失败: %w", err)
	}
	defer rows.Close()

	result := make([]*EnrollmentToken, 0)
	for rows.Next() {
		t := &EnrollmentToken{}
		if err := rows.Scan(&t.ID, &t.Name, &t.GroupID, &t.MaxUses, &t.UsedCount,
			&t.ExpiresAt, &t.CreatedBy, &t.CreatedAt, &t.RevokedAt); err != nil {
			continue
		}
		result = append(result, t)
	}
	return result, nil
}

// RevokeToken 撤销 Token
func (p *PSQL) RevokeToken(ctx context.Context, id int64) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE enrollment_tokens SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`,
		id)
	if err != nil {
		return fmt.Errorf("撤销 Token 失败: %w", err)
	}
	return nil
}

// CleanupExpiredTokens 清理已过期且已撤销的 Token（可选，定期调用）
func (p *PSQL) CleanupExpiredTokens(ctx context.Context) error {
	_, err := p.pool.Exec(ctx,
		`DELETE FROM enrollment_tokens 
		 WHERE expires_at < NOW() - INTERVAL '30 days'
		 OR (revoked_at IS NOT NULL AND revoked_at < NOW() - INTERVAL '30 days')`)
	return err
}

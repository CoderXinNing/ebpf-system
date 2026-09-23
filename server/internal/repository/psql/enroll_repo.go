package psql

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// EnrollResult enrollment 成功后的返回信息
type EnrollResult struct {
	AgentID   string
	GroupID   *int64
	GroupName string
}

// EnrollAgent 事务化注册 Agent
//
// 关键：全程在事务内，SELECT FOR UPDATE 锁 token 行
// 防止并发使用同一 token
func (p *PSQL) EnrollAgent(ctx context.Context, req EnrollRequest) (*EnrollResult, error) {
	// 计算 token hash
	tokenHashRaw := sha256.Sum256([]byte(req.Token))
	tokenHash := hex.EncodeToString(tokenHashRaw[:])

	// 计算 public_key_hash
	pubKeyHashRaw := sha256.Sum256(req.PublicKeyDER)
	pubKeyHash := pubKeyHashRaw[:]

	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("开启事务失败: %w", err)
	}
	defer tx.Rollback(ctx)

	// ============================================
	// 1. SELECT FOR UPDATE 锁定 token 行
	// ============================================
	var tokenID int64
	var maxUses, usedCount int
	var expiresAt time.Time
	var revokedAt *time.Time
	var groupID *int64

	err = tx.QueryRow(ctx,
		`SELECT id, max_uses, used_count, expires_at, revoked_at, group_id
		 FROM enrollment_tokens
		 WHERE token_hash = $1
		 FOR UPDATE`,
		tokenHash,
	).Scan(&tokenID, &maxUses, &usedCount, &expiresAt, &revokedAt, &groupID)
	if err != nil {
		return nil, fmt.Errorf("Token 无效或不存在")
	}

	// ============================================
	// 2. 检查 token 有效性
	// ============================================
	if revokedAt != nil {
		return nil, fmt.Errorf("Token 已撤销")
	}
	if time.Now().After(expiresAt) {
		return nil, fmt.Errorf("Token 已过期")
	}
	if usedCount >= maxUses {
		return nil, fmt.Errorf("Token 使用次数已用完")
	}

	// ============================================
	// 3. 检查 agent_id 唯一
	// ============================================
	var exists bool
	err = tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = $1)`,
		req.AgentID,
	).Scan(&exists)
	if err != nil {
		return nil, fmt.Errorf("检查 agent_id 失败: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("Agent ID 已存在（%s）", req.AgentID)
	}

	// ============================================
	// 4. 创建 Agent 记录
	// ============================================
	_, err = tx.Exec(ctx,
		`INSERT INTO agents (
			agent_id, hostname, ip_addr, group_id,
			public_key_der, public_key_hash, machine_id, mac_address,
			capability_level, baseline_state, first_seen, last_seen
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'cmdb', 'learning', NOW(), NOW())`,
		req.AgentID, req.Hostname, req.IPAddr, groupID,
		req.PublicKeyDER, pubKeyHash, req.MachineID, req.MAC,
	)
	if err != nil {
		return nil, fmt.Errorf("创建 Agent 失败: %w", err)
	}

	// ============================================
	// 5. 更新 token 使用次数（达到上限即撤销）
	// ============================================
	newUsedCount := usedCount + 1
	var newRevokedAt interface{}
	if newUsedCount >= maxUses {
		newRevokedAt = time.Now()
	}

	_, err = tx.Exec(ctx,
		`UPDATE enrollment_tokens
		 SET used_count = $1, revoked_at = COALESCE($2, revoked_at)
		 WHERE id = $3`,
		newUsedCount, newRevokedAt, tokenID)
	if err != nil {
		return nil, fmt.Errorf("更新 Token 失败: %w", err)
	}

	// ============================================
	// 6. 提交
	// ============================================
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("提交事务失败: %w", err)
	}

	// 查分组名
	groupName := "未分组"
	if groupID != nil {
		var gname string
		p.pool.QueryRow(ctx, `SELECT name FROM host_groups WHERE id = $1`, *groupID).Scan(&gname)
		if gname != "" {
			groupName = gname
		}
	}

	return &EnrollResult{
		AgentID:   req.AgentID,
		GroupID:   groupID,
		GroupName: groupName,
	}, nil
}

// EnrollRequest enrollment 请求参数
type EnrollRequest struct {
	Token        string
	AgentID      string
	Hostname     string
	IPAddr       string
	MachineID    string
	MAC          string
	PublicKeyDER []byte
}

package auth

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// defaultReadIntConf 从 system_config 读整数配置
func defaultReadIntConf(pool *pgxpool.Pool) func(ctx context.Context, namespace, key string, defaultVal int) int {
	return func(ctx context.Context, namespace, key string, defaultVal int) int {
		var v string
		err := pool.QueryRow(ctx,
			`SELECT value FROM system_config WHERE namespace = $1 AND key = $2`,
			namespace, key).Scan(&v)
		if err != nil || v == "" {
			return defaultVal
		}
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return defaultVal
		}
		return n
	}
}

// CreateSession 登录成功后创建会话
//
// 返回：
//
//	sessionID  明文（嵌入 JWT，前端不直接看到）
//	dbID       sessions 表主键（用于审计关联）
func (am *AuthManager) CreateSession(ctx context.Context, userID int, ip, userAgent string, keepalive bool) (string, int64, error) {
	sessionID, err := GenerateSessionID()
	if err != nil {
		return "", 0, err
	}

	absoluteHours := am.readIntConf(ctx, "session", "absolute_hours", 8)
	now := time.Now()

	sess := &Session{
		UserID:         userID,
		SessionIDHash:  HashSessionID(sessionID),
		IP:             ip,
		UserAgent:      userAgent,
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Duration(absoluteHours) * time.Hour),
		LastActivityAt: now,
		Keepalive:      keepalive,
	}

	dbID, err := am.sessionStore.Create(ctx, sess)
	if err != nil {
		return "", 0, err
	}
	return sessionID, dbID, nil
}

// ValidateAndTouch 验证 token + 校验 session 生命周期 + 滑动续期
//
// 校验顺序：
//  1. JWT 签名有效
//  2. session 存在
//  3. 未撤销
//  4. 未超过绝对过期时间
//  5. 未超过空闲超时（keepalive 时用延长值）
//
// 通过后 Touch 更新 last_activity_at
// 返回：user / session_id（DB 主键 id）/ error
func (am *AuthManager) ValidateAndTouch(ctx context.Context, tokenStr string) (*User, int64, error) {
	user, sessionIDPlain, err := am.ValidateToken(tokenStr)
	if err != nil {
		return nil, 0, err
	}
	if sessionIDPlain == "" {
		return nil, 0, fmt.Errorf("token无效：缺少 session_id")
	}

	sess, err := am.sessionStore.GetByIDHash(ctx, HashSessionID(sessionIDPlain))
	if err != nil {
		return nil, 0, fmt.Errorf("会话不存在或已失效")
	}

	// 撤销检查
	if sess.RevokedAt != nil {
		return nil, 0, fmt.Errorf("会话已撤销")
	}

	// 绝对超时
	if time.Now().After(sess.ExpiresAt) {
		_ = am.sessionStore.Revoke(ctx, sess.ID)
		return nil, 0, fmt.Errorf("会话已过期")
	}

	// 空闲超时
	idleMinutes := am.readIntConf(ctx, "session", "idle_minutes", 10)
	if sess.Keepalive {
		idleMinutes = am.readIntConf(ctx, "session", "keepalive_extend_minutes", 60)
	}
	idleTimeout := time.Duration(idleMinutes) * time.Minute
	if time.Since(sess.LastActivityAt) > idleTimeout {
		_ = am.sessionStore.Revoke(ctx, sess.ID)
		return nil, 0, fmt.Errorf("会话空闲超时")
	}

	// 滑动续期（30 秒去重，SQL 层短路）
	_ = am.sessionStore.Touch(ctx, sess.ID)

	return user, sess.ID, nil
}

// GetSessionByID 按主键查询会话详情
func (am *AuthManager) GetSessionByID(ctx context.Context, id int64) (*Session, error) {
	// 直接用 sessionStore 接口，但需要按 id 查（接口里没有）
	// 简化：通过 pool 直接查
	var sess Session
	err := am.pool.QueryRow(ctx,
		`SELECT id, user_id, session_id_hash, COALESCE(ip,''), COALESCE(user_agent,''),
		        created_at, expires_at, revoked_at, last_activity_at, keepalive
		 FROM sessions WHERE id = $1`, id,
	).Scan(&sess.ID, &sess.UserID, &sess.SessionIDHash, &sess.IP, &sess.UserAgent,
		&sess.CreatedAt, &sess.ExpiresAt, &sess.RevokedAt, &sess.LastActivityAt, &sess.Keepalive)
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

// GetSessionConfig 返回前端需要的会话配置
//
// 返回：idleMinutes / absoluteHours
func (am *AuthManager) GetSessionConfig(ctx context.Context) (int, int) {
	idleMinutes := am.readIntConf(ctx, "session", "idle_minutes", 10)
	absoluteHours := am.readIntConf(ctx, "session", "absolute_hours", 8)
	return idleMinutes, absoluteHours
}

// RevokeSessionByID 撤销会话（logout 调用）
func (am *AuthManager) RevokeSessionByID(ctx context.Context, sessionID int64) error {
	return am.sessionStore.Revoke(ctx, sessionID)
}

// RevokeSessionsByUserID 撤销某用户全部会话（踢下线，管理功能）
func (am *AuthManager) RevokeSessionsByUserID(ctx context.Context, userID int) error {
	return am.sessionStore.RevokeByUserID(ctx, userID)
}

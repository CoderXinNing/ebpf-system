package auth

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// configCacheEntry 配置缓存条目
type configCacheEntry struct {
	value    int
	cachedAt time.Time
}

// defaultReadIntConf 从 system_config 读整数配置（带 5 分钟内存缓存）
//
// 缓存理由：ValidateAndTouch 每次请求都读 idle_minutes，
// 高频请求下 DB 压力大。配置改动不频繁，5 分钟延迟可接受。
func defaultReadIntConf(pool *pgxpool.Pool) func(ctx context.Context, namespace, key string, defaultVal int) int {
	var cache sync.Map

	const ttl = 5 * time.Minute

	return func(ctx context.Context, namespace, key string, defaultVal int) int {
		cacheKey := namespace + "." + key

		if v, ok := cache.Load(cacheKey); ok {
			if e, ok := v.(*configCacheEntry); ok {
				if time.Since(e.cachedAt) < ttl {
					return e.value
				}
			}
		}

		var v string
		err := pool.QueryRow(ctx,
			`SELECT value FROM system_config WHERE namespace = $1 AND key = $2`,
			namespace, key).Scan(&v)
		if err != nil || v == "" {
			cache.Store(cacheKey, &configCacheEntry{value: defaultVal, cachedAt: time.Now()})
			return defaultVal
		}
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			cache.Store(cacheKey, &configCacheEntry{value: defaultVal, cachedAt: time.Now()})
			return defaultVal
		}
		cache.Store(cacheKey, &configCacheEntry{value: n, cachedAt: time.Now()})
		return n
	}
}

// CreateSession 登录成功后创建会话
//
// 返回：
//
//	sessionID  明文（嵌入 JWT，前端不直接看到）
//	dbID       sessions 表主键（用于审计关联）
func (am *AuthManager) CreateSession(ctx context.Context, userID int, ip, userAgent string) (string, int64, error) {
	sessionID, err := GenerateSessionID()
	if err != nil {
		return "", 0, err
	}

	absoluteHours := am.readIntConf(ctx, "session", "absolute_hours", 0)
	now := time.Now()

	var expiresAt *time.Time
	if absoluteHours > 0 {
		t := now.Add(time.Duration(absoluteHours) * time.Hour)
		expiresAt = &t
	}

	sess := &Session{
		UserID:         userID,
		SessionIDHash:  HashSessionID(sessionID),
		IP:             ip,
		UserAgent:      userAgent,
		CreatedAt:      now,
		ExpiresAt:      expiresAt,
		LastActivityAt: now,
		Keepalive:      false,
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
//  5. 未超过空闲超时
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

	// 绝对超时（NULL 表示禁用）
	if sess.ExpiresAt != nil && time.Now().After(*sess.ExpiresAt) {
		if err := am.sessionStore.Revoke(ctx, sess.ID); err != nil {
			fmt.Printf("⚠️ 撤销过期会话失败 (id=%d): %v\n", sess.ID, err)
		}
		return nil, 0, fmt.Errorf("会话已过期")
	}

	// 空闲超时（统一：任何后端交互都刷，由 Touch 完成）
	idleMinutes := am.readIntConf(ctx, "session", "idle_minutes", 10)
	idleTimeout := time.Duration(idleMinutes) * time.Minute
	if time.Since(sess.LastActivityAt) > idleTimeout {
		if err := am.sessionStore.Revoke(ctx, sess.ID); err != nil {
			fmt.Printf("⚠️ 撤销空闲会话失败 (id=%d): %v\n", sess.ID, err)
		}
		return nil, 0, fmt.Errorf("会话空闲超时")
	}

	// 滑动续期（30 秒去重，SQL 层短路）
	if err := am.sessionStore.Touch(ctx, sess.ID); err != nil {
		fmt.Printf("⚠️ 更新会话活动时间失败 (id=%d): %v\n", sess.ID, err)
	}

	return user, sess.ID, nil
}

// GetSessionByID 按主键查询会话详情
func (am *AuthManager) GetSessionByID(ctx context.Context, id int64) (*Session, error) {
	return am.sessionStore.GetByID(ctx, id)
}

// GetSessionConfig 返回前端需要的会话配置
//
// 返回：idleMinutes / absoluteHours / heartbeatIntervalSeconds
//   - absoluteHours = 0 表示禁用
func (am *AuthManager) GetSessionConfig(ctx context.Context) (int, int, int) {
	idleMinutes := am.readIntConf(ctx, "session", "idle_minutes", 10)
	absoluteHours := am.readIntConf(ctx, "session", "absolute_hours", 0)
	heartbeatInterval := am.readIntConf(ctx, "session", "heartbeat_interval_seconds", 180)
	return idleMinutes, absoluteHours, heartbeatInterval
}

// UpdateSessionHeartbeat 切换会话心跳开关
func (am *AuthManager) UpdateSessionHeartbeat(ctx context.Context, sessionID int64, enabled bool) error {
	return am.sessionStore.UpdateHeartbeat(ctx, sessionID, enabled)
}

// RevokeSessionByID 撤销会话（logout 调用）
func (am *AuthManager) RevokeSessionByID(ctx context.Context, sessionID int64) error {
	return am.sessionStore.Revoke(ctx, sessionID)
}

// RevokeSessionsByUserID 撤销某用户全部会话（踢下线，管理功能）
func (am *AuthManager) RevokeSessionsByUserID(ctx context.Context, userID int) error {
	return am.sessionStore.RevokeByUserID(ctx, userID)
}

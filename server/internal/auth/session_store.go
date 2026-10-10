package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Session 会话记录
type Session struct {
	ID             int64
	UserID         int
	SessionIDHash  string
	IP             string
	UserAgent      string
	CreatedAt      time.Time
	ExpiresAt      *time.Time // 绝对过期时间；NULL 表示禁用
	RevokedAt      *time.Time
	LastActivityAt time.Time
	Keepalive      bool // 心跳开关
}

// SessionStore 会话存储抽象
//
// 当前实现：PGSessionStore（单 Server，状态在 PG）
// 未来扩展：
//   - RedisSessionStore（多实例共享）
//   - HybridSessionStore（PG 持久 + Redis 缓存）
type SessionStore interface {
	Create(ctx context.Context, sess *Session) (int64, error)
	GetByIDHash(ctx context.Context, hash string) (*Session, error)
	GetByID(ctx context.Context, id int64) (*Session, error)
	Touch(ctx context.Context, id int64) error
	Revoke(ctx context.Context, id int64) error
	RevokeByUserID(ctx context.Context, userID int) error
	UpdateHeartbeat(ctx context.Context, id int64, enabled bool) error
}

// PGSessionStore PostgreSQL 实现
type PGSessionStore struct {
	pool *pgxpool.Pool
}

func NewPGSessionStore(pool *pgxpool.Pool) *PGSessionStore {
	return &PGSessionStore{pool: pool}
}

func (s *PGSessionStore) Create(ctx context.Context, sess *Session) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx,
		`INSERT INTO sessions
		   (user_id, session_id_hash, ip, user_agent, created_at, expires_at, last_activity_at, keepalive)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id`,
		sess.UserID, sess.SessionIDHash, sess.IP, sess.UserAgent,
		sess.CreatedAt, sess.ExpiresAt, sess.LastActivityAt, sess.Keepalive,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("创建会话失败: %w", err)
	}
	return id, nil
}

func (s *PGSessionStore) GetByIDHash(ctx context.Context, hash string) (*Session, error) {
	sess := &Session{}
	err := s.pool.QueryRow(ctx,
		`SELECT id, user_id, session_id_hash, COALESCE(ip,''), COALESCE(user_agent,''),
		        created_at, expires_at, revoked_at, last_activity_at, keepalive
		 FROM sessions
		 WHERE session_id_hash = $1`, hash,
	).Scan(&sess.ID, &sess.UserID, &sess.SessionIDHash, &sess.IP, &sess.UserAgent,
		&sess.CreatedAt, &sess.ExpiresAt, &sess.RevokedAt, &sess.LastActivityAt, &sess.Keepalive)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("会话不存在")
		}
		return nil, fmt.Errorf("查询会话失败: %w", err)
	}
	return sess, nil
}

// GetByID 按主键查询会话
func (s *PGSessionStore) GetByID(ctx context.Context, id int64) (*Session, error) {
	sess := &Session{}
	err := s.pool.QueryRow(ctx,
		`SELECT id, user_id, session_id_hash, COALESCE(ip,''), COALESCE(user_agent,''),
		        created_at, expires_at, revoked_at, last_activity_at, keepalive
		 FROM sessions WHERE id = $1`, id,
	).Scan(&sess.ID, &sess.UserID, &sess.SessionIDHash, &sess.IP, &sess.UserAgent,
		&sess.CreatedAt, &sess.ExpiresAt, &sess.RevokedAt, &sess.LastActivityAt, &sess.Keepalive)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("会话不存在")
		}
		return nil, fmt.Errorf("查询会话失败: %w", err)
	}
	return sess, nil
}

// Touch 滑动续期（30 秒去重，降低写压力）
func (s *PGSessionStore) Touch(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE sessions
		 SET last_activity_at = NOW()
		 WHERE id = $1
		   AND last_activity_at < NOW() - INTERVAL '30 seconds'`, id)
	return err
}

func (s *PGSessionStore) Revoke(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = NOW()
		 WHERE id = $1 AND revoked_at IS NULL`, id)
	return err
}

func (s *PGSessionStore) RevokeByUserID(ctx context.Context, userID int) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = NOW()
		 WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	return err
}

func (s *PGSessionStore) UpdateHeartbeat(ctx context.Context, id int64, enabled bool) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE sessions SET keepalive = $1 WHERE id = $2`, enabled, id)
	return err
}

// ============================================================
// 辅助函数
// ============================================================

// GenerateSessionID 生成会话 ID（CSPRNG 32 字节 → base64url 43 字符）
//
// 熵：256 位，符合 NIST 800-63B 规范
func GenerateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("生成 session_id 失败: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashSessionID 计算 session_id 明文的 SHA256 hex
func HashSessionID(sessionID string) string {
	h := sha256.Sum256([]byte(sessionID))
	return hex.EncodeToString(h[:])
}

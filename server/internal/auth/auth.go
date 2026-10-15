package auth

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
	"log"
)

// AuthConfig 认证配置
type AuthConfig struct {
	JWTSecret    string
	AdminUser    string
	AdminPass    string
	OperatorUser string
	OperatorPass string
}

// DefaultAuthConfig 返回默认配置。
//
// BUG-015：
//   - 默认口令不再内置明文
//   - 首次启动必须由环境变量提供 ADMIN_PASS，否则 log.Fatalf
//   - JWT_SECRET 若为空/过短，log.Fatalf（原默认 "dev-secret-change-me" 视为硬编码漏洞）
//
// 注：BUG-007 修的是「授权以 DB role 为准」，不解决密钥强度；
// 本函数只做「弱口令/弱密钥拒绝启动」，JWT 机制本身等 JWE 设计。
func DefaultAuthConfig() AuthConfig {
	jwtSecret := os.Getenv("JWT_SECRET")
	if len(jwtSecret) < 32 {
		log.Fatalf("❌ JWT_SECRET 未设置或过短（需 ≥32 字节）。请设置环境变量 JWT_SECRET。")
	}

	adminUser := getEnvOrDefault("ADMIN_USER", "admin")
	adminPass := os.Getenv("ADMIN_PASS")
	if adminPass == "" {
		log.Fatalf("❌ ADMIN_PASS 未设置。请设置环境变量 ADMIN_PASS（首次启动密码）。")
	}
	if len(adminPass) < 8 {
		log.Fatalf("❌ ADMIN_PASS 过短（需 ≥8 字节）。")
	}

	operatorUser := getEnvOrDefault("OPERATOR_USER", "operator")
	operatorPass := os.Getenv("OPERATOR_PASS")
	if operatorPass == "" {
		log.Fatalf("❌ OPERATOR_PASS 未设置。请设置环境变量 OPERATOR_PASS。")
	}
	if len(operatorPass) < 8 {
		log.Fatalf("❌ OPERATOR_PASS 过短（需 ≥8 字节）。")
	}

	return AuthConfig{
		JWTSecret:    jwtSecret,
		AdminUser:    adminUser,
		AdminPass:    adminPass,
		OperatorUser: operatorUser,
		OperatorPass: operatorPass,
	}
}

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

type AuthManager struct {
	pool         *pgxpool.Pool
	config       AuthConfig
	sessionStore SessionStore
	// readIntConf 从 system_config 读取整数配置（用于 session 超时参数）
	// 独立成函数字段，便于测试替换
	readIntConf func(ctx context.Context, namespace, key string, defaultVal int) int

	// roleCache 缓存 user_id → role 映射（BUG-007：授权以 DB role 为准）
	// 避免 ValidateAndTouch 每次请求都查 DB。
	// 变更 role/删用户时主动 invalidate（见 UpdateUserRole / DeleteUser）。
	roleCache sync.Map // map[int]*roleCacheEntry
}

// roleCacheEntry 角色缓存条目
type roleCacheEntry struct {
	role     string
	cachedAt time.Time
}

// roleCacheTTL 角色缓存有效期。
// 60 秒的权衡：性能（避免每请求查 DB）vs 变更传播（降权 60s 内生效）。
// 主动 invalidate 后基本立即生效。
const roleCacheTTL = 60 * time.Second

// NewAuthManager 创建认证管理器（PSQL）
func NewAuthManager(pool *pgxpool.Pool) (*AuthManager, error) {
	return NewAuthManagerWithStore(pool, DefaultAuthConfig(),
		NewPGSessionStore(pool), defaultReadIntConf(pool))
}

// NewAuthManagerWithStore 允许注入自定义 SessionStore（测试或未来 Redis）
func NewAuthManagerWithStore(
	pool *pgxpool.Pool,
	config AuthConfig,
	sessionStore SessionStore,
	readIntConf func(ctx context.Context, namespace, key string, defaultVal int) int,
) (*AuthManager, error) {
	am := &AuthManager{
		pool:         pool,
		config:       config,
		sessionStore: sessionStore,
		readIntConf:  readIntConf,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := am.CreateUser(ctx, config.AdminUser, config.AdminPass, "admin"); err != nil {
		return nil, fmt.Errorf("创建管理员失败: %w", err)
	}
	if err := am.CreateUser(ctx, config.OperatorUser, config.OperatorPass, "operator"); err != nil {
		return nil, fmt.Errorf("创建运营用户失败: %w", err)
	}
	return am, nil
}

// CreateUser 创建用户（幂等）
func (am *AuthManager) CreateUser(ctx context.Context, username, password, role string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("密码哈希失败: %w", err)
	}
	_, err = am.pool.Exec(ctx,
		`INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)
		 ON CONFLICT (username) DO NOTHING`,
		username, string(hash), role)
	return err
}

// VerifyPassword 验证用户密码
func (am *AuthManager) VerifyPassword(ctx context.Context, username, password string) (*User, error) {
	var user User
	var hash string
	err := am.pool.QueryRow(ctx,
		`SELECT id, username, password_hash, role FROM users WHERE username = $1`, username,
	).Scan(&user.ID, &user.Username, &hash, &user.Role)
	if err != nil {
		return nil, fmt.Errorf("用户不存在")
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return nil, fmt.Errorf("密码错误")
	}
	return &user, nil
}

// GenerateToken 生成 JWT（携带 session_id）
//
// TTL = session.absolute_hours（默认 0 = 禁用绝对超时，token 不过期）
//
// BUG-022：默认值从 8 改为 0，与 GetSessionConfig / CreateSession 三处统一。
// absolute_hours <= 0 时不设置 exp 字段，token 无绝对超时；
// 会话生命周期仍受 sessions.expires_at + idle 超时约束。
func (am *AuthManager) GenerateToken(user *User, sessionID string) (string, error) {
	absoluteHours := am.readIntConf(context.Background(), "session", "absolute_hours", 0)
	claims := jwt.MapClaims{
		"user_id":    user.ID,
		"username":   user.Username,
		"role":       user.Role,
		"session_id": sessionID,
	}
	if absoluteHours > 0 {
		claims["exp"] = time.Now().Add(time.Duration(absoluteHours) * time.Hour).Unix()
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(am.config.JWTSecret))
}

// ValidateToken 验证 JWT，返回 user + sessionID
func (am *AuthManager) ValidateToken(tokenStr string) (*User, string, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return []byte(am.config.JWTSecret), nil
	})
	if err != nil || !token.Valid {
		return nil, "", fmt.Errorf("token无效")
	}
	claims := token.Claims.(jwt.MapClaims)

	userID, ok := claims["user_id"].(float64)
	if !ok {
		return nil, "", fmt.Errorf("token无效：缺少 user_id")
	}
	username, _ := claims["username"].(string)
	role, _ := claims["role"].(string)
	sessionID, _ := claims["session_id"].(string)

	return &User{
		ID:       int(userID),
		Username: username,
		Role:     role,
	}, sessionID, nil
}

// ListUsers 用户列表
func (am *AuthManager) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := am.pool.Query(ctx, `SELECT id, username, role FROM users ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("查询用户列表失败: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role); err != nil {
			return nil, fmt.Errorf("扫描用户失败: %w", err)
		}
		users = append(users, u)
	}
	return users, nil
}

// GetUserByID 按 ID 查用户（BUG-007：用于授权时取 DB 最新 role）
func (am *AuthManager) GetUserByID(ctx context.Context, id int) (*User, error) {
	var u User
	err := am.pool.QueryRow(ctx,
		`SELECT id, username, role FROM users WHERE id = $1`, id).
		Scan(&u.ID, &u.Username, &u.Role)
	if err != nil {
		return nil, fmt.Errorf("用户不存在: %w", err)
	}
	return &u, nil
}

// getRoleCached 取 user_id 的最新 role（带 60s 缓存）
func (am *AuthManager) getRoleCached(ctx context.Context, userID int) (string, error) {
	if v, ok := am.roleCache.Load(userID); ok {
		if e, ok := v.(*roleCacheEntry); ok {
			if time.Since(e.cachedAt) < roleCacheTTL {
				return e.role, nil
			}
		}
	}

	u, err := am.GetUserByID(ctx, userID)
	if err != nil {
		return "", err
	}
	am.roleCache.Store(userID, &roleCacheEntry{role: u.Role, cachedAt: time.Now()})
	return u.Role, nil
}

// invalidateRoleCache 清除指定 user 的 role 缓存
func (am *AuthManager) invalidateRoleCache(userID int) {
	am.roleCache.Delete(userID)
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// HasPermission 检查角色是否有指定资源的操作权限
func (am *AuthManager) HasPermission(ctx context.Context, role string, resource string, action string) (bool, error) {
	var count int
	err := am.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM role_permissions rp
		 JOIN roles r ON rp.role_id = r.id
		 WHERE r.name = $1 AND rp.resource = $2 AND rp.action = $3`,
		role, resource, action,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("查询权限失败: %w", err)
	}
	return count > 0, nil
}

// UpdateUserRole 修改用户角色
func (am *AuthManager) UpdateUserRole(ctx context.Context, userID int, role string) error {
	_, err := am.pool.Exec(ctx, `UPDATE users SET role = $1 WHERE id = $2`, role, userID)
	if err != nil {
		return fmt.Errorf("修改角色失败: %w", err)
	}
	// BUG-007 配套：role 变更立即生效（不等缓存过期）
	am.invalidateRoleCache(userID)
	return nil
}

// DeleteUser 删除用户
//
// 配套（BUG-007 + BUG-013）：
//   - 失效 role 缓存
//   - 撤销该用户所有会话（否则已登录的 JWT 仍有效直到 exp）
func (am *AuthManager) DeleteUser(ctx context.Context, userID int) error {
	_, err := am.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	if err != nil {
		return fmt.Errorf("删除用户失败: %w", err)
	}
	am.invalidateRoleCache(userID)
	// 撤销所有会话（失败不阻塞删除，只记日志）
	if err := am.sessionStore.RevokeByUserID(ctx, userID); err != nil {
		fmt.Printf("⚠️ 撤销用户 %d 的会话失败: %v\n", userID, err)
	}
	return nil
}

// ChangePassword 修改密码
func (am *AuthManager) ChangePassword(ctx context.Context, userID int, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("密码哈希失败: %w", err)
	}
	_, err = am.pool.Exec(ctx, `UPDATE users SET password_hash = $1 WHERE id = $2`, string(hash), userID)
	if err != nil {
		return fmt.Errorf("修改密码失败: %w", err)
	}
	return nil
}

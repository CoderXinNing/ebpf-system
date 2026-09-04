package auth

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// AuthConfig 认证配置
type AuthConfig struct {
	JWTSecret    string
	AdminUser    string
	AdminPass    string
	OperatorUser string
	OperatorPass string
}

// DefaultAuthConfig 返回默认配置（开发用，生产用环境变量）
func DefaultAuthConfig() AuthConfig {
	return AuthConfig{
		JWTSecret:    getEnvOrDefault("JWT_SECRET", "dev-secret-change-me"),
		AdminUser:    getEnvOrDefault("ADMIN_USER", "admin"),
		AdminPass:    getEnvOrDefault("ADMIN_PASS", "admin123"),
		OperatorUser: getEnvOrDefault("OPERATOR_USER", "operator"),
		OperatorPass: getEnvOrDefault("OPERATOR_PASS", "operator123"),
	}
}

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

type AuthManager struct {
	pool   *pgxpool.Pool
	config AuthConfig
}

// NewAuthManager 创建认证管理器（PSQL）
func NewAuthManager(pool *pgxpool.Pool) (*AuthManager, error) {
	return NewAuthManagerWithConfig(pool, DefaultAuthConfig())
}

func NewAuthManagerWithConfig(pool *pgxpool.Pool, config AuthConfig) (*AuthManager, error) {
	am := &AuthManager{pool: pool, config: config}
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

// GenerateToken 生成 JWT
func (am *AuthManager) GenerateToken(user *User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"role":     user.Role,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	})
	return token.SignedString([]byte(am.config.JWTSecret))
}

// ValidateToken 验证 JWT
func (am *AuthManager) ValidateToken(tokenStr string) (*User, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return []byte(am.config.JWTSecret), nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("token无效")
	}
	claims := token.Claims.(jwt.MapClaims)
	return &User{
		ID:       int(claims["user_id"].(float64)),
		Username: claims["username"].(string),
		Role:     claims["role"].(string),
	}, nil
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

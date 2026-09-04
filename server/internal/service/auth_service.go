package service

import (
	"fmt"
	"time"

	"github.com/CoderXinNing/ebpf-system/server/internal/model"
	"github.com/CoderXinNing/ebpf-system/server/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// AuthService 认证业务逻辑
type AuthService struct {
	users    repository.UserRepository
	auditLog repository.AuditLogRepository
}

func NewAuthService(users repository.UserRepository, auditLog repository.AuditLogRepository) *AuthService {
	return &AuthService{users: users, auditLog: auditLog}
}

// Login 用户登录，返回 JWT token
func (s *AuthService) Login(username string, password string, ip string) (string, *model.User, error) {
	user, err := s.users.VerifyPassword(username, password)
	if err != nil {
		s.auditLog.Save(username, "登录失败", "密码错误", ip)
		return "", nil, err
	}

	token, err := s.GenerateToken(user)
	if err != nil {
		return "", nil, fmt.Errorf("生成 token 失败: %w", err)
	}

	s.auditLog.Save(username, "登录成功", "Web登录", ip)
	return token, user, nil
}

// HashPassword 生成密码哈希
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("密码哈希失败: %w", err)
	}
	return string(hash), nil
}

// GenerateToken 生成 JWT token（占位，Phase 3 接入 RBAC 后完善）
func (s *AuthService) GenerateToken(user *model.User) (string, error) {
	// TODO: Phase 3 接入 JWT 或 PASETO
	return fmt.Sprintf("%s:%d", user.Username, time.Now().Unix()), nil
}

package psql

import (
	"context"
	"fmt"

	"github.com/CoderXinNing/ebpf-system/server/internal/model"
	"golang.org/x/crypto/bcrypt"
)

// CreateUser 创建用户
func (p *PSQL) CreateUser(ctx context.Context, user *model.User, passwordHash string) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)`,
		user.Username, passwordHash, user.Role)
	if err != nil {
		return fmt.Errorf("创建用户失败: %w", err)
	}
	return nil
}

// VerifyUserPassword 验证用户密码
func (p *PSQL) VerifyUserPassword(ctx context.Context, username string, password string) (*model.User, error) {
	var user model.User
	var hash string
	err := p.pool.QueryRow(ctx,
		`SELECT id, username, password_hash, role FROM users WHERE username = $1`, username,
	).Scan(&user.ID, &user.Username, &hash, &user.Role)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, fmt.Errorf("用户不存在")
		}
		return nil, fmt.Errorf("查询用户失败: %w", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return nil, fmt.Errorf("密码错误")
	}
	return &user, nil
}

// ListUsers 查询用户列表
func (p *PSQL) ListUsers(ctx context.Context) ([]*model.User, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, username, role FROM users ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("查询用户列表失败: %w", err)
	}
	defer rows.Close()

	var users []*model.User
	for rows.Next() {
		var user model.User
		if err := rows.Scan(&user.ID, &user.Username, &user.Role); err != nil {
			return nil, fmt.Errorf("扫描用户失败: %w", err)
		}
		users = append(users, &user)
	}
	return users, nil
}

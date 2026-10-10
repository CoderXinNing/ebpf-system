package psql

import (
	"context"
	"fmt"
)

// ListGroups 列出所有主机分组名
func (p *PSQL) ListGroups(ctx context.Context) ([]string, error) {
	rows, err := p.pool.Query(ctx, `SELECT name FROM host_groups ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("查询分组失败: %w", err)
	}
	defer rows.Close()

	groups := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil {
			groups = append(groups, name)
		}
	}
	return groups, nil
}

// CreateGroup 创建主机分组
func (p *PSQL) CreateGroup(ctx context.Context, name string) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO host_groups (name) VALUES ($1)
		 ON CONFLICT (name) DO NOTHING`, name)
	if err != nil {
		return fmt.Errorf("创建分组失败: %w", err)
	}
	return nil
}

// DeleteGroup 删除主机分组
func (p *PSQL) DeleteGroup(ctx context.Context, name string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM host_groups WHERE name = $1`, name)
	if err != nil {
		return fmt.Errorf("删除分组失败: %w", err)
	}
	return nil
}

package psql

import (
	"context"
	"fmt"
)

// ListWhitelist 查询所有白名单
func (p *PSQL) ListWhitelist(ctx context.Context) ([]string, error) {
	rows, err := p.pool.Query(ctx, `SELECT process_name FROM whitelist ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("查询白名单失败: %w", err)
	}
	defer rows.Close()

	result := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		result = append(result, name)
	}
	return result, nil
}

// AddWhitelist 添加白名单
func (p *PSQL) AddWhitelist(ctx context.Context, processName, reason, createdBy string) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO whitelist (process_name, reason, created_by)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (process_name) DO UPDATE SET reason = EXCLUDED.reason`,
		processName, reason, createdBy)
	if err != nil {
		return fmt.Errorf("添加白名单失败: %w", err)
	}
	return nil
}

// RemoveWhitelist 移除白名单
func (p *PSQL) RemoveWhitelist(ctx context.Context, processName string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM whitelist WHERE process_name = $1`, processName)
	if err != nil {
		return fmt.Errorf("移除白名单失败: %w", err)
	}
	return nil
}

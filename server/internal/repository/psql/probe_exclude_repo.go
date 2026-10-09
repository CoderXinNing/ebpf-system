package psql

import (
	"context"
	"fmt"
)

// ListProbeExcludeComms 查询所有探针排除名单（comm 列表）
func (p *PSQL) ListProbeExcludeComms(ctx context.Context) ([]string, error) {
	rows, err := p.pool.Query(ctx, `SELECT comm FROM probe_exclude_comms ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("查询探针排除名单失败: %w", err)
	}
	defer rows.Close()

	result := make([]string, 0)
	for rows.Next() {
		var comm string
		if err := rows.Scan(&comm); err != nil {
			continue
		}
		result = append(result, comm)
	}
	return result, nil
}

// AddProbeExcludeComms 添加探针排除名单
func (p *PSQL) AddProbeExcludeComms(ctx context.Context, comm, reason, createdBy string) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO probe_exclude_comms (comm, reason, created_by)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (comm) DO UPDATE SET reason = EXCLUDED.reason`,
		comm, reason, createdBy)
	if err != nil {
		return fmt.Errorf("添加探针排除名单失败: %w", err)
	}
	return nil
}

// RemoveProbeExcludeComms 移除探针排除名单
func (p *PSQL) RemoveProbeExcludeComms(ctx context.Context, comm string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM probe_exclude_comms WHERE comm = $1`, comm)
	if err != nil {
		return fmt.Errorf("移除探针排除名单失败: %w", err)
	}
	return nil
}

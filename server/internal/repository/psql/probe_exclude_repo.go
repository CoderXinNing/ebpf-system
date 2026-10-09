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

// ============================================
// file_access 独立 comm 排除（三维度 #11）
//
// 语义：过滤 file_access 探针的噪音源（如 psql 正常读 /etc/shadow），
//      与 exec+bash 共享的 probe_exclude_comms 相互独立。
// ============================================

// ListFileAccessExcludeComms file_access 独立 comm 排除列表
func (p *PSQL) ListFileAccessExcludeComms(ctx context.Context) ([]string, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT comm FROM probe_exclude_comms_file_access ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("查询 file_access 排除名单失败: %w", err)
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

// AddFileAccessExcludeComms 添加 file_access 独立 comm
func (p *PSQL) AddFileAccessExcludeComms(ctx context.Context, comm, reason, createdBy string) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO probe_exclude_comms_file_access (comm, reason, created_by)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (comm) DO UPDATE SET reason = EXCLUDED.reason`,
		comm, reason, createdBy)
	if err != nil {
		return fmt.Errorf("添加 file_access 排除名单失败: %w", err)
	}
	return nil
}

// RemoveFileAccessExcludeComms 移除 file_access 独立 comm
func (p *PSQL) RemoveFileAccessExcludeComms(ctx context.Context, comm string) error {
	_, err := p.pool.Exec(ctx,
		`DELETE FROM probe_exclude_comms_file_access WHERE comm = $1`, comm)
	if err != nil {
		return fmt.Errorf("移除 file_access 排除名单失败: %w", err)
	}
	return nil
}

// ============================================
// tcp 独立 IP 排除（三维度 #12）
//
// 语义：tcp 探针走独立 IP 维度，comm 维度对 tcp 无意义。
//      IP 可以是单 IP（1.2.3.4）或 CIDR（10.0.0.0/8）。
// ============================================

// ListExcludeIPs tcp 独立 IP 排除列表
func (p *PSQL) ListExcludeIPs(ctx context.Context) ([]string, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT ip FROM probe_exclude_ips ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("查询 tcp IP 排除失败: %w", err)
	}
	defer rows.Close()

	result := make([]string, 0)
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			continue
		}
		result = append(result, ip)
	}
	return result, nil
}

// AddExcludeIP 添加 tcp 独立 IP
func (p *PSQL) AddExcludeIP(ctx context.Context, ip, reason, createdBy string) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO probe_exclude_ips (ip, reason, created_by)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (ip) DO UPDATE SET reason = EXCLUDED.reason`,
		ip, reason, createdBy)
	if err != nil {
		return fmt.Errorf("添加 tcp IP 排除失败: %w", err)
	}
	return nil
}

// RemoveExcludeIP 移除 tcp 独立 IP
func (p *PSQL) RemoveExcludeIP(ctx context.Context, ip string) error {
	_, err := p.pool.Exec(ctx,
		`DELETE FROM probe_exclude_ips WHERE ip = $1`, ip)
	if err != nil {
		return fmt.Errorf("移除 tcp IP 排除失败: %w", err)
	}
	return nil
}

// ============================================
// 统一 Apply：一次性读三表 / 全量替换三表
//
// 语义：前端点 Apply 时提交"最终态"，后端事务内
//      DELETE + INSERT 三表，任一步失败整体回滚。
// 见 RULES-APPLY-DESIGN.txt（阶段 E 的简化版）
// ============================================

// GetAllExcludes 一次性返回三维度排除名单
//
// 顺序：execComms（exec+bash 共享）/ fileComms / tcpIPs
func (p *PSQL) GetAllExcludes(ctx context.Context) ([]string, []string, []string, error) {
	execComms, err := p.ListProbeExcludeComms(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("读 exec+bash 失败: %w", err)
	}
	fileComms, err := p.ListFileAccessExcludeComms(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("读 file_access 失败: %w", err)
	}
	tcpIPs, err := p.ListExcludeIPs(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("读 tcp IP 失败: %w", err)
	}
	return execComms, fileComms, tcpIPs, nil
}

// ReplaceAllExcludes 事务内全量替换三维度排除名单
//
// 语义：传入的三个列表就是最终态，空切片 = 清空该维度。
// 失败整体回滚，不留中间态。
func (p *PSQL) ReplaceAllExcludes(ctx context.Context, execComms, fileComms, tcpIPs []string, createdBy string) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("开启事务失败: %w", err)
	}
	defer tx.Rollback(ctx)

	// ---- exec+bash ----
	if _, err := tx.Exec(ctx, `DELETE FROM probe_exclude_comms`); err != nil {
		return fmt.Errorf("清空 exec+bash 失败: %w", err)
	}
	for _, comm := range execComms {
		if comm == "" {
			continue
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO probe_exclude_comms (comm, reason, created_by)
			 VALUES ($1, $2, $3)`,
			comm, "apply", createdBy); err != nil {
			return fmt.Errorf("写入 exec+bash [%s] 失败: %w", comm, err)
		}
	}

	// ---- file_access ----
	if _, err := tx.Exec(ctx, `DELETE FROM probe_exclude_comms_file_access`); err != nil {
		return fmt.Errorf("清空 file_access 失败: %w", err)
	}
	for _, comm := range fileComms {
		if comm == "" {
			continue
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO probe_exclude_comms_file_access (comm, reason, created_by)
			 VALUES ($1, $2, $3)`,
			comm, "apply", createdBy); err != nil {
			return fmt.Errorf("写入 file_access [%s] 失败: %w", comm, err)
		}
	}

	// ---- tcp IP ----
	if _, err := tx.Exec(ctx, `DELETE FROM probe_exclude_ips`); err != nil {
		return fmt.Errorf("清空 tcp IP 失败: %w", err)
	}
	for _, ip := range tcpIPs {
		if ip == "" {
			continue
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO probe_exclude_ips (ip, reason, created_by)
			 VALUES ($1, $2, $3)`,
			ip, "apply", createdBy); err != nil {
			return fmt.Errorf("写入 tcp IP [%s] 失败: %w", ip, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}
	return nil
}

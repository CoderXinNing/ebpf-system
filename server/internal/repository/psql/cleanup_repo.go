package psql

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"time"
)

// 归档表名正则：events_YYYY_MM_archive
var archiveTablePattern = regexp.MustCompile(`^events_\d{4}_\d{2}_archive$`)

// CleanupEvents 清理 events 数据
//
// mode:
//
//	"all"         清空主表所有分区 + 删除所有归档表
//	"before_days" 删除 N 天前的主表数据 + 删除超期归档表
//
// 返回：删除/清空的行数（归档表 DROP 不计入行数）
func (p *PSQL) CleanupEvents(ctx context.Context, mode string, days int) (int64, error) {
	if mode == "all" {
		return p.cleanupEventsAll(ctx)
	}
	if mode == "before_days" {
		if days <= 0 {
			return 0, fmt.Errorf("days 必须大于 0")
		}
		return p.cleanupEventsBeforeDays(ctx, days)
	}
	return 0, fmt.Errorf("未知 mode: %s", mode)
}

func (p *PSQL) cleanupEventsAll(ctx context.Context) (int64, error) {
	// 1. TRUNCATE 主表（PG 会级联所有分区）
	tag, err := p.pool.Exec(ctx, "TRUNCATE TABLE events")
	if err != nil {
		return 0, fmt.Errorf("清空 events 主表失败: %w", err)
	}
	total := tag.RowsAffected()

	// 2. 遍历并 DROP 所有归档表
	rows, err := p.pool.Query(ctx, `
		SELECT relname FROM pg_class
		WHERE relname ~ '^events_[0-9]{4}_[0-9]{2}_archive$'`)
	if err != nil {
		return total, fmt.Errorf("查询归档表失败: %w", err)
	}

	var archives []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil && archiveTablePattern.MatchString(name) {
			archives = append(archives, name)
		}
	}
	rows.Close()

	for _, name := range archives {
		if _, err := p.pool.Exec(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", name)); err != nil {
			log.Printf("⚠️ DROP 归档表 %s 失败: %v", name, err)
		} else {
			log.Printf("🗑️  已删除归档表: %s", name)
		}
	}

	return total, nil
}

func (p *PSQL) cleanupEventsBeforeDays(ctx context.Context, days int) (int64, error) {
	total := int64(0)

	// 1. 主表：DELETE 指定天数前的数据
	tag, err := p.pool.Exec(ctx, fmt.Sprintf(
		"DELETE FROM events WHERE timestamp < NOW() - INTERVAL '%d days'", days))
	if err != nil {
		return 0, fmt.Errorf("删除 events 主表数据失败: %w", err)
	}
	total += tag.RowsAffected()

	// 2. 归档表：整表时间范围早于 cutoff 才 DROP
	cutoffMonth := fmt.Sprintf("events_%s_archive",
		time.Now().AddDate(0, 0, -days).Format("2006_01"))

	rows, err := p.pool.Query(ctx, `
		SELECT relname FROM pg_class
		WHERE relname ~ '^events_[0-9]{4}_[0-9]{2}_archive$'
		  AND relname < $1`, cutoffMonth)
	if err != nil {
		return total, fmt.Errorf("查询归档表失败: %w", err)
	}

	var archives []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil {
			archives = append(archives, name)
		}
	}
	rows.Close()

	for _, name := range archives {
		// 归档表整表早于 cutoff → 先 DELETE 表内超期行（保留已删主机数据）
		// 简化：直接 DROP（用户已确认"归档可以归档"，即可以按表级删）
		if _, err := p.pool.Exec(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", name)); err != nil {
			log.Printf("⚠️ DROP 归档表 %s 失败: %v", name, err)
		} else {
			log.Printf("🗑️  已删除归档表: %s", name)
		}
	}

	return total, nil
}

// CleanupAlerts 清理 alerts
//
// mode: "all" 全部清空 / "before_days" 删除 N 天前
func (p *PSQL) CleanupAlerts(ctx context.Context, mode string, days int) (int64, error) {
	return p.cleanupGeneric(ctx, "alerts", "created_at", mode, days)
}

// CleanupAuditLogs 清理 audit_logs
func (p *PSQL) CleanupAuditLogs(ctx context.Context, mode string, days int) (int64, error) {
	return p.cleanupGeneric(ctx, "audit_logs", "created_at", mode, days)
}

// CleanupTokens 清理 enrollment_tokens
func (p *PSQL) CleanupTokens(ctx context.Context, mode string, days int) (int64, error) {
	// tokens 语义：清"已过期/已撤销"的
	if mode == "all" {
		tag, err := p.pool.Exec(ctx, "DELETE FROM enrollment_tokens")
		if err != nil {
			return 0, fmt.Errorf("清空 tokens 失败: %w", err)
		}
		return tag.RowsAffected(), nil
	}
	if mode == "before_days" {
		if days <= 0 {
			return 0, fmt.Errorf("days 必须大于 0")
		}
		tag, err := p.pool.Exec(ctx, fmt.Sprintf(
			`DELETE FROM enrollment_tokens 
			 WHERE expires_at < NOW() - INTERVAL '%d days'
			 OR (revoked_at IS NOT NULL AND revoked_at < NOW() - INTERVAL '%d days')`,
			days, days))
		if err != nil {
			return 0, fmt.Errorf("清理 tokens 失败: %w", err)
		}
		return tag.RowsAffected(), nil
	}
	return 0, fmt.Errorf("未知 mode: %s", mode)
}

func (p *PSQL) cleanupGeneric(ctx context.Context, table, timeCol, mode string, days int) (int64, error) {
	if mode == "all" {
		tag, err := p.pool.Exec(ctx, fmt.Sprintf("DELETE FROM %s", table))
		if err != nil {
			return 0, fmt.Errorf("清空 %s 失败: %w", table, err)
		}
		return tag.RowsAffected(), nil
	}
	if mode == "before_days" {
		if days <= 0 {
			return 0, fmt.Errorf("days 必须大于 0")
		}
		tag, err := p.pool.Exec(ctx, fmt.Sprintf(
			"DELETE FROM %s WHERE %s < NOW() - INTERVAL '%d days'", table, timeCol, days))
		if err != nil {
			return 0, fmt.Errorf("清理 %s 失败: %w", table, err)
		}
		return tag.RowsAffected(), nil
	}
	return 0, fmt.Errorf("未知 mode: %s", mode)
}

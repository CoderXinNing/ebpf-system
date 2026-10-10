package psql

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PSQL 是 PostgreSQL 数据访问层。
// 注意：过渡期不嵌入 store.Store（store 是 SQLite 专用），
// handler 层将直接使用 PSQL 的 repository 方法。
type PSQL struct {
	pool *pgxpool.Pool
}

// Config 是 PSQL 连接配置
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
}

// New 创建 PSQL 连接池
func New(cfg Config) (*PSQL, error) {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.DBName)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("创建连接池失败: %w", err)
	}

	// 验证连接
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("数据库连接失败: %w", err)
	}

	psql := &PSQL{pool: pool}

	// 启动时确保未来 3 个月的分区存在
	if err := psql.EnsurePartitions(ctx); err != nil {
		log.Printf("⚠️ 检查分区失败: %v", err)
	}

	log.Printf("✅ PostgreSQL 连接成功: %s:%d/%s", cfg.Host, cfg.Port, cfg.DBName)
	return psql, nil
}

// Close 关闭连接池
func (p *PSQL) Close() {
	if p.pool != nil {
		p.pool.Close()
	}
}

// 分区维护常量
const (
	// PartitionMonthsAhead 预建未来几个月的分区（含当前月共 N+1 个月）
	PartitionMonthsAhead = 3

	// PartitionMonthsKeep 保留最近几个月分区（含当前月）
	// 更早的分区会被 DETACH 并归档（不改名 _archive）
	PartitionMonthsKeep = 3
)

// Pool 返回底层连接池（过渡期使用）
func (p *PSQL) Pool() *pgxpool.Pool {
	return p.pool
}

// EnsurePartitions 确保当前月 + 未来 N 个月的分区存在
//
// 设计说明：
//   - 时间边界完全由 PostgreSQL 侧生成（date_trunc + interval），
//     避免 Go time.Local / time.UTC 与 DB 时区不一致导致边界偏移。
//   - 幂等：CREATE TABLE IF NOT EXISTS，重复执行无副作用。
//   - 由 StartMaintenanceTask 每日调用，保证 Server 长期不重启也不缺分区。
func (p *PSQL) EnsurePartitions(ctx context.Context) error {
	for i := 0; i <= PartitionMonthsAhead; i++ {
		// 分区名也从 DB 拿，与边界时区严格一致（避免 Go/DB 时区错位）
		var pname string
		if err := p.pool.QueryRow(ctx,
			`SELECT to_char(date_trunc('month', now() + make_interval(months => $1)), 'YYYY_MM')`,
			i).Scan(&pname); err != nil {
			return fmt.Errorf("获取第 %d 个月分区名失败: %w", i, err)
		}

		query := fmt.Sprintf(`
			CREATE TABLE IF NOT EXISTS events_%s PARTITION OF events
			FOR VALUES FROM (date_trunc('month', now() + make_interval(months => %d)))
			              TO (date_trunc('month', now() + make_interval(months => %d)))`,
			pname, i, i+1,
		)
		if _, err := p.pool.Exec(ctx, query); err != nil {
			return fmt.Errorf("创建第 %d 个月分区 (%s) 失败: %w", i, pname, err)
		}
	}
	return nil
}

// StartMaintenanceTask 启动定时维护任务
//
// 行为：
//  1. 启动 5 分钟后跑第一次（避开 Server 启动高峰）
//  2. 之后每 24 小时跑一次
//  3. 每次先 EnsurePartitions（保证未来分区存在），再 runCleanup（清理过期数据）
func (p *PSQL) StartMaintenanceTask(ctx context.Context) {
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Minute):
		}

		p.runMaintenance(ctx)

		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.runMaintenance(ctx)
			}
		}
	}()
}

// runMaintenance 一次完整维护：确保分区 + 清理
func (p *PSQL) runMaintenance(ctx context.Context) {
	if err := p.EnsurePartitions(ctx); err != nil {
		log.Printf("⚠️ 维护任务：确保分区失败: %v", err)
	}
	p.runCleanup(ctx)
}

// runCleanup 执行清理
//
// events 分区清理策略：
//   - 保留最近 PartitionMonthsKeep 个月（含当前月）
//   - 查 pg_inherits 找出真正早于 cutoff 的分区（白名单，绝不误删）
//   - 归档而非 DROP：DETACH + RENAME 加 _archive 后缀
//     理由：DROP 不可逆，归档保留取证能力，成本极低
func (p *PSQL) runCleanup(ctx context.Context) {
	// ============ 读用户配置（log_settings），失败用默认值兜底 ============
	alertDays := p.ReadIntSetting(ctx, "alert_days", 90)
	auditDays := p.ReadIntSetting(ctx, "audit_days", 180)
	eventDays := p.ReadIntSetting(ctx, "event_days", 180)
	tokenDays := p.ReadIntSetting(ctx, "token_days", 180)

	// ============ events 主表：按月归档 ============
	// 保留最近 PartitionMonthsKeep 个月（含当前月），更早的 DETACH → _archive
	cutoffMonth := time.Now().AddDate(0, -(PartitionMonthsKeep - 1), 0)
	cutoffName := fmt.Sprintf("events_%s", cutoffMonth.Format("2006_01"))

	rows, err := p.pool.Query(ctx, `
		SELECT c.relname
		FROM pg_class c
		JOIN pg_inherits i ON c.oid = i.inhrelid
		WHERE i.inhparent = 'events'::regclass
		  AND c.relname < $1
		  AND c.relname NOT LIKE '%_archive'
		ORDER BY c.relname`, cutoffName)
	if err != nil {
		log.Printf("⚠️ 查询待清理分区失败: %v", err)
	} else {
		var toArchive []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err == nil {
				toArchive = append(toArchive, name)
			}
		}
		rows.Close()

		for _, name := range toArchive {
			archiveName := name + "_archive"
			if _, err := p.pool.Exec(ctx,
				fmt.Sprintf("ALTER TABLE events DETACH PARTITION %s", name)); err != nil {
				log.Printf("⚠️ DETACH %s 失败: %v", name, err)
				continue
			}
			if _, err := p.pool.Exec(ctx,
				fmt.Sprintf("ALTER TABLE %s RENAME TO %s", name, archiveName)); err != nil {
				log.Printf("⚠️ 归档 %s 失败: %v", name, err)
				continue
			}
			log.Printf("📦 归档分区: %s → %s", name, archiveName)
		}
	}

	// ============ events 归档表：按月保留，过期 DROP ============
	// eventDays 转月（向上取整）：180 天 ≈ 6 个月
	eventMonths := (eventDays + 29) / 30
	if eventMonths < 1 {
		eventMonths = 1
	}
	archiveCutoff := time.Now().AddDate(0, -eventMonths, 0)
	archiveCutoffName := fmt.Sprintf("events_%s_archive", archiveCutoff.Format("2006_01"))

	archRows, err := p.pool.Query(ctx, `
		SELECT relname FROM pg_class
		WHERE relname ~ '^events_[0-9]{4}_[0-9]{2}_archive$'
		  AND relname < $1
		ORDER BY relname`, archiveCutoffName)
	if err != nil {
		log.Printf("⚠️ 查询待删归档表失败: %v", err)
	} else {
		var toDrop []string
		for archRows.Next() {
			var name string
			if err := archRows.Scan(&name); err == nil {
				toDrop = append(toDrop, name)
			}
		}
		archRows.Close()

		for _, name := range toDrop {
			if _, err := p.pool.Exec(ctx,
				fmt.Sprintf("DROP TABLE IF EXISTS %s", name)); err != nil {
				log.Printf("⚠️ DROP 归档表 %s 失败: %v", name, err)
				continue
			}
			log.Printf("🗑️  删除过期归档表: %s (保留 %d 天 ≈ %d 月)",
				name, eventDays, eventMonths)
		}
	}

	// ============ alerts：读 alert_days ============
	_, err = p.pool.Exec(ctx, fmt.Sprintf(
		"DELETE FROM alerts WHERE created_at < NOW() - INTERVAL '%d days'", alertDays))
	if err != nil {
		log.Printf("⚠️ 清理旧告警失败: %v", err)
	}

	// ============ audit_logs：读 audit_days ============
	_, err = p.pool.Exec(ctx, fmt.Sprintf(
		"DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL '%d days'", auditDays))
	if err != nil {
		log.Printf("⚠️ 清理旧审计日志失败: %v", err)
	}

	// ============ enrollment_tokens：读 token_days ============
	if err := p.CleanupExpiredTokens(ctx, tokenDays); err != nil {
		log.Printf("⚠️ 清理过期 Token 失败: %v", err)
	}

	// ============ baseline_snapshots：保留 90 天（非用户配置）============
	_, err = p.pool.Exec(ctx, "DELETE FROM baseline_snapshots WHERE recorded_at < NOW() - INTERVAL '90 days'")
	if err != nil {
		log.Printf("⚠️ 清理旧基线快照失败: %v", err)
	}

	// ============ sessions：保留 7 天（非用户配置）============
	_, err = p.pool.Exec(ctx, "DELETE FROM sessions WHERE created_at < NOW() - INTERVAL '7 days' AND revoked_at IS NULL")
	if err != nil {
		log.Printf("⚠️ 清理过期会话失败: %v", err)
	}

	log.Printf("🧹 定时清理完成（alert=%dd audit=%dd event=%dd token=%dd）",
		alertDays, auditDays, eventDays, tokenDays)
}

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

// Pool 返回底层连接池（过渡期使用）
func (p *PSQL) Pool() *pgxpool.Pool {
	return p.pool
}

// EnsurePartitions 确保未来 3 个月的分区存在
func (p *PSQL) EnsurePartitions(ctx context.Context) error {
	for i := 0; i < 3; i++ {
		month := time.Now().AddDate(0, i, 0)
		partitionName := fmt.Sprintf("events_%s", month.Format("2006_01"))
		startDate := time.Date(month.Year(), month.Month(), 1, 0, 0, 0, 0, time.UTC)
		endDate := startDate.AddDate(0, 1, 0)

		query := fmt.Sprintf(
			"CREATE TABLE IF NOT EXISTS %s PARTITION OF events FOR VALUES FROM ('%s') TO ('%s')",
			partitionName,
			startDate.Format("2006-01-02"),
			endDate.Format("2006-01-02"),
		)
		if _, err := p.pool.Exec(ctx, query); err != nil {
			return fmt.Errorf("创建分区 %s 失败: %w", partitionName, err)
		}
	}
	return nil
}

// StartCleanupTask 启动定时清理任务
func (p *PSQL) StartCleanupTask(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.runCleanup(ctx)
			}
		}
	}()
}

// runCleanup 执行清理
func (p *PSQL) runCleanup(ctx context.Context) {
	// events 保留 30 天（DROP 旧分区）
	cutoff30 := time.Now().AddDate(0, 0, -30)
	oldPartition := fmt.Sprintf("events_%s", cutoff30.Format("2006_01"))
	_, err := p.pool.Exec(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", oldPartition))
	if err != nil {
		log.Printf("⚠️ 清理旧分区失败: %v", err)
	}

	// alerts 保留 90 天
	_, err = p.pool.Exec(ctx, "DELETE FROM alerts WHERE created_at < NOW() - INTERVAL '90 days'")
	if err != nil {
		log.Printf("⚠️ 清理旧告警失败: %v", err)
	}

	// audit_logs 保留 180 天
	_, err = p.pool.Exec(ctx, "DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL '180 days'")
	if err != nil {
		log.Printf("⚠️ 清理旧审计日志失败: %v", err)
	}

	// baseline_snapshots 保留 90 天
	_, err = p.pool.Exec(ctx, "DELETE FROM baseline_snapshots WHERE recorded_at < NOW() - INTERVAL '90 days'")
	if err != nil {
		log.Printf("⚠️ 清理旧基线快照失败: %v", err)
	}

	// sessions 保留 7 天
	_, err = p.pool.Exec(ctx, "DELETE FROM sessions WHERE created_at < NOW() - INTERVAL '7 days' AND revoked_at IS NULL")
	if err != nil {
		log.Printf("⚠️ 清理过期会话失败: %v", err)
	}

	log.Println("🧹 定时清理完成")
}

package sqlite

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	"github.com/CoderXinNing/ebpf-system/server/internal/store"
)

// SQLite 是 repository 接口的 SQLite 实现。
// 嵌入 *store.Store 以兼容现有 handler（过渡期），
// 后续新代码直接使用 SQLite 的 repository 方法。
type SQLite struct {
	*store.Store
	db *sql.DB
}

// New 初始化 SQLite 数据库连接并建表
func New(dbPath string) (*SQLite, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}

	tables := []string{
		`CREATE TABLE IF NOT EXISTS agents (
			agent_id TEXT PRIMARY KEY,
			hostname TEXT,
			ip_addr TEXT,
			version TEXT,
			group_name TEXT,
			token TEXT,
			first_seen INTEGER,
			last_seen INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			role TEXT DEFAULT 'viewer'
		)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			username TEXT,
			action TEXT,
			detail TEXT,
			ip TEXT,
			created_at INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS log_settings (
			key TEXT PRIMARY KEY,
			value TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS host_groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			created_at INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS probe_configs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			agent_id TEXT NOT NULL,
			probe_name TEXT NOT NULL,
			enabled INTEGER DEFAULT 1,
			remove INTEGER DEFAULT 1,
			path TEXT,
			sha256 TEXT DEFAULT '',
			updated_at INTEGER,
			UNIQUE(agent_id, probe_name)
		)`,
		`CREATE TABLE IF NOT EXISTS asset_snapshots (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			agent_id TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			processes_json TEXT,
			users_json TEXT,
			system_json TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_asset_agent_time ON asset_snapshots(agent_id, created_at DESC)`,
	}

	for _, ddl := range tables {
		if _, err := db.Exec(ddl); err != nil {
			db.Close()
			return nil, fmt.Errorf("建表失败: %w\nSQL: %s", err, ddl)
		}
	}

	return &SQLite{
		Store: store.NewStoreFromDB(db),
		db:    db,
	}, nil
}

// DB 返回底层 *sql.DB（过渡期使用，Phase 3 迁移完成后移除）
func (s *SQLite) DB() *sql.DB {
	return s.db
}

// Close 关闭数据库连接
func (s *SQLite) Close() error {
	return s.db.Close()
}

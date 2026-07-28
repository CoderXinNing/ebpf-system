package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Store 数据库操作
type Store struct {
	db *sql.DB
}

// NewStore 初始化数据库
func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}

	// 建表
	tables := []string{
		// 用户表（从auth迁移过来）
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			role TEXT DEFAULT 'viewer'
		)`,
		// 主机资产快照
		`CREATE TABLE IF NOT EXISTS asset_snapshots (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			agent_id TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			processes_json TEXT,
			users_json TEXT,
			system_json TEXT
		)`,
		// 索引：按Agent+时间查最新
		`CREATE INDEX IF NOT EXISTS idx_asset_agent_time ON asset_snapshots(agent_id, created_at DESC)`,
	}

	for _, ddl := range tables {
		if _, err := db.Exec(ddl); err != nil {
			db.Close()
			return nil, fmt.Errorf("建表失败: %w\nSQL: %s", err, ddl)
		}
	}

	return &Store{db: db}, nil
}

// SaveAsset 保存资产快照
func (s *Store) SaveAsset(agentID string, processesJSON, usersJSON, systemJSON []byte) error {
	_, err := s.db.Exec(
		"INSERT INTO asset_snapshots (agent_id, created_at, processes_json, users_json, system_json) VALUES (?, ?, ?, ?, ?)",
		agentID, time.Now().Unix(), string(processesJSON), string(usersJSON), string(systemJSON),
	)
	return err
}

// GetLatestAsset 获取最新资产快照
func (s *Store) GetLatestAsset(agentID string) (processesJSON, usersJSON, systemJSON []byte, err error) {
	var p, u, sys sql.NullString
	err = s.db.QueryRow(
		"SELECT processes_json, users_json, system_json FROM asset_snapshots WHERE agent_id = ? ORDER BY created_at DESC LIMIT 1",
		agentID,
	).Scan(&p, &u, &sys)
	if err != nil {
		return nil, nil, nil, err
	}
	return []byte(p.String), []byte(u.String), []byte(sys.String), nil
}

// GetAllLatestAssets 获取所有Agent的最新资产（用于概览）
func (s *Store) GetAllLatestAssets() (map[string]map[string]int, error) {
	rows, err := s.db.Query(`
		SELECT agent_id, processes_json, users_json 
		FROM asset_snapshots 
		WHERE id IN (SELECT MAX(id) FROM asset_snapshots GROUP BY agent_id)
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]map[string]int)
	for rows.Next() {
		var agentID string
		var pJSON, uJSON sql.NullString
		rows.Scan(&agentID, &pJSON, &uJSON)

		procCount := 0
		userCount := 0
		if pJSON.Valid {
			var procs []interface{}
			json.Unmarshal([]byte(pJSON.String), &procs)
			procCount = len(procs)
		}
		if uJSON.Valid {
			var users []interface{}
			json.Unmarshal([]byte(uJSON.String), &users)
			userCount = len(users)
		}

		result[agentID] = map[string]int{
			"process_count": procCount,
			"user_count":    userCount,
		}
	}
	return result, nil
}

// Close 关闭数据库
func (s *Store) Close() {
	s.db.Close()
}

// DB 暴露底层数据库连接
func (s *Store) DB() *sql.DB {
	return s.db
}

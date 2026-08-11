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

// AlertRecord 告警记录
type AlertRecord struct {
	ID          int64  `json:"id"`
	RuleName    string `json:"rule_name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	AgentID     string `json:"agent_id"`
	PID         int32  `json:"pid"`
	Comm        string `json:"comm"`
	Filename    string `json:"filename"`
	CreatedAt   int64  `json:"created_at"`
}

func (s *Store) InitAlertTable() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_name TEXT, severity TEXT, description TEXT,
		agent_id TEXT, pid INTEGER, comm TEXT, filename TEXT,
		created_at INTEGER
	)`)
	return err
}

func (s *Store) SaveAlert(a AlertRecord) error {
	_, err := s.db.Exec(
		"INSERT INTO alerts (rule_name, severity, description, agent_id, pid, comm, filename, created_at) VALUES (?,?,?,?,?,?,?,?)",
		a.RuleName, a.Severity, a.Description, a.AgentID, a.PID, a.Comm, a.Filename, time.Now().Unix(),
	)
	return err
}

func (s *Store) GetAlerts(limit int) ([]AlertRecord, error) {
	if limit <= 0 { limit = 100 }
	rows, err := s.db.Query("SELECT id, rule_name, severity, description, agent_id, pid, comm, filename, created_at FROM alerts ORDER BY id DESC LIMIT ?", limit)
	if err != nil { return nil, err }
	defer rows.Close()

	var alerts []AlertRecord
	for rows.Next() {
		var a AlertRecord
		rows.Scan(&a.ID, &a.RuleName, &a.Severity, &a.Description, &a.AgentID, &a.PID, &a.Comm, &a.Filename, &a.CreatedAt)
		alerts = append(alerts, a)
	}
	return alerts, nil
}

// EventRecord 事件记录
type EventRecord struct {
	ID        int64  `json:"id"`
	AgentID   string `json:"agent_id"`
	ProbeName string `json:"probe_name"`
	Timestamp int64  `json:"timestamp"`
	EventType string `json:"event_type"`
	PID       int32  `json:"pid"`
	Comm      string `json:"comm"`
	Filename  string `json:"filename"`
	Details   string `json:"details,omitempty"`
}

func (s *Store) InitEventTable() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		agent_id TEXT, probe_name TEXT, timestamp INTEGER,
		event_type TEXT, pid INTEGER, comm TEXT,
		filename TEXT, details TEXT
	)`)
	return err
}

func (s *Store) SaveEvent(e EventRecord) error {
	_, err := s.db.Exec(
		"INSERT INTO events (agent_id, probe_name, timestamp, event_type, pid, comm, filename, details) VALUES (?,?,?,?,?,?,?,?)",
		e.AgentID, e.ProbeName, e.Timestamp, e.EventType, e.PID, e.Comm, e.Filename, e.Details,
	)
	return err
}

func (s *Store) GetEvents(limit int, agentID string) ([]EventRecord, error) {
	if limit <= 0 { limit = 100 }
	var rows *sql.Rows
	var err error
	if agentID != "" {
		rows, err = s.db.Query("SELECT id, agent_id, probe_name, timestamp, event_type, pid, comm, filename, details FROM events WHERE agent_id = ? ORDER BY id DESC LIMIT ?", agentID, limit)
	} else {
		rows, err = s.db.Query("SELECT id, agent_id, probe_name, timestamp, event_type, pid, comm, filename, details FROM events ORDER BY id DESC LIMIT ?", limit)
	}
	if err != nil { return nil, err }
	defer rows.Close()

	var events []EventRecord
	for rows.Next() {
		var e EventRecord
		rows.Scan(&e.ID, &e.AgentID, &e.ProbeName, &e.Timestamp, &e.EventType, &e.PID, &e.Comm, &e.Filename, &e.Details)
		events = append(events, e)
	}
	return events, nil
}

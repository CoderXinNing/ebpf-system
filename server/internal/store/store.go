package store

import (
	"database/sql"
	"log"
	"strconv"
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
		// 操作审计日志
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			username TEXT,
			action TEXT,
			detail TEXT,
			ip TEXT,
			created_at INTEGER
		)`,
		// 日志保留天数配置
		`CREATE TABLE IF NOT EXISTS log_settings (
			key TEXT PRIMARY KEY,
			value TEXT
		)`,
		// 主机分组
		`CREATE TABLE IF NOT EXISTS host_groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			created_at INTEGER
		)`,
		// 探针配置
		`CREATE TABLE IF NOT EXISTS probe_configs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			agent_id TEXT NOT NULL,
			probe_name TEXT NOT NULL,
			enabled INTEGER DEFAULT 1,
			remove INTEGER DEFAULT 1,
			path TEXT,
			updated_at INTEGER,
			UNIQUE(agent_id, probe_name)
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
	Details     string `json:"details"`
	Source      string `json:"source"`
	CreatedAt   int64  `json:"created_at"`
}

func (s *Store) InitAlertTable() error {
	// 旧表迁移：加 source 列
	s.db.Exec("ALTER TABLE alerts ADD COLUMN source TEXT DEFAULT 'rule'")
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_name TEXT, severity TEXT, description TEXT,
		agent_id TEXT, pid INTEGER, comm TEXT, filename TEXT,
		details TEXT, source TEXT DEFAULT 'rule', created_at INTEGER
	)`)
	return err
}

func (s *Store) SaveAlert(a AlertRecord) error {
	if a.Source == "" {
		a.Source = "rule"
	}
	_, err := s.db.Exec(
		"INSERT INTO alerts (rule_name, severity, description, agent_id, pid, comm, filename, details, source, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
		a.RuleName, a.Severity, a.Description, a.AgentID, a.PID, a.Comm, a.Filename, a.Details, a.Source, time.Now().Unix(),
	)
	return err
}

func (s *Store) GetAlerts(limit int) ([]AlertRecord, error) {
	if limit <= 0 { limit = 100 }
	rows, err := s.db.Query("SELECT id, rule_name, severity, description, agent_id, pid, comm, filename, details, source, created_at FROM alerts ORDER BY id DESC LIMIT ?", limit)
	if err != nil { return nil, err }
	defer rows.Close()

	var alerts []AlertRecord
	for rows.Next() {
		var a AlertRecord
		var source sql.NullString
		rows.Scan(&a.ID, &a.RuleName, &a.Severity, &a.Description, &a.AgentID, &a.PID, &a.Comm, &a.Filename, &a.Details, &source, &a.CreatedAt)
		a.Source = source.String
		if a.Source == "" {
			a.Source = "rule"
		}
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

// ProbeConfigRecord 探针配置
type ProbeConfigRecord struct {
	ID        int64  `json:"id"`
	AgentID   string `json:"agent_id"`
	ProbeName string `json:"probe_name"`
	Enabled   bool   `json:"enabled"`
	Remove    bool   `json:"remove"`
	Path      string `json:"path"`
	UpdatedAt int64  `json:"updated_at"`
}

// UpsertProbeConfig 插入或更新探针配置
func (s *Store) UpsertProbeConfig(r ProbeConfigRecord) error {
	enabled := 0
	if r.Enabled { enabled = 1 }
	remove := 0
	if r.Remove { remove = 1 }

	_, err := s.db.Exec(
		`INSERT INTO probe_configs (agent_id, probe_name, enabled, remove, path, updated_at)
		 VALUES (?,?,?,?,?,?)
		 ON CONFLICT(agent_id, probe_name) DO UPDATE SET
		 enabled=excluded.enabled, remove=excluded.remove, path=excluded.path, updated_at=excluded.updated_at`,
		r.AgentID, r.ProbeName, enabled, remove, r.Path, time.Now().Unix(),
	)
	return err
}

// GetProbeConfigs 获取指定主机的探针配置
func (s *Store) GetProbeConfigs(agentID string) ([]ProbeConfigRecord, error) {
	rows, err := s.db.Query(
		"SELECT id, agent_id, probe_name, enabled, remove, path, updated_at FROM probe_configs WHERE agent_id = ?",
		agentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []ProbeConfigRecord
	for rows.Next() {
		var c ProbeConfigRecord
		var enabled, remove int
		var path sql.NullString
		rows.Scan(&c.ID, &c.AgentID, &c.ProbeName, &enabled, &remove, &path, &c.UpdatedAt)
		c.Enabled = enabled == 1
		c.Remove = remove == 1
		c.Path = path.String
		configs = append(configs, c)
	}
	return configs, nil
}

// DeleteProbeConfig 删除探针配置
func (s *Store) DeleteProbeConfig(agentID, probeName string) error {
	_, err := s.db.Exec("DELETE FROM probe_configs WHERE agent_id = ? AND probe_name = ?", agentID, probeName)
	return err
}

// ========== 主机分组 ==========

// CreateGroup 创建分组
func (s *Store) CreateGroup(name string) error {
	_, err := s.db.Exec("INSERT INTO host_groups (name, created_at) VALUES (?, ?)", name, time.Now().Unix())
	return err
}

// DeleteGroup 删除分组
func (s *Store) DeleteGroup(name string) error {
	_, err := s.db.Exec("DELETE FROM host_groups WHERE name = ?", name)
	return err
}

// GetGroups 获取所有分组
func (s *Store) GetGroups() ([]string, error) {
	rows, err := s.db.Query("SELECT name FROM host_groups ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []string
	for rows.Next() {
		var name string
		rows.Scan(&name)
		groups = append(groups, name)
	}
	return groups, nil
}

// ========== 审计日志 ==========

// SaveAuditLog 保存操作日志
func (s *Store) SaveAuditLog(username, action, detail, ip string) error {
	_, err := s.db.Exec(
		"INSERT INTO audit_logs (username, action, detail, ip, created_at) VALUES (?,?,?,?,?)",
		username, action, detail, ip, time.Now().Unix(),
	)
	return err
}

// GetAuditLogs 获取审计日志
func (s *Store) GetAuditLogs(limit int) ([]map[string]interface{}, error) {
	if limit <= 0 { limit = 100 }
	rows, err := s.db.Query("SELECT id, username, action, detail, ip, created_at FROM audit_logs ORDER BY id DESC LIMIT ?", limit)
	if err != nil { return nil, err }
	defer rows.Close()

	var logs []map[string]interface{}
	for rows.Next() {
		var id int64
		var username, action, detail, ip string
		var createdAt int64
		rows.Scan(&id, &username, &action, &detail, &ip, &createdAt)
		logs = append(logs, map[string]interface{}{
			"id": id, "username": username, "action": action,
			"detail": detail, "ip": ip, "created_at": createdAt,
		})
	}
	return logs, nil
}

// ========== 日志设置 ==========

// SetLogSetting 设置日志保留天数
func (s *Store) SetLogSetting(key, value string) error {
	_, err := s.db.Exec(
		"INSERT INTO log_settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
		key, value,
	)
	return err
}

// GetLogSetting 获取设置
func (s *Store) GetLogSetting(key string) (string, error) {
	var value string
	err := s.db.QueryRow("SELECT value FROM log_settings WHERE key = ?", key).Scan(&value)
	if err != nil {
		return "", err
	}
	return value, nil
}

// CleanExpiredLogs 清理过期日志
func (s *Store) CleanExpiredLogs() {
	// 读取保留天数
	eventDays := 30
	alertDays := 90
	auditDays := 180

	if v, err := s.GetLogSetting("event_days"); err == nil && v != "" {
		if d, err := strconv.Atoi(v); err == nil { eventDays = d }
	}
	if v, err := s.GetLogSetting("alert_days"); err == nil && v != "" {
		if d, err := strconv.Atoi(v); err == nil { alertDays = d }
	}
	if v, err := s.GetLogSetting("audit_days"); err == nil && v != "" {
		if d, err := strconv.Atoi(v); err == nil { auditDays = d }
	}

	now := time.Now().Unix()
	eventCutoff := now - int64(eventDays*86400)
	alertCutoff := now - int64(alertDays*86400)
	auditCutoff := now - int64(auditDays*86400)

	result1, err1 := s.db.Exec("DELETE FROM events WHERE timestamp < ?", eventCutoff)
	if err1 != nil {
		log.Printf("⚠️ 清理事件失败: %v", err1)
	} else if n, _ := result1.RowsAffected(); n > 0 {
		log.Printf("🧹 清理过期事件: %d条 (保留%d天)", n, eventDays)
	}

	result2, err2 := s.db.Exec("DELETE FROM alerts WHERE created_at < ?", alertCutoff)
	if err2 != nil {
		log.Printf("⚠️ 清理告警失败: %v", err2)
	} else if n, _ := result2.RowsAffected(); n > 0 {
		log.Printf("🧹 清理过期告警: %d条 (保留%d天)", n, alertDays)
	}

	result3, err3 := s.db.Exec("DELETE FROM audit_logs WHERE created_at < ?", auditCutoff)
	if err3 != nil {
		log.Printf("⚠️ 清理审计日志失败: %v", err3)
	} else if n, _ := result3.RowsAffected(); n > 0 {
		log.Printf("🧹 清理过期审计日志: %d条 (保留%d天)", n, auditDays)
	}
}

// SaveAlertFeedback 保存告警反馈
func (s *Store) SaveAlertFeedback(alertID, feedbackType, username string) error {
	// 更新 alerts 表加 feedback 字段（如果不存在则忽略）
	s.db.Exec("ALTER TABLE alerts ADD COLUMN feedback TEXT DEFAULT ''")
	s.db.Exec("ALTER TABLE alerts ADD COLUMN feedback_by TEXT DEFAULT ''")
	_, err := s.db.Exec("UPDATE alerts SET feedback = ?, feedback_by = ? WHERE id = ?", feedbackType, username, alertID)
	return err
}

// GetAlertStats 告警统计
func (s *Store) GetAlertStats() map[string]interface{} {
	stats := make(map[string]interface{})

	// 总告警数
	var total int
	s.db.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&total)
	stats["total"] = total

	// 今日告警
	var today int
	s.db.QueryRow("SELECT COUNT(*) FROM alerts WHERE created_at > ?", time.Now().Unix()-86400).Scan(&today)
	stats["today"] = today

	// 误报数
	var falsePositive int
	s.db.QueryRow("SELECT COUNT(*) FROM alerts WHERE feedback = 'false_positive'").Scan(&falsePositive)
	stats["false_positive"] = falsePositive

	// 已确认数
	var confirmed int
	s.db.QueryRow("SELECT COUNT(*) FROM alerts WHERE feedback = 'confirmed'").Scan(&confirmed)
	stats["confirmed"] = confirmed

	// 按规则分布
	rows, err := s.db.Query("SELECT rule_name, COUNT(*) as cnt FROM alerts GROUP BY rule_name ORDER BY cnt DESC LIMIT 10")
	if err == nil {
		defer rows.Close()
		var ruleStats []map[string]interface{}
		for rows.Next() {
			var name string
			var cnt int
			rows.Scan(&name, &cnt)
			ruleStats = append(ruleStats, map[string]interface{}{"rule": name, "count": cnt})
		}
		stats["rule_distribution"] = ruleStats
	}

	// 按严重程度分布
	rows2, err2 := s.db.Query("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity")
	if err2 == nil {
		defer rows2.Close()
		var sevStats []map[string]interface{}
		for rows2.Next() {
			var sev string
			var cnt int
			rows2.Scan(&sev, &cnt)
			sevStats = append(sevStats, map[string]interface{}{"severity": sev, "count": cnt})
		}
		stats["severity_distribution"] = sevStats
	}

	return stats
}

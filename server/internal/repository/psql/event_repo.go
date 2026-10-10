package psql

import (
	"context"
	"time"

	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"

	"github.com/CoderXinNing/ebpf-system/server/internal/model"
)

// toJSON 确保 details 是合法 JSON
func toJSON(s string) json.RawMessage {
	if s == "" {
		return json.RawMessage("null")
	}
	// 尝试解析，失败则作为 JSON 字符串
	if json.Valid([]byte(s)) {
		return json.RawMessage(s)
	}
	// 包装为 JSON 字符串
	encoded, _ := json.Marshal(s)
	return encoded
}

// SaveEvent 保存事件
func (p *PSQL) SaveEvent(ctx context.Context, event *model.Event) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO events (agent_id, probe_name, event_type, pid, ppid, uid, comm, parent_comm, filename, details, source_channel, correlation_id, event_hash, timestamp)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		event.AgentID, event.ProbeName, event.EventType, event.PID, event.PPID, event.UID,
		event.Comm, event.ParentComm, event.Filename, toJSON(event.Details),
		event.SourceChannel, event.CorrelationID, event.EventHash, event.Timestamp,
	)
	if err != nil {
		return fmt.Errorf("保存事件失败: %w", err)
	}
	return nil
}

// ListEvents 查询事件列表
func (p *PSQL) ListEvents(ctx context.Context, filter *model.AgentListFilter) ([]*model.Event, error) {
	query := `SELECT id, agent_id, probe_name, event_type, pid, ppid, uid, comm, parent_comm, filename, details, source_channel, correlation_id, event_hash, timestamp FROM events`
	args := []interface{}{}
	argIdx := 1

	if filter != nil && filter.AgentID != "" {
		query += fmt.Sprintf(` WHERE agent_id = $%d`, argIdx)
		args = append(args, filter.AgentID)
		argIdx++
	}
	query += ` ORDER BY timestamp DESC`

	limit := 100
	if filter != nil && filter.Limit > 0 {
		limit = filter.Limit
	}
	query += fmt.Sprintf(` LIMIT $%d`, argIdx)
	args = append(args, limit)

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("查询事件列表失败: %w", err)
	}
	defer rows.Close()

	var events []*model.Event
	for rows.Next() {
		var event model.Event
		var detailsRaw []byte
		if err := rows.Scan(&event.ID, &event.AgentID, &event.ProbeName, &event.EventType,
			&event.PID, &event.PPID, &event.UID, &event.Comm, &event.ParentComm,
			&event.Filename, &detailsRaw, &event.SourceChannel, &event.CorrelationID,
			&event.EventHash, &event.Timestamp); err != nil {
			return nil, fmt.Errorf("扫描事件失败: %w", err)
		}
		event.Details = string(detailsRaw)
		events = append(events, &event)
	}
	return events, nil
}

// ListEventsByCorrelationID 按 correlation_id 查询事件
func (p *PSQL) ListEventsByCorrelationID(ctx context.Context, corrID string) ([]*model.Event, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, agent_id, probe_name, event_type, pid, ppid, uid, comm, parent_comm, filename, details, source_channel, correlation_id, event_hash, timestamp
		 FROM events WHERE correlation_id = $1 ORDER BY timestamp ASC`, corrID)
	if err != nil {
		return nil, fmt.Errorf("查询攻击链失败: %w", err)
	}
	defer rows.Close()

	var events []*model.Event
	for rows.Next() {
		var event model.Event
		var detailsRaw []byte
		if err := rows.Scan(&event.ID, &event.AgentID, &event.ProbeName, &event.EventType,
			&event.PID, &event.PPID, &event.UID, &event.Comm, &event.ParentComm,
			&event.Filename, &detailsRaw, &event.SourceChannel, &event.CorrelationID,
			&event.EventHash, &event.Timestamp); err != nil {
			return nil, fmt.Errorf("扫描事件失败: %w", err)
		}
		event.Details = string(detailsRaw)
		events = append(events, &event)
	}
	return events, nil
}

// CleanExpiredEvents 清理过期事件（通过 DROP 旧分区实现）
func (p *PSQL) CleanExpiredEvents(ctx context.Context, beforeTimestamp int64) error {
	// 分区表按月清理，不逐行删除
	return nil
}

// EventRecord 事件记录（兼容旧 store.EventRecord 的 map 格式）
type EventRecord struct {
	ID        int64  `json:"id"`
	AgentID   string `json:"agent_id"`
	ProbeName string `json:"probe_name"`
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	PID       int32  `json:"pid"`
	Comm      string `json:"comm"`
	Filename  string `json:"filename"`
	Details   string `json:"details"`
}

// ListEventsAsRecords 按 agentID 查询事件（兼容旧 store.GetEvents 的返回）
func (p *PSQL) ListEventsAsRecords(ctx context.Context, limit int, agentID string) ([]EventRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	var rows pgx.Rows
	var err error
	if agentID != "" {
		rows, err = p.pool.Query(ctx, `
			SELECT id, agent_id, COALESCE(probe_name,''), timestamp,
			       COALESCE(event_type,''), COALESCE(pid,0), COALESCE(comm,''),
			       COALESCE(filename,''), COALESCE(details::text,'')
			FROM events WHERE agent_id = $1
			ORDER BY id DESC LIMIT $2`, agentID, limit)
	} else {
		rows, err = p.pool.Query(ctx, `
			SELECT id, agent_id, COALESCE(probe_name,''), timestamp,
			       COALESCE(event_type,''), COALESCE(pid,0), COALESCE(comm,''),
			       COALESCE(filename,''), COALESCE(details::text,'')
			FROM events
			ORDER BY id DESC LIMIT $1`, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("查询事件失败: %w", err)
	}
	defer rows.Close()

	result := make([]EventRecord, 0, limit)
	for rows.Next() {
		var r EventRecord
		var ts time.Time
		if err := rows.Scan(&r.ID, &r.AgentID, &r.ProbeName, &ts, &r.EventType,
			&r.PID, &r.Comm, &r.Filename, &r.Details); err != nil {
			continue
		}
		r.Timestamp = ts.Format("2006-01-02 15:04:05")
		result = append(result, r)
	}
	return result, nil
}

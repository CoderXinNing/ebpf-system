package model

import "time"

// Event 表示一条安全事件
type Event struct {
	ID            int64     `json:"id"`
	AgentID       string    `json:"agent_id"`
	ProbeName     string    `json:"probe_name"`
	EventType     string    `json:"event_type"`
	PID           int32     `json:"pid"`
	PPID          int32     `json:"ppid"`
	UID           int32     `json:"uid"`
	Comm          string    `json:"comm"`
	ParentComm    string    `json:"parent_comm"`
	Filename      string    `json:"filename"`
	Details       string    `json:"details"`
	SourceChannel string    `json:"source_channel"`
	CorrelationID string    `json:"correlation_id"`
	EventHash     string    `json:"event_hash"`
	Timestamp     time.Time `json:"timestamp"`
}

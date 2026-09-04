package model

import "time"

// Alert 表示一条告警
type Alert struct {
	ID             int64      `json:"id"`
	RuleName       string     `json:"rule_name"`
	Severity       string     `json:"severity"`
	Description    string     `json:"description"`
	AgentID        string     `json:"agent_id"`
	PID            int32      `json:"pid"`
	Comm           string     `json:"comm"`
	Filename       string     `json:"filename"`
	Details        string     `json:"details"`
	Source         string     `json:"source"`
	DetectionLevel string     `json:"detection_level"`
	ActionType     string     `json:"action_type"`
	CorrelationID  string     `json:"correlation_id"`
	Status         string     `json:"status"`
	DetectedAt     *time.Time `json:"detected_at"`
	CreatedAt      time.Time  `json:"created_at"`
}

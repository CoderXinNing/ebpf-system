package model

import "time"

// ProbeConfig 表示探针配置
type ProbeConfig struct {
	ID              int64     `json:"id"`
	AgentID         string    `json:"agent_id"`
	ProbeTemplateID int64     `json:"probe_template_id"`
	Status          string    `json:"status"`
	DesiredStatus   string    `json:"desired_status"`
	FailureReason   string    `json:"failure_reason"`
	VersionLock     int32     `json:"version_lock"`
	UpdatedAt       time.Time `json:"updated_at"`
}

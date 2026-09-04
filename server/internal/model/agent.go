package model

import (
	"encoding/json"
	"time"
)

// Agent 表示一台已注册的主机
type Agent struct {
	ID                string          `json:"id"`
	Hostname          string          `json:"hostname"`
	DisplayName       string          `json:"display_name"`
	IPAddr            string          `json:"ip_addr"`
	Location          string          `json:"location"`
	Owner             string          `json:"owner"`
	Version           string          `json:"version"`
	GroupID           *int64          `json:"group_id"`
	TokenHash         string          `json:"-"`
	CapabilityLevel   string          `json:"capability_level"`
	ActiveProbes      int32           `json:"active_probes"`
	ProbeDetails      json.RawMessage `json:"probe_details"`
	BaselineState     string          `json:"baseline_state"`
	LearningStartedAt *time.Time      `json:"learning_started_at"`
	LearningDuration  string          `json:"learning_duration"`
	FirstSeen         time.Time       `json:"first_seen"`
	LastSeen          time.Time       `json:"last_seen"`
	Framework         json.RawMessage `json:"framework"`
	KernelInfo        json.RawMessage `json:"kernel_info"`
	VersionLock       int32           `json:"version_lock"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

// AgentListFilter 列表查询条件
type AgentListFilter struct {
	AgentID string
	Group   string
	Keyword string
	Limit   int
	Offset  int
}

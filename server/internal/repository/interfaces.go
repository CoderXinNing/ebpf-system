package repository

import (
	"github.com/CoderXinNing/ebpf-system/server/internal/model"
)

// AgentRepository Agent 数据访问接口
type AgentRepository interface {
	Save(agent *model.Agent) error
	GetByID(id string) (*model.Agent, error)
	Delete(id string) error
	List(filter *model.AgentListFilter) ([]*model.Agent, error)
}

// EventRepository 事件数据访问接口
type EventRepository interface {
	Save(event *model.Event) error
	List(filter *model.AgentListFilter) ([]*model.Event, error)
	CleanExpired(beforeTimestamp int64) error
}

// AlertRepository 告警数据访问接口
type AlertRepository interface {
	Save(alert *model.Alert) error
	List(limit int) ([]*model.Alert, error)
	SaveFeedback(alertID string, feedbackType string, username string) error
	GetStats() map[string]interface{}
}

// ProbeConfigRepository 探针配置数据访问接口
type ProbeConfigRepository interface {
	Upsert(config *model.ProbeConfig) error
	GetByAgentID(agentID string) ([]*model.ProbeConfig, error)
	Delete(agentID string, probeName string) error
}

// UserRepository 用户数据访问接口
type UserRepository interface {
	Create(user *model.User, passwordHash string) error
	VerifyPassword(username string, password string) (*model.User, error)
	List() ([]*model.User, error)
}

// AuditLogRepository 审计日志数据访问接口
type AuditLogRepository interface {
	Save(username string, action string, detail string, ip string) error
	List(limit int) ([]map[string]interface{}, error)
}

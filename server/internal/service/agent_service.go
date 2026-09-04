package service

import (
	"fmt"

	"github.com/CoderXinNing/ebpf-system/server/internal/model"
	"github.com/CoderXinNing/ebpf-system/server/internal/repository"
)

// AgentService Agent 业务逻辑
type AgentService struct {
	agents repository.AgentRepository
}

func NewAgentService(agents repository.AgentRepository) *AgentService {
	return &AgentService{agents: agents}
}

// Register 注册 Agent
func (s *AgentService) Register(agent *model.Agent) error {
	if agent.ID == "" {
		return fmt.Errorf("agent_id 不能为空")
	}
	if agent.Hostname == "" {
		return fmt.Errorf("hostname 不能为空")
	}
	return s.agents.Save(agent)
}

// GetByID 查询 Agent
func (s *AgentService) GetByID(id string) (*model.Agent, error) {
	return s.agents.GetByID(id)
}

// List 查询 Agent 列表
func (s *AgentService) List(filter *model.AgentListFilter) ([]*model.Agent, error) {
	return s.agents.List(filter)
}

// Delete 删除 Agent
func (s *AgentService) Delete(id string) error {
	return s.agents.Delete(id)
}

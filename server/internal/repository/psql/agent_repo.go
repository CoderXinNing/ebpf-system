package psql

import (
	"context"
	"fmt"
	"time"

	"github.com/CoderXinNing/ebpf-system/server/internal/model"
)

// SaveAgent 保存或更新 Agent
func (p *PSQL) SaveAgent(ctx context.Context, agent *model.Agent) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO agents (agent_id, hostname, display_name, ip_addr, location, owner, version, group_id, token_hash, capability_level, active_probes, probe_details, baseline_state, learning_started_at, learning_duration, first_seen, last_seen, framework, kernel_info)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
		 ON CONFLICT (agent_id) DO UPDATE SET
		   hostname = EXCLUDED.hostname,
		   display_name = EXCLUDED.display_name,
		   ip_addr = EXCLUDED.ip_addr,
		   location = EXCLUDED.location,
		   owner = EXCLUDED.owner,
		   version = EXCLUDED.version,
		   group_id = EXCLUDED.group_id,
		   token_hash = EXCLUDED.token_hash,
		   capability_level = EXCLUDED.capability_level,
		   active_probes = EXCLUDED.active_probes,
		   probe_details = EXCLUDED.probe_details,
		   baseline_state = EXCLUDED.baseline_state,
		   learning_started_at = EXCLUDED.learning_started_at,
		   learning_duration = EXCLUDED.learning_duration,
		   last_seen = EXCLUDED.last_seen,
		   framework = EXCLUDED.framework,
		   kernel_info = EXCLUDED.kernel_info,
		   version_lock = agents.version_lock + 1`,
		agent.ID, agent.Hostname, agent.DisplayName, agent.IPAddr, agent.Location, agent.Owner,
		agent.Version, agent.GroupID, agent.TokenHash, agent.CapabilityLevel, agent.ActiveProbes,
		agent.ProbeDetails, agent.BaselineState, agent.LearningStartedAt, agent.LearningDuration,
		agent.FirstSeen, agent.LastSeen, agent.Framework, agent.KernelInfo,
	)
	if err != nil {
		return fmt.Errorf("保存 Agent 失败: %w", err)
	}
	return nil
}

// GetAgentByID 根据 agent_id 查询
func (p *PSQL) GetAgentByID(ctx context.Context, agentID string) (*model.Agent, error) {
	var agent model.Agent
	err := p.pool.QueryRow(ctx,
		`SELECT agent_id, hostname, display_name, ip_addr, location, owner, version, group_id, token_hash, capability_level, active_probes, probe_details, baseline_state, learning_started_at, learning_duration, first_seen, last_seen, framework, kernel_info
		 FROM agents WHERE agent_id = $1`, agentID,
	).Scan(&agent.ID, &agent.Hostname, &agent.DisplayName, &agent.IPAddr, &agent.Location,
		&agent.Owner, &agent.Version, &agent.GroupID, &agent.TokenHash, &agent.CapabilityLevel,
		&agent.ActiveProbes, &agent.ProbeDetails, &agent.BaselineState, &agent.LearningStartedAt,
		&agent.LearningDuration, &agent.FirstSeen, &agent.LastSeen, &agent.Framework, &agent.KernelInfo)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, fmt.Errorf("查询 Agent 失败: %w", err)
	}
	return &agent, nil
}

// DeleteAgent 删除 Agent
func (p *PSQL) DeleteAgent(ctx context.Context, agentID string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM agents WHERE agent_id = $1`, agentID)
	if err != nil {
		return fmt.Errorf("删除 Agent 失败: %w", err)
	}
	return nil
}

// ListAgents 查询 Agent 列表
func (p *PSQL) ListAgents(ctx context.Context, filter *model.AgentListFilter) ([]*model.Agent, error) {
	query := `SELECT agent_id, hostname, display_name, ip_addr, location, owner, version, group_id, token_hash, capability_level, active_probes, baseline_state, first_seen, last_seen FROM agents`
	args := []interface{}{}
	argIdx := 1

	if filter != nil && filter.Group != "" && filter.Group != "全部" {
		query += fmt.Sprintf(` WHERE group_id = (SELECT id FROM host_groups WHERE name = $%d)`, argIdx)
		args = append(args, filter.Group)
		argIdx++
	}
	query += ` ORDER BY last_seen DESC`

	if filter != nil && filter.Limit > 0 {
		query += fmt.Sprintf(` LIMIT $%d`, argIdx)
		args = append(args, filter.Limit)
	}

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("查询 Agent 列表失败: %w", err)
	}
	defer rows.Close()

	var agents []*model.Agent
	for rows.Next() {
		var agent model.Agent
		if err := rows.Scan(&agent.ID, &agent.Hostname, &agent.DisplayName, &agent.IPAddr,
			&agent.Location, &agent.Owner, &agent.Version, &agent.GroupID, &agent.TokenHash,
			&agent.CapabilityLevel, &agent.ActiveProbes, &agent.BaselineState,
			&agent.FirstSeen, &agent.LastSeen); err != nil {
			return nil, fmt.Errorf("扫描 Agent 失败: %w", err)
		}
		agents = append(agents, &agent)
	}
	return agents, nil
}

// UpdateLastSeen 更新心跳时间
func (p *PSQL) UpdateLastSeen(ctx context.Context, agentID string, lastSeen time.Time) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE agents SET last_seen = $2 WHERE agent_id = $1`,
		agentID, lastSeen)
	if err != nil {
		return fmt.Errorf("更新心跳失败: %w", err)
	}
	return nil
}

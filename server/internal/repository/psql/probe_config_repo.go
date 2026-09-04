package psql

import (
	"context"
	"fmt"

	"github.com/CoderXinNing/ebpf-system/server/internal/model"
)

// UpsertProbeConfig 创建或更新探针配置
func (p *PSQL) UpsertProbeConfig(ctx context.Context, config *model.ProbeConfig) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO probe_configs (agent_id, probe_template_id, status, desired_status, failure_reason, version_lock)
		 VALUES ($1, $2, $3, $4, $5, 0)
		 ON CONFLICT (agent_id, probe_template_id) DO UPDATE SET
		   status = EXCLUDED.status,
		   desired_status = EXCLUDED.desired_status,
		   failure_reason = EXCLUDED.failure_reason,
		   version_lock = probe_configs.version_lock + 1`,
		config.AgentID, config.ProbeTemplateID, config.Status, config.DesiredStatus, config.FailureReason,
	)
	if err != nil {
		return fmt.Errorf("保存探针配置失败: %w", err)
	}
	return nil
}

// GetProbeConfigsByAgentID 查询 Agent 的探针配置
func (p *PSQL) GetProbeConfigsByAgentID(ctx context.Context, agentID string) ([]*model.ProbeConfig, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, agent_id, probe_template_id, status, desired_status, failure_reason, version_lock, updated_at
		 FROM probe_configs WHERE agent_id = $1 ORDER BY probe_template_id`, agentID)
	if err != nil {
		return nil, fmt.Errorf("查询探针配置失败: %w", err)
	}
	defer rows.Close()

	var configs []*model.ProbeConfig
	for rows.Next() {
		var config model.ProbeConfig
		if err := rows.Scan(&config.ID, &config.AgentID, &config.ProbeTemplateID,
			&config.Status, &config.DesiredStatus, &config.FailureReason,
			&config.VersionLock, &config.UpdatedAt); err != nil {
			return nil, fmt.Errorf("扫描探针配置失败: %w", err)
		}
		configs = append(configs, &config)
	}
	return configs, nil
}

// DeleteProbeConfig 删除探针配置
func (p *PSQL) DeleteProbeConfig(ctx context.Context, agentID string, probeTemplateID int64) error {
	_, err := p.pool.Exec(ctx,
		`DELETE FROM probe_configs WHERE agent_id = $1 AND probe_template_id = $2`,
		agentID, probeTemplateID)
	if err != nil {
		return fmt.Errorf("删除探针配置失败: %w", err)
	}
	return nil
}

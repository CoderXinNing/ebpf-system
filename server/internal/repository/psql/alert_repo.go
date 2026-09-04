package psql

import (
	"context"
	"fmt"

	"github.com/CoderXinNing/ebpf-system/server/internal/model"
)

// SaveAlert 保存告警
func (p *PSQL) SaveAlert(ctx context.Context, alert *model.Alert) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO alerts (rule_name, severity, description, agent_id, pid, comm, filename, details, source, detection_level, action_type, correlation_id, status, detected_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		alert.RuleName, alert.Severity, alert.Description, alert.AgentID, alert.PID,
		alert.Comm, alert.Filename, alert.Details, alert.Source, alert.DetectionLevel,
		alert.ActionType, alert.CorrelationID, alert.Status, alert.DetectedAt,
	)
	if err != nil {
		return fmt.Errorf("保存告警失败: %w", err)
	}
	return nil
}

// ListAlerts 查询告警列表
func (p *PSQL) ListAlerts(ctx context.Context, limit int) ([]*model.Alert, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.pool.Query(ctx,
		`SELECT id, rule_name, severity, description, agent_id, pid, comm, filename, details, source, detection_level, action_type, correlation_id, status, detected_at, created_at
		 FROM alerts ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("查询告警列表失败: %w", err)
	}
	defer rows.Close()

	var alerts []*model.Alert
	for rows.Next() {
		var alert model.Alert
		if err := rows.Scan(&alert.ID, &alert.RuleName, &alert.Severity, &alert.Description,
			&alert.AgentID, &alert.PID, &alert.Comm, &alert.Filename, &alert.Details,
			&alert.Source, &alert.DetectionLevel, &alert.ActionType, &alert.CorrelationID,
			&alert.Status, &alert.DetectedAt, &alert.CreatedAt); err != nil {
			return nil, fmt.Errorf("扫描告警失败: %w", err)
		}
		alerts = append(alerts, &alert)
	}
	return alerts, nil
}

// SaveAlertFeedback 保存告警反馈
func (p *PSQL) SaveAlertFeedback(ctx context.Context, alertID int64, feedback string, username string) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE alerts SET status = $2 WHERE id = $1`,
		alertID, feedback)
	if err != nil {
		return fmt.Errorf("保存告警反馈失败: %w", err)
	}
	return nil
}

// GetAlertStats 获取告警统计
func (p *PSQL) GetAlertStats(ctx context.Context) map[string]interface{} {
	stats := make(map[string]interface{})
	var total, critical, high int
	p.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts`).Scan(&total)
	p.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts WHERE severity = 'critical'`).Scan(&critical)
	p.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts WHERE severity = 'high'`).Scan(&high)
	stats["total"] = total
	stats["critical"] = critical
	stats["high"] = high
	return stats
}

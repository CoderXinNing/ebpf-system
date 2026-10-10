package psql

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/CoderXinNing/ebpf-system/server/internal/audit"
)

// WriteAudit 写入一条审计记录
//
// 设计：
//   - before_value / after_value 序列化为 jsonb
//   - 空值序列化为 NULL（不写 "null" 字符串）
//   - session_id 可为 nil（当前上下文未注入，后续补）
//   - 失败不阻塞业务：调用方应记录日志，不 panic
func (p *PSQL) WriteAudit(ctx context.Context, rec audit.Record) error {
	beforeJSON := marshalOrNil(rec.BeforeValue)
	afterJSON := marshalOrNil(rec.AfterValue)

	_, err := p.pool.Exec(ctx, `
		INSERT INTO audit_logs (
			session_id, username, action, action_code, detail,
			target_type, target_id, target_name,
			event_type, event_rw,
			before_value, after_value,
			result, ip, user_agent,
			created_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8,
			$9, $10,
			$11, $12,
			$13, $14, $15,
			NOW()
		)`,
		rec.SessionID, rec.Username, rec.Action, nullableStr(rec.ActionCode), nullableStr(rec.Detail),
		nullableStr(rec.TargetType), nullableStr(rec.TargetID), nullableStr(rec.TargetName),
		nullableStr(rec.EventType), nullableStr(rec.EventRW),
		beforeJSON, afterJSON,
		nullableStr(rec.Result), nullableStr(rec.IP), nullableStr(rec.UserAgent),
	)
	if err != nil {
		return fmt.Errorf("写入审计日志失败: %w", err)
	}
	return nil
}

// ListAudit 列出最近的审计记录（兼容旧 UI 的 map 格式）
//
// 返回格式与旧 store.GetAuditLogs 对齐，避免前端改动：
//
//	id / username / action / detail / ip / created_at
func (p *PSQL) ListAudit(ctx context.Context, limit int) ([]map[string]interface{}, error) {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}

	rows, err := p.pool.Query(ctx, `
		SELECT id, username, action, action_code, detail,
		       target_type, target_id, target_name,
		       event_type, event_rw, result, ip, created_at
		FROM audit_logs
		ORDER BY id DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("查询审计日志失败: %w", err)
	}
	defer rows.Close()

	result := make([]map[string]interface{}, 0, limit)
	for rows.Next() {
		var (
			id         int64
			username   *string
			action     *string
			actionCode *string
			detail     *string
			targetType *string
			targetID   *string
			targetName *string
			eventType  *string
			eventRW    *string
			resultStr  *string
			ip         *string
			createdAt  time.Time
		)
		if err := rows.Scan(
			&id, &username, &action, &actionCode, &detail,
			&targetType, &targetID, &targetName,
			&eventType, &eventRW, &resultStr, &ip, &createdAt,
		); err != nil {
			continue
		}

		result = append(result, map[string]interface{}{
			"id":          id,
			"username":    derefStr(username),
			"action":      derefStr(action),
			"action_code": derefStr(actionCode),
			"detail":      derefStr(detail),
			"target_type": derefStr(targetType),
			"target_id":   derefStr(targetID),
			"target_name": derefStr(targetName),
			"event_type":  derefStr(eventType),
			"event_rw":    derefStr(eventRW),
			"result":      derefStr(resultStr),
			"ip":          derefStr(ip),
			"created_at":  createdAt.Format("2006-01-02 15:04:05"),
		})
	}
	return result, nil
}

// ============================================================
// 内部辅助
// ============================================================

func marshalOrNil(v interface{}) interface{} {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil || string(b) == "null" {
		return nil
	}
	return b
}

func nullableStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

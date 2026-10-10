package psql

import (
	"context"
	"fmt"
	"strconv"
)

// SystemConfig 系统配置记录
type SystemConfig struct {
	Namespace   string
	Key         string
	Value       string
	ValueType   string // string / int / bool / json
	Description string
	UpdatedBy   string
}

// GetSystemConfigString 读取字符串配置
func (p *PSQL) GetSystemConfigString(ctx context.Context, namespace, key string) (string, error) {
	var value string
	err := p.pool.QueryRow(ctx,
		`SELECT value FROM system_config WHERE namespace = $1 AND key = $2`,
		namespace, key).Scan(&value)
	if err != nil {
		return "", fmt.Errorf("配置不存在: %s.%s", namespace, key)
	}
	return value, nil
}

// GetSystemConfigInt 读取整数配置，失败或非法返回默认值
func (p *PSQL) GetSystemConfigInt(ctx context.Context, namespace, key string, defaultVal int) int {
	v, err := p.GetSystemConfigString(ctx, namespace, key)
	if err != nil || v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return defaultVal
	}
	return n
}

// GetSystemConfigBool 读取布尔配置，失败返回默认值
func (p *PSQL) GetSystemConfigBool(ctx context.Context, namespace, key string, defaultVal bool) bool {
	v, err := p.GetSystemConfigString(ctx, namespace, key)
	if err != nil || v == "" {
		return defaultVal
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return defaultVal
	}
	return b
}

// SetSystemConfig 写入配置（UPSERT）
func (p *PSQL) SetSystemConfig(ctx context.Context, namespace, key, value, updatedBy string) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO system_config (namespace, key, value, updated_by, updated_at)
		 VALUES ($1, $2, $3, $4, NOW())
		 ON CONFLICT (namespace, key) DO UPDATE
		 SET value = EXCLUDED.value,
		     updated_by = EXCLUDED.updated_by,
		     updated_at = NOW()`,
		namespace, key, value, updatedBy)
	if err != nil {
		return fmt.Errorf("写入配置失败: %w", err)
	}
	return nil
}

// ListSystemConfigByNamespace 列出某命名空间的所有配置
func (p *PSQL) ListSystemConfigByNamespace(ctx context.Context, namespace string) ([]*SystemConfig, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT namespace, key, value, value_type, COALESCE(description, ''), COALESCE(updated_by, '')
		 FROM system_config
		 WHERE namespace = $1
		 ORDER BY key`, namespace)
	if err != nil {
		return nil, fmt.Errorf("查询配置失败: %w", err)
	}
	defer rows.Close()

	result := make([]*SystemConfig, 0)
	for rows.Next() {
		c := &SystemConfig{}
		if err := rows.Scan(&c.Namespace, &c.Key, &c.Value, &c.ValueType,
			&c.Description, &c.UpdatedBy); err == nil {
			result = append(result, c)
		}
	}
	return result, nil
}

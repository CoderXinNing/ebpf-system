package psql

import (
	"context"
	"strconv"
)

// GetLogSetting 获取单个设置
func (p *PSQL) GetLogSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := p.pool.QueryRow(ctx, `SELECT value FROM log_settings WHERE key = $1`, key).Scan(&value)
	if err != nil {
		return "", err
	}
	return value, nil
}

// SetLogSetting 设置单个值
func (p *PSQL) SetLogSetting(ctx context.Context, key, value string) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO log_settings (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
		key, value)
	return err
}

// ReadIntSetting 读取整数设置，失败返回默认值
//
// 安全性：
//   - 值必须能 Atoi 成合法整数，否则返回默认值
//   - 防止脏数据 / 注入进入 SQL（下游用 %d 格式化）
func (p *PSQL) ReadIntSetting(ctx context.Context, key string, defaultVal int) int {
	v, err := p.GetLogSetting(ctx, key)
	if err != nil || v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return defaultVal
	}
	return n
}

// ListSettings 列出所有设置
func (p *PSQL) ListSettings(ctx context.Context) (map[string]string, error) {
	rows, err := p.pool.Query(ctx, `SELECT key, value FROM log_settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err == nil {
			result[k] = v
		}
	}
	return result, nil
}

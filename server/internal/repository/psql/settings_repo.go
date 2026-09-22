package psql

import (
	"context"
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

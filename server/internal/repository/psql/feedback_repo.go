package psql

import (
	"context"
	"fmt"
	"strings"
)

// SaveFeedbackFeature 保存误报特征（写入 log_settings，key 前缀 fp_）
//
// 复用 log_settings 表，不新建表。
// 旧 SQLite 实现使用 'fp_' || key 作为复合主键，PG 侧保持相同约定。
func (p *PSQL) SaveFeedbackFeature(ctx context.Context, featureKey string) error {
	if featureKey == "" {
		return nil
	}
	key := "fp_" + featureKey
	_, err := p.pool.Exec(ctx,
		`INSERT INTO log_settings (key, value) VALUES ($1, '1')
		 ON CONFLICT (key) DO NOTHING`, key)
	if err != nil {
		return fmt.Errorf("保存误报特征失败: %w", err)
	}
	return nil
}

// GetFeedbackFeatures 获取所有误报特征（去掉 fp_ 前缀）
func (p *PSQL) GetFeedbackFeatures(ctx context.Context) ([]string, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT key FROM log_settings WHERE key LIKE 'fp_%'`)
	if err != nil {
		return nil, fmt.Errorf("查询误报特征失败: %w", err)
	}
	defer rows.Close()

	features := make([]string, 0)
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err == nil {
			features = append(features, strings.TrimPrefix(key, "fp_"))
		}
	}
	return features, nil
}

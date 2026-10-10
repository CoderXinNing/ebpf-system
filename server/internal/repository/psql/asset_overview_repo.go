package psql

import (
	"context"
	"encoding/json"
	"fmt"
)

// GetAllLatestAssets 返回所有 Agent 的资产统计（进程数 / 用户数）
//
// 返回格式兼容旧 store.GetAllLatestAssets：
//
//	map[agentID]{process_count: N, user_count: M}
//
// 数据源：cmdb_assets 中 asset_type ∈ (process, user) 的最新记录
func (p *PSQL) GetAllLatestAssets(ctx context.Context) (map[string]map[string]int, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT DISTINCT ON (agent_id, asset_type)
			agent_id, asset_type, asset_info
		FROM cmdb_assets
		WHERE asset_type IN ('process', 'user')
		ORDER BY agent_id, asset_type, updated_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("查询资产概览失败: %w", err)
	}
	defer rows.Close()

	result := make(map[string]map[string]int)
	for rows.Next() {
		var agentID, assetType string
		var info []byte
		if err := rows.Scan(&agentID, &assetType, &info); err != nil {
			continue
		}

		if _, ok := result[agentID]; !ok {
			result[agentID] = map[string]int{
				"process_count": 0,
				"user_count":    0,
			}
		}

		// 计算数组长度
		var arr []interface{}
		if err := json.Unmarshal(info, &arr); err == nil {
			switch assetType {
			case "process":
				result[agentID]["process_count"] = len(arr)
			case "user":
				result[agentID]["user_count"] = len(arr)
			}
		}
	}
	return result, nil
}

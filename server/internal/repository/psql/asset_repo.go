package psql

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

)

// SaveAsset 保存资产快照
func (p *PSQL) SaveAsset(ctx context.Context, agentID string, processesJSON, usersJSON, systemJSON []byte) error {
	log.Printf("DEBUG: SaveAsset 入口 processes=%d users=%d system=%d", len(processesJSON), len(usersJSON), len(systemJSON))
	if len(processesJSON) > 10 {
		log.Printf("DEBUG: processesJSON 前 50 字符: %s", string(processesJSON[:50]))
	}
	if processesJSON != nil && len(processesJSON) > 2 {
		_, err := p.pool.Exec(ctx,
			`INSERT INTO cmdb_assets (agent_id, asset_type, asset_name, asset_info, updated_at)
			 VALUES ($1, 'process', 'all', $2, NOW())
			 ON CONFLICT (agent_id, asset_type, asset_name) DO UPDATE SET asset_info = EXCLUDED.asset_info, updated_at = NOW()`,
			agentID, processesJSON)
		if err != nil {
			return fmt.Errorf("保存进程资产失败: %w", err)
		}
		log.Printf("📊 进程资产已保存: %d bytes", len(processesJSON))
	}

	if usersJSON != nil && len(usersJSON) > 2 {
		_, err := p.pool.Exec(ctx,
			`INSERT INTO cmdb_assets (agent_id, asset_type, asset_name, asset_info, updated_at)
			 VALUES ($1, 'user', 'all', $2, NOW())
			 ON CONFLICT (agent_id, asset_type, asset_name) DO UPDATE SET asset_info = EXCLUDED.asset_info, updated_at = NOW()`,
			agentID, usersJSON)
		if err != nil {
			return fmt.Errorf("保存用户资产失败: %w", err)
		}
	}

	if systemJSON != nil && len(systemJSON) > 2 {
		_, err := p.pool.Exec(ctx,
			`INSERT INTO cmdb_assets (agent_id, asset_type, asset_name, asset_info, updated_at)
			 VALUES ($1, 'service', 'all', $2, NOW())
			 ON CONFLICT (agent_id, asset_type, asset_name) DO UPDATE SET asset_info = EXCLUDED.asset_info, updated_at = NOW()`,
			agentID, systemJSON)
		if err != nil {
			return fmt.Errorf("保存系统信息失败: %w", err)
		}
	}

	// 保存其他资产类型（映射到允许的 CHECK 值）
	allowedTypes := map[string]string{
		"packages":        "package",
		"jar_packages":    "package",
		"python_packages": "package",
		"npm_packages":    "package",
		"crons":           "service",
		"services":        "service",
		"service_status":  "service",
		"web_components":  "web_component",
	}
	var sysData map[string]interface{}
	if err := json.Unmarshal(systemJSON, &sysData); err == nil {
		for assetType, assetData := range sysData {
			mappedType, ok := allowedTypes[assetType]
			if !ok {
				continue
			}
			info, _ := json.Marshal(assetData)
			_, err = p.pool.Exec(ctx,
				`INSERT INTO cmdb_assets (agent_id, asset_type, asset_name, asset_info, updated_at)
				 VALUES ($1, $2, 'all', $3::jsonb, NOW())
				 ON CONFLICT (agent_id, asset_type, asset_name) DO UPDATE SET asset_info = EXCLUDED.asset_info, updated_at = NOW()`,
				agentID, mappedType, info)
			if err != nil {
				log.Printf("保存 %s 资产失败: %v", mappedType, err)
			}
		}
	}

	return nil
}

// GetLatestAsset 获取最新资产快照
func (p *PSQL) GetLatestAsset(ctx context.Context, agentID string) (json.RawMessage, json.RawMessage, json.RawMessage, error) {
	// 查询进程资产
	processRows, err := p.pool.Query(ctx,
		`SELECT asset_info FROM cmdb_assets 
		 WHERE agent_id = $1 AND asset_type = 'process' 
		 ORDER BY updated_at DESC LIMIT 1`, agentID)
	if err != nil {
		return nil, nil, nil, err
	}
	defer processRows.Close()

	var processes json.RawMessage
	if processRows.Next() {
		processRows.Scan(&processes)
	} else {
		processes = json.RawMessage("[]")
	}

	// 查询用户资产
	userRows, err := p.pool.Query(ctx,
		`SELECT asset_info FROM cmdb_assets 
		 WHERE agent_id = $1 AND asset_type = 'user' 
		 ORDER BY updated_at DESC LIMIT 1`, agentID)
	if err != nil {
		return nil, nil, nil, err
	}
	defer userRows.Close()

	var users json.RawMessage
	if userRows.Next() {
		userRows.Scan(&users)
	} else {
		users = json.RawMessage("[]")
	}

	// 查询系统信息
	sysRows, err := p.pool.Query(ctx,
		`SELECT asset_info FROM cmdb_assets 
		 WHERE agent_id = $1 AND asset_type = 'system' 
		 ORDER BY updated_at DESC LIMIT 1`, agentID)
	if err != nil {
		return nil, nil, nil, err
	}
	defer sysRows.Close()

	var system json.RawMessage
	if sysRows.Next() {
		sysRows.Scan(&system)
	} else {
		system = json.RawMessage("{}")
	}

	return processes, users, system, nil
}

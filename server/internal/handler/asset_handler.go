package handler

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// AssetsOverview 资产概览
func (h *Handler) AssetsOverview(c *gin.Context) {
	data, err := h.Store.GetAllLatestAssets()
	if err != nil {
		c.JSON(500, gin.H{"error": "查询失败"})
		return
	}
	type AssetSummary struct {
		AgentID      string  `json:"agent_id"`
		Hostname     string  `json:"hostname"`
		OS           string  `json:"os"`
		ProcessCount int     `json:"process_count"`
		UserCount    int     `json:"user_count"`
		Online       bool    `json:"online"`
		CPUPercent   float64 `json:"cpu_percent"`
		MemPercent   float64 `json:"mem_percent"`
		DiskPercent  float64 `json:"disk_percent"`
	}
	summaries := make([]AssetSummary, 0, len(data))
	now := time.Now().Unix()
	for agentID, counts := range data {
		h.Mu.RLock()
		agent := h.Agents[agentID]
		h.Mu.RUnlock()
		hostname := ""
		online := false
		if agent != nil {
			hostname = agent.Hostname
			if now-agent.LastSeen < 60 {
				online = true
			}
		}
		var cpuP, memP, diskP float64
		if _, _, sysJSON, err := h.Store.GetLatestAsset(agentID); err == nil {
			var sysData map[string]interface{}
			json.Unmarshal(sysJSON, &sysData)
			if perf, ok := sysData["perf"].(map[string]interface{}); ok {
				if v, ok := perf["cpu_percent"].(float64); ok {
					cpuP = v
				}
				if v, ok := perf["mem_percent"].(float64); ok {
					memP = v
				}
				if du, ok := perf["disk_usage"].([]interface{}); ok && len(du) > 0 {
					if dm, ok := du[0].(map[string]interface{}); ok {
						if p, ok := dm["percent"].(string); ok {
							p = strings.TrimSuffix(p, "%")
							if f, err := strconv.ParseFloat(p, 64); err == nil {
								diskP = f
							}
						}
					}
				}
			}
		}
		summaries = append(summaries, AssetSummary{
			AgentID:      agentID,
			Hostname:     hostname,
			OS:           h.getOS(agentID),
			ProcessCount: counts["process_count"],
			UserCount:    counts["user_count"],
			Online:       online,
			CPUPercent:   cpuP,
			MemPercent:   memP,
			DiskPercent:  diskP,
		})
	}
	c.JSON(200, gin.H{"agents": summaries})
}

// AssetDetail 资产详情
func (h *Handler) AssetDetail(c *gin.Context) {
	agentID := c.Param("id")
	if agentID == "" {
		c.JSON(400, gin.H{"error": "缺少agent_id"})
		return
	}
	processes, users, sysJSON, err := h.Store.GetLatestAsset(agentID)
	if err != nil {
		c.JSON(404, gin.H{"error": "资产不存在"})
		return
	}
	c.JSON(200, gin.H{
		"processes": json.RawMessage(processes),
		"users":     json.RawMessage(users),
		"system":    json.RawMessage(sysJSON),
	})
}

// AssetsByCategory 按分类查询资产
func (h *Handler) AssetsByCategory(c *gin.Context) {
	agentID := c.Query("agent_id")
	category := c.Query("category")

	type AssetItem struct {
		Type        string   `json:"type"`
		AgentID     string   `json:"agent_id"`
		Hostname    string   `json:"hostname"`
		ServiceName string   `json:"service_name"`
		Version     string   `json:"version"`
		Group       string   `json:"group"`
		PID         int32    `json:"pid"`
		ListenPort  []string `json:"listen_port"`
		ExePath     string   `json:"exe_path"`
		ConfigPath  string   `json:"config_path"`
	}

	var items []AssetItem
	h.Mu.RLock()
	defer h.Mu.RUnlock()

	for aid, agent := range h.Agents {
		if agentID != "" && aid != agentID {
			continue
		}

		_, _, sysJSON, err := h.Store.GetLatestAsset(aid)
		if err != nil {
			continue
		}

		var sysData map[string]interface{}
		json.Unmarshal(sysJSON, &sysData)

		if svcs, ok := sysData["services"].([]interface{}); ok {
			for _, svc := range svcs {
				s, ok := svc.(map[string]interface{})
				if !ok {
					continue
				}
				svcType := getString(s, "type")
				if category != "" && category != "所有" && svcType != category {
					continue
				}
				ports := []string{}
				if p, ok := s["listen_port"].([]interface{}); ok {
					for _, pp := range p {
						if ps, ok := pp.(string); ok {
							ports = append(ports, ps)
						}
					}
				}
				items = append(items, AssetItem{
					Type:        svcType,
					AgentID:     aid,
					Hostname:    agent.Hostname,
					ServiceName: getString(s, "name"),
					Version:     getString(s, "version"),
					PID:         int32(getFloat(s, "pid")),
					ListenPort:  ports,
					ExePath:     getString(s, "exe_path"),
					ConfigPath:  getString(s, "config_path"),
				})
			}
		}

		if wcs, ok := sysData["web_components"].([]interface{}); ok {
			for _, wc := range wcs {
				w, ok := wc.(map[string]interface{})
				if !ok {
					continue
				}
				wcType := getString(w, "type")
				if category != "" && category != "所有" && wcType != category {
					continue
				}
				items = append(items, AssetItem{
					Type:        wcType,
					AgentID:     aid,
					Hostname:    agent.Hostname,
					ServiceName: getString(w, "name"),
					Version:     getString(w, "version"),
					PID:         int32(getFloat(w, "pid")),
					ExePath:     getString(w, "base_path"),
					ConfigPath:  getString(w, "config_path"),
				})
			}
		}
	}

	c.JSON(200, gin.H{"total": len(items), "items": items})
}

// getOS 获取 Agent 的 OS 名称
func (h *Handler) getOS(agentID string) string {
	_, _, sysJSON, err := h.Store.GetLatestAsset(agentID)
	if err != nil {
		return "-"
	}
	var sysData map[string]interface{}
	json.Unmarshal(sysJSON, &sysData)
	if s, ok := sysData["system"].(map[string]interface{}); ok {
		if osInfo, ok := s["os"].(map[string]interface{}); ok {
			if name, ok := osInfo["name"].(string); ok {
				return name
			}
		}
	}
	return "-"
}

// getString 从 map 安全获取字符串
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// getFloat 从 map 安全获取 float64
func getFloat(m map[string]interface{}, key string) float64 {
	if v, ok := m[key]; ok && v != nil {
		if f, ok := v.(float64); ok {
			return f
		}
	}
	return 0
}

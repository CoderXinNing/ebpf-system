package handler

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

// SearchStarChain 按 IP/主机名/correlation_id 搜索攻击链
func (h *Handler) SearchStarChain(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		c.JSON(400, gin.H{"error": "缺少查询参数"})
		return
	}

	// 先按 correlation_id 查
	if h.ListStarEventsFunc != nil {
		events, err := h.ListStarEventsFunc(query)
		if err == nil && len(events) > 0 {
			tree := buildChainTree(events)
			c.JSON(200, gin.H{
				"query":          query,
				"match_type":     "correlation_id",
				"correlation_id": query,
				"total":          len(events),
				"tree":           tree,
			})
			return
		}
	}

	// 按 IP 或主机名查告警
	if h.ListAlertsFunc != nil {
		alerts, err := h.ListAlertsFunc(100)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		matchedAlerts := make([]map[string]interface{}, 0)
		for _, alert := range alerts {
			agentID := fmt.Sprintf("%v", alert["agent_id"])
			comm := fmt.Sprintf("%v", alert["comm"])
			pid := fmt.Sprintf("%v", alert["pid"])

			hostname := h.GetAgentHostname(agentID)
			ipAddr := h.GetAgentIP(agentID)

			// 匹配：agent_id / comm / pid / hostname / ip
			if containsStr(agentID, query) || containsStr(comm, query) || containsStr(pid, query) || containsStr(hostname, query) || containsStr(ipAddr, query) {
				alert["hostname"] = hostname
				alert["ip_addr"] = ipAddr
				matchedAlerts = append(matchedAlerts, alert)
			}
		}

		if len(matchedAlerts) > 0 {
			c.JSON(200, gin.H{
				"query":      query,
				"match_type": "alerts",
				"alerts":     matchedAlerts,
			})
			return
		}
	}

	c.JSON(404, gin.H{"error": "未找到匹配结果"})
}

func contains(s, substr interface{}) bool {
	str, ok1 := s.(string)
	sub, ok2 := substr.(string)
	if !ok1 || !ok2 {
		return false
	}
	return len(str) > 0 && len(sub) > 0 && (str == sub || containsStr(str, sub))
}

// GetAgentIP 查询 Agent IP
func (h *Handler) GetAgentIP(agentID string) string {
	h.Mu.RLock()
	if agent, ok := h.Agents[agentID]; ok {
		h.Mu.RUnlock()
		return agent.IPAddr
	}
	h.Mu.RUnlock()
	return ""
}

// GetAgentHostname 查询 Agent 主机名（通过 PSQL）
func (h *Handler) GetAgentHostname(agentID string) string {
	// 从内存 map 找
	h.Mu.RLock()
	if agent, ok := h.Agents[agentID]; ok {
		h.Mu.RUnlock()
		return agent.Hostname
	}
	h.Mu.RUnlock()
	return ""
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

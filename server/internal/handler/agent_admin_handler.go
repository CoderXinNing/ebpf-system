package handler

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// DeleteAgent 删除 Agent（DB + 内存）
func (h *Handler) DeleteAgent(c *gin.Context) {
	var req struct {
		AgentID string `json:"agent_id"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}
	if req.AgentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 agent_id"})
		return
	}

	// 1. DB 删除
	if h.DeleteAgentFunc != nil {
		if err := h.DeleteAgentFunc(req.AgentID); err != nil {
			log.Printf("⚠️ DB 删除 Agent 失败: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	// 2. 内存删除
	h.Mu.Lock()
	delete(h.Agents, req.AgentID)
	h.Mu.Unlock()

	log.Printf("🗑️  Agent 已删除: %s", req.AgentID)
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Agent 已删除"})
}

// ReloadAgents 从 DB 全量重载 Agent 到内存
func (h *Handler) ReloadAgents(c *gin.Context) {
	if h.ReloadAgentsFunc == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "重载功能未初始化"})
		return
	}

	count, err := h.ReloadAgentsFunc()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	log.Printf("🔄 Agent 列表已重载: %d 个", count)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"count":   count,
		"message": "Agent 列表已重载",
	})
}

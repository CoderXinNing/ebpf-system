package handler

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// RevokeAgent 撤销 Agent
//
// 效果：设置 revoked_at，之后 L4 校验会拒绝该 Agent 的连接
func (h *Handler) RevokeAgent(c *gin.Context) {
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

	if h.RevokeAgentFunc == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "撤销功能未初始化"})
		return
	}

	if err := h.RevokeAgentFunc(req.AgentID); err != nil {
		log.Printf("⚠️ 撤销 Agent 失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	log.Printf("🔒 Agent 已撤销: %s", req.AgentID)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Agent 已撤销，下次连接将被拒绝",
	})
}

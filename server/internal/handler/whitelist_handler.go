package handler

import (
	"github.com/gin-gonic/gin"
)

// WhitelistItem 白名单条目
type WhitelistItem struct {
	ProcessName string `json:"process_name"`
	Reason      string `json:"reason"`
}

// ListWhitelist 查询白名单
func (h *Handler) ListWhitelist(c *gin.Context) {
	c.JSON(200, gin.H{
		"whitelist": []WhitelistItem{
			{ProcessName: "sshd", Reason: "正常运维进程"},
			{ProcessName: "cron", Reason: "系统定时任务"},
		},
	})
}

// AddWhitelist 添加白名单
func (h *Handler) AddWhitelist(c *gin.Context) {
	var req WhitelistItem
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请求格式错误"})
		return
	}
	c.JSON(200, gin.H{"success": true, "message": "白名单已添加"})
}

// RemoveWhitelist 移除白名单
func (h *Handler) RemoveWhitelist(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "message": "白名单已移除"})
}

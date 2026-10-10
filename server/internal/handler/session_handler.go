package handler

import (
	"log"

	"github.com/gin-gonic/gin"
)

// SessionKeepalive 心跳：延长会话
//
// 前端在页面可见时定时调用（默认 5 分钟一次）。
// authMiddleware 已经通过 ValidateAndTouch 完成 Touch，
// 这里只需返回成功。
func (h *Handler) SessionKeepalive(c *gin.Context) {
	c.JSON(200, gin.H{"success": true})
}

// SessionConfig 返回当前会话配置
func (h *Handler) SessionConfig(c *gin.Context) {
	idleMinutes, absoluteHours, heartbeatInterval := h.Auth.GetSessionConfig(c.Request.Context())

	heartbeatEnabled := false
	if sid, ok := c.Get("session_id"); ok {
		if id, ok := sid.(int64); ok && id > 0 {
			if sess, err := h.Auth.GetSessionByID(c.Request.Context(), id); err == nil {
				heartbeatEnabled = sess.Keepalive
			}
		}
	}

	c.JSON(200, gin.H{
		"idle_minutes":               idleMinutes,
		"absolute_hours":             absoluteHours,
		"heartbeat_enabled":          heartbeatEnabled,
		"heartbeat_interval_seconds": heartbeatInterval,
	})
}

// SessionHeartbeat 切换心跳开关
func (h *Handler) SessionHeartbeat(c *gin.Context) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请求格式错误"})
		return
	}

	sid, ok := c.Get("session_id")
	if !ok {
		c.JSON(401, gin.H{"error": "会话不存在"})
		return
	}
	id, ok := sid.(int64)
	if !ok || id <= 0 {
		c.JSON(500, gin.H{"error": "会话 ID 异常"})
		return
	}

	if err := h.Auth.UpdateSessionHeartbeat(c.Request.Context(), id, req.Enabled); err != nil {
		log.Printf("⚠️ 切换心跳开关失败: %v", err)
		c.JSON(500, gin.H{"error": "切换失败"})
		return
	}

	c.JSON(200, gin.H{"success": true, "enabled": req.Enabled})
}

// SessionClose 关闭会话
//
// 前端在 beforeunload 时通过 sendBeacon 调用（不可靠）。
// 后端必须依赖 idle timeout 兜底。
func (h *Handler) SessionClose(c *gin.Context) {
	if sid, ok := c.Get("session_id"); ok {
		if id, ok := sid.(int64); ok {
			if err := h.Auth.RevokeSessionByID(c.Request.Context(), id); err != nil {
				log.Printf("⚠️ 关闭会话失败: %v", err)
			}
		}
	}
	c.JSON(200, gin.H{"success": true})
}

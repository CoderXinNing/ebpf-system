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
//
// 前端心跳后调用，同步 idle / absolute 配置（配置被改后，前端最多 5 分钟感知）
func (h *Handler) SessionConfig(c *gin.Context) {
	idleMinutes, absoluteHours := h.Auth.GetSessionConfig(c.Request.Context())

	keepalive := false
	if sid, ok := c.Get("session_id"); ok {
		if id, ok := sid.(int64); ok && id > 0 {
			// 从会话记录读 keepalive 状态
			if sess, err := h.Auth.GetSessionByID(c.Request.Context(), id); err == nil {
				keepalive = sess.Keepalive
			}
		}
	}

	c.JSON(200, gin.H{
		"idle_minutes":   idleMinutes,
		"absolute_hours": absoluteHours,
		"keepalive":      keepalive,
	})
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

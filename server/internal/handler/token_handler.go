package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// ListEnrollmentTokens 列出所有注册 Token
func (h *Handler) ListEnrollmentTokens(c *gin.Context) {
	if h.ListTokensFunc == nil {
		c.JSON(http.StatusOK, gin.H{"tokens": []interface{}{}})
		return
	}
	tokens, err := h.ListTokensFunc()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tokens": tokens})
}

// CreateEnrollmentToken 生成注册 Token
func (h *Handler) CreateEnrollmentToken(c *gin.Context) {
	var req struct {
		Name     string `json:"name"`
		GroupID  *int64 `json:"group_id"`
		MaxUses  int    `json:"max_uses"`
		TTLHours int    `json:"ttl_hours"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "名称不能为空"})
		return
	}
	if req.MaxUses <= 0 {
		req.MaxUses = 1
	}
	if req.TTLHours <= 0 {
		req.TTLHours = 24
	}

	if h.GenerateTokenFunc == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token 功能未初始化"})
		return
	}

	// 从 JWT 里取当前用户
	createdBy, _ := c.Get("username")
	createdByStr, _ := createdBy.(string)

	token, err := h.GenerateTokenFunc(req.Name, req.GroupID, req.MaxUses, req.TTLHours, createdByStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"token":   token,
		"message": fmt.Sprintf("Token 已生成（%d 次，%d 小时）", req.MaxUses, req.TTLHours),
	})
}

// RevokeEnrollmentToken 撤销 Token
func (h *Handler) RevokeEnrollmentToken(c *gin.Context) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}
	if req.ID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效 ID"})
		return
	}
	if h.RevokeTokenFunc == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token 功能未初始化"})
		return
	}
	if err := h.RevokeTokenFunc(req.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Token 已撤销"})
}

// 用于统一时间格式
var _ = time.Now

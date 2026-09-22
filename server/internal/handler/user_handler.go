package handler

import (
	"github.com/gin-gonic/gin"
)

// CreateUser 创建用户
func (h *Handler) CreateUser(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请求格式错误"})
		return
	}
	if req.Username == "" || req.Password == "" || req.Role == "" {
		c.JSON(400, gin.H{"error": "用户名/密码/角色不能为空"})
		return
	}
	if req.Role != "admin" && req.Role != "operator" && req.Role != "viewer" {
		c.JSON(400, gin.H{"error": "角色必须是 admin/operator/viewer"})
		return
	}
	if err := h.Auth.CreateUser(c.Request.Context(), req.Username, req.Password, req.Role); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"success": true, "message": "用户已创建"})
}

// UpdateUser 修改用户
func (h *Handler) UpdateUser(c *gin.Context) {
	var req struct {
		ID       int    `json:"id"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请求格式错误"})
		return
	}
	if req.ID <= 0 {
		c.JSON(400, gin.H{"error": "无效用户 ID"})
		return
	}

	if req.Role != "" {
		if req.Role != "admin" && req.Role != "operator" && req.Role != "viewer" {
			c.JSON(400, gin.H{"error": "角色必须是 admin/operator/viewer"})
			return
		}
		if err := h.Auth.UpdateUserRole(c.Request.Context(), req.ID, req.Role); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
	}

	if req.Password != "" {
		if len(req.Password) < 6 {
			c.JSON(400, gin.H{"error": "密码至少 6 位"})
			return
		}
		if err := h.Auth.ChangePassword(c.Request.Context(), req.ID, req.Password); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
	}

	c.JSON(200, gin.H{"success": true, "message": "用户已更新"})
}

// DeleteUser 删除用户
func (h *Handler) DeleteUser(c *gin.Context) {
	var req struct {
		ID int `json:"id"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请求格式错误"})
		return
	}
	if req.ID <= 0 {
		c.JSON(400, gin.H{"error": "无效用户 ID"})
		return
	}

	// 防止删除自己
	curUser, _ := c.Get("username")
	users, _ := h.Auth.ListUsers(c.Request.Context())
	for _, u := range users {
		if u.ID == req.ID && u.Username == curUser {
			c.JSON(400, gin.H{"error": "不能删除当前登录用户"})
			return
		}
	}

	if err := h.Auth.DeleteUser(c.Request.Context(), req.ID); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"success": true, "message": "用户已删除"})
}

package handler

import (
	"fmt"
	"log"
	"time"

	"github.com/CoderXinNing/ebpf-system/server/internal/audit"
	"github.com/CoderXinNing/ebpf-system/server/internal/auth"
	"github.com/gin-gonic/gin"
)

// Login 用户登录
func (h *Handler) Login(c *gin.Context) {
	var req struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		Keepalive bool   `json:"keepalive"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请求格式错误"})
		return
	}

	// 检查是否锁定
	maxAttempts := h.GetSecuritySetting("max_login_attempts", 5)
	lockMinutes := h.GetSecuritySetting("lock_minutes", 15)
	attemptKey := "login_attempt:" + req.Username

	attempts := h.GetIntSetting(attemptKey, 0)
	lockUntil := h.GetIntSetting("lock_until:"+req.Username, 0)
	if lockUntil > int(time.Now().Unix()) {
		remain := (lockUntil - int(time.Now().Unix())) / 60
		h.writeAudit(c, audit.Record{
			Username:   req.Username,
			Action:     "登录失败",
			ActionCode: audit.ActionLoginFail,
			TargetType: audit.TargetSession,
			Detail:     fmt.Sprintf("账户锁定中,剩余%d分钟", remain),
			EventType:  audit.EventConsoleSignin,
			EventRW:    audit.RWWrite,
			Result:     audit.ResultFailure,
		})
		c.JSON(401, gin.H{"error": fmt.Sprintf("账户已锁定，请 %d 分钟后重试", remain)})
		return
	}

	user, err := h.Auth.VerifyPassword(c.Request.Context(), req.Username, req.Password)
	if err != nil {
		attempts++
		h.SetIntSetting(attemptKey, attempts)
		if attempts >= maxAttempts {
			lockUntil := int(time.Now().Unix()) + lockMinutes*60
			h.SetIntSetting("lock_until:"+req.Username, lockUntil)
			h.SetIntSetting(attemptKey, 0)
			h.writeAudit(c, audit.Record{
				Username:   req.Username,
				Action:     "登录锁定",
				ActionCode: audit.ActionLoginLocked,
				TargetType: audit.TargetSession,
				Detail:     fmt.Sprintf("连续失败%d次,锁定%d分钟", attempts, lockMinutes),
				EventType:  audit.EventConsoleSignin,
				EventRW:    audit.RWWrite,
				Result:     audit.ResultFailure,
			})
			c.JSON(401, gin.H{"error": fmt.Sprintf("连续失败 %d 次，账户锁定 %d 分钟", maxAttempts, lockMinutes)})
			return
		}
		h.writeAudit(c, audit.Record{
			Username:   req.Username,
			Action:     "登录失败",
			ActionCode: audit.ActionLoginFail,
			TargetType: audit.TargetSession,
			Detail:     fmt.Sprintf("密码错误(%d/%d)", attempts, maxAttempts),
			EventType:  audit.EventConsoleSignin,
			EventRW:    audit.RWWrite,
			Result:     audit.ResultFailure,
		})
		c.JSON(401, gin.H{"error": fmt.Sprintf("用户名或密码错误（剩余尝试 %d 次）", maxAttempts-attempts)})
		return
	}

	// 登录成功，清除计数
	h.SetIntSetting(attemptKey, 0)

	// 创建会话
	sessionID, dbID, err := h.Auth.CreateSession(
		c.Request.Context(), user.ID, c.ClientIP(), c.Request.UserAgent(), req.Keepalive)
	if err != nil {
		log.Printf("⚠️ 创建会话失败: %v", err)
		c.JSON(500, gin.H{"error": "创建会话失败"})
		return
	}

	// 生成 JWT（携带 session_id）
	token, err := h.Auth.GenerateToken(user, sessionID)
	if err != nil {
		log.Printf("⚠️ 生成 token 失败: %v", err)
		c.JSON(500, gin.H{"error": "生成 token 失败"})
		return
	}

	h.writeAudit(c, audit.Record{
		Username:   user.Username,
		Action:     "登录成功",
		ActionCode: audit.ActionLogin,
		TargetType: audit.TargetSession,
		TargetID:   fmt.Sprintf("%d", dbID),
		SessionID:  &dbID, // 登录时中间件未跑，手动填
		Detail:     "Web登录",
		EventType:  audit.EventConsoleSignin,
		EventRW:    audit.RWWrite,
		Result:     audit.ResultSuccess,
	})
	idleMinutes, absoluteHours := h.Auth.GetSessionConfig(c.Request.Context())
	c.JSON(200, gin.H{
		"token": token,
		"user":  user,
		"session": gin.H{
			"idle_minutes":   idleMinutes,
			"absolute_hours": absoluteHours,
			"keepalive":      req.Keepalive,
		},
	})
}

// ListUsers 用户列表
func (h *Handler) ListUsers(c *gin.Context) {
	users, err := h.Auth.ListUsers(c.Request.Context())
	if err != nil {
		c.JSON(500, gin.H{"error": "查询用户失败"})
		return
	}
	c.JSON(200, gin.H{"users": users})
}

// authMiddleware JWT 验证中间件
func (h *Handler) authMiddleware(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(401, gin.H{"error": "未登录"})
		c.Abort()
		return
	}
	// 去掉 "Bearer " 前缀
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}
	// 验证 JWT + 校验 session 生命周期 + 滑动续期
	user, sessionDBID, err := h.Auth.ValidateAndTouch(c.Request.Context(), token)
	if err != nil {
		c.JSON(401, gin.H{"error": err.Error()})
		c.Abort()
		return
	}
	c.Set("user", user)
	c.Set("session_id", sessionDBID)
	c.Next()
}

// roleMiddleware 角色权限中间件（兼容旧 API，内部转调 rbacMiddleware）
func (h *Handler) roleMiddleware(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.JSON(401, gin.H{"error": "未登录"})
			c.Abort()
			return
		}
		u := user.(*auth.User)
		for _, role := range roles {
			if u.Role == role {
				c.Next()
				return
			}
		}
		c.JSON(403, gin.H{"error": "权限不足"})
		c.Abort()
	}
}

// rbacMiddleware 基于 role_permissions 表的 RBAC 中间件
// 用法：h.rbacMiddleware("agents", "write") 表示需要 agents 资源的 write 权限
func (h *Handler) rbacMiddleware(resource string, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.JSON(401, gin.H{"error": "未登录"})
			c.Abort()
			return
		}
		u := user.(*auth.User)
		hasPerm, err := h.Auth.HasPermission(c.Request.Context(), u.Role, resource, action)
		if err != nil {
			c.JSON(500, gin.H{"error": "权限查询失败"})
			c.Abort()
			return
		}
		if !hasPerm {
			c.JSON(403, gin.H{"error": "权限不足"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// getUsername 从 context 获取用户名
func (h *Handler) getUsername(c *gin.Context) string {
	user, exists := c.Get("user")
	if !exists {
		return "unknown"
	}
	return user.(*auth.User).Username
}

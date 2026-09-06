package handler

import (
	"fmt"
	"os/exec"
	"sync"
	"log"

	"github.com/CoderXinNing/ebpf-system/proto/pb"
	"github.com/CoderXinNing/ebpf-system/server/internal/auth"
	"github.com/CoderXinNing/ebpf-system/server/internal/store"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	movedGroups map[string]string
	Store *store.Store
	Auth  *auth.AuthManager
	Agents map[string]*AgentInfo
	Events []ProbeEvent
	Mu     sync.RWMutex
	EventMu sync.RWMutex
	sendCmd func(agentID string, cmd *pb.ProbeCommand) error
}

type AgentInfo struct {
	ID           string            `json:"id"`
	Hostname     string            `json:"hostname"`
	IPAddr       string            `json:"ip_addr"`
	Token        string            `json:"-"`
	Version     string            `json:"version"`
	Group       string            `json:"group"`
	ActiveProbes int32             `json:"active_probes"`
	ProbeDetails string            `json:"probe_details"`
	BaselineState string           `json:"baseline_state"`
	BaselineRemaining int64        `json:"baseline_remaining"`
	LastSeen     int64             `json:"last_seen"`
	FirstSeen    int64             `json:"first_seen"`
	Framework    *pb.FrameworkInfo `json:"framework"`
	KernelInfo   *pb.KernelInfo    `json:"kernel_info"`
	Commands     []*pb.ProbeCommand `json:"-"`
}

type ProbeEvent struct {
	ID             string `json:"id"`
	AgentID        string `json:"agent_id"`
	ProbeName      string `json:"probe_name"`
	Timestamp      int64  `json:"timestamp"`
	EventType      string `json:"event_type"`
	PID            int32  `json:"pid"`
	Comm           string `json:"comm"`
	Filename       string `json:"filename"`
	Details        string `json:"details,omitempty"`
	CorrelationID  string `json:"correlation_id,omitempty"`
	CorrelationKey uint64 `json:"correlation_key,omitempty"`
}

func NewHandler(st *store.Store, am *auth.AuthManager, sendCmd func(string, *pb.ProbeCommand) error) *Handler {
	return &Handler{
		Store:   st,
		Auth:    am,
		Agents:  make(map[string]*AgentInfo),
		movedGroups: make(map[string]string),
		Events:  make([]ProbeEvent, 0, 10000),
		sendCmd: sendCmd,
	}
}

// NewHandlerWithNilStore 创建无 Store 的 Handler（PSQL 模式过渡期使用）
func NewHandlerWithNilStore(am *auth.AuthManager, sendCmd func(string, *pb.ProbeCommand) error) *Handler {
	return &Handler{
		Store:   nil,
		Auth:    am,
		Agents:  make(map[string]*AgentInfo),
		movedGroups: make(map[string]string),
		Events:  make([]ProbeEvent, 0, 10000),
		sendCmd: sendCmd,
	}
}

func (h *Handler) SetupRoutes(r *gin.Engine) {
	r.POST("/api/login", h.Login)

	api := r.Group("/api")
	api.Use(h.authMiddleware)
	{
		api.GET("/health", h.Health)
		api.GET("/agents", h.ListAgents)
		api.GET("/events", h.ListEvents)
		api.GET("/star/:correlation_id", h.rbacMiddleware("events", "read"), h.GetStarChain)
		api.DELETE("/agents/:id", h.rbacMiddleware("agents", "delete"), func(c *gin.Context) {
			agentID := c.Param("id")
			h.Store.DeleteAgentAll(agentID)
			h.Mu.Lock()
			delete(h.Agents, agentID)
			h.Mu.Unlock()
			h.Store.SaveAuditLog(h.getUsername(c), "删除主机", agentID, c.ClientIP())
			c.JSON(200, gin.H{"success": true})
		})

		api.POST("/move", h.rbacMiddleware("agents", "write"), func(c *gin.Context) {
			var req struct {
				AgentIDs []string `json:"agent_ids"`
				Group    string   `json:"group"`
			}
			c.BindJSON(&req)
			h.Mu.Lock()
			for _, aid := range req.AgentIDs {
				if agent, ok := h.Agents[aid]; ok {
					agent.Group = req.Group
					h.movedGroups[aid] = req.Group
				}
			}
			h.Mu.Unlock()
			log.Printf("📋 移动主机: %v -> %s", req.AgentIDs, req.Group)
			h.Store.SaveAuditLog(h.getUsername(c), "移动主机", fmt.Sprintf("%v -> %s", req.AgentIDs, req.Group), c.ClientIP())
			c.JSON(200, gin.H{"success": true})
		})
		api.POST("/command", h.rbacMiddleware("agents", "write"), h.Command)

		// 探针管理
		api.GET("/probes/config", h.rbacMiddleware("probes", "read"), h.ListProbeConfigs)
		api.POST("/probes/deploy", h.rbacMiddleware("probes", "write"), h.DeployProbe)
		api.POST("/probes/destroy", h.rbacMiddleware("probes", "write"), h.DestroyProbe)
		api.GET("/assets", h.AssetsOverview)
		api.GET("/assets/:agent_id", h.AssetDetail)
		api.GET("/groups", func(c *gin.Context) {
			groups, _ := h.Store.GetGroups()
			c.JSON(200, gin.H{"groups": groups})
		})
		api.POST("/groups", h.roleMiddleware("admin", "operator"), func(c *gin.Context) {
			var req struct { Name string `json:"name"` }
			c.BindJSON(&req)
			if req.Name == "" {
				c.JSON(400, gin.H{"error": "组名不能为空"})
				return
			}
			if err := h.Store.CreateGroup(req.Name); err != nil {
				c.JSON(500, gin.H{"error": "创建失败"})
				return
			}
			log.Printf("📋 创建分组: %s", req.Name)
			c.JSON(200, gin.H{"success": true})
		})
		api.DELETE("/groups/:name", h.roleMiddleware("admin"), func(c *gin.Context) {
			name := c.Param("name")
			if err := h.Store.DeleteGroup(name); err != nil {
				c.JSON(500, gin.H{"error": "删除失败"})
				return
			}
			log.Printf("🗑️ 删除分组: %s", name)
			c.JSON(200, gin.H{"success": true})
		})
		api.GET("/assets/category", h.AssetsByCategory)
		api.GET("/alerts", func(c *gin.Context) {
			alerts, _ := h.Store.GetAlerts(100)
			if alerts == nil {
				alerts = []store.AlertRecord{}
			}
			c.JSON(200, gin.H{"alerts": alerts})
		})
		api.GET("/baseline/stats", h.roleMiddleware("admin", "operator"), func(c *gin.Context) {
			h.Mu.RLock()
			defer h.Mu.RUnlock()
			learning := 0
			observe := 0
			protect := 0
			offline := 0
			for _, a := range h.Agents {
				switch a.BaselineState {
				case "learning":
					learning++
				case "observe":
					observe++
				case "protect":
					protect++
				default:
					offline++
				}
			}
			c.JSON(200, gin.H{
				"learning": learning,
				"observe":  observe,
				"protect":  protect,
				"offline":  offline,
				"total":    len(h.Agents),
			})
		})

		api.GET("/alerts/stats", h.rbacMiddleware("alerts", "read"), func(c *gin.Context) {
			c.JSON(200, h.Store.GetAlertStats())
		})
		api.POST("/alerts/:id/feedback", h.rbacMiddleware("alerts", "write"), func(c *gin.Context) {
			id := c.Param("id")
			var req struct {
				Type string `json:"type"`
			}
			c.BindJSON(&req)
			h.Store.SaveAlertFeedback(id, req.Type, h.getUsername(c))

			// 误报 → 记录特征到黑名单
			if req.Type == "false_positive" {
				// 从告警里提取特征信息存入黑名单
				alerts, _ := h.Store.GetAlerts(1)
				if len(alerts) > 0 {
					featureKey := alerts[0].Comm + ":" + alerts[0].Filename
					h.Store.SaveFeedbackFeature(featureKey)
					log.Printf("📝 误报特征已记录: %s", featureKey)
				}
			}
			c.JSON(200, gin.H{"success": true})
		})
		api.GET("/users", h.rbacMiddleware("users", "read"), h.ListUsers)

		// 审计日志
		api.POST("/logout", h.authMiddleware, func(c *gin.Context) {
			h.Store.SaveAuditLog(h.getUsername(c), "注销", "退出登录", c.ClientIP())
			c.JSON(200, gin.H{"success": true})
		})

		api.GET("/logs/export", h.rbacMiddleware("audit", "export"), func(c *gin.Context) {
			logs, _ := h.Store.GetAuditLogs(10000)
			c.Header("Content-Type", "text/csv")
			c.Header("Content-Disposition", "attachment; filename=audit_logs.csv")
			c.String(200, "id,username,action,detail,ip,created_at\n")
			for _, l := range logs {
				c.String(200, "%v,%s,%s,%s,%s,%v\n",
					l["id"], l["username"], l["action"], l["detail"], l["ip"], l["created_at"])
			}
		})

		api.GET("/logs", h.rbacMiddleware("audit", "read"), func(c *gin.Context) {
			logs, _ := h.Store.GetAuditLogs(200)
			c.JSON(200, gin.H{"logs": logs})
		})

		// 日志设置
		api.POST("/system/page-visit", h.authMiddleware, func(c *gin.Context) {
			var req struct {
				Page string `json:"page"`
			}
			c.BindJSON(&req)
			pageName := map[string]string{
				"/": "仪表盘", "/hosts": "主机管理", "/events": "事件流",
				"/alerts": "告警中心", "/probes": "探针管理", "/install": "Agent部署",
				"/users": "用户管理", "/logs": "系统日志", "/log-settings": "日志管理",
				"/time-settings": "时间设置", "/personalize": "个性化", "/about": "关于系统",
			}[req.Page]
			if pageName == "" {
				pageName = req.Page
			}
			h.Store.SaveAuditLog(h.getUsername(c), "访问页面", pageName, c.ClientIP())
			c.JSON(200, gin.H{"success": true})
		})

		api.POST("/system/time", h.roleMiddleware("admin"), func(c *gin.Context) {
			var req struct {
				Datetime string `json:"datetime"` // 2026-09-04 16:45:00
			}
			c.BindJSON(&req)
			if req.Datetime != "" {
				cmd := exec.Command("date", "-s", req.Datetime)
				if err := cmd.Run(); err != nil {
					c.JSON(500, gin.H{"error": "设置失败: " + err.Error()})
					return
				}
				h.Store.SaveAuditLog(h.getUsername(c), "修改系统时间", req.Datetime, c.ClientIP())
			}
			c.JSON(200, gin.H{"success": true})
		})
		api.POST("/system/ntp", h.roleMiddleware("admin"), func(c *gin.Context) {
			var req struct {
				Server string `json:"server"`
			}
			c.BindJSON(&req)
			if req.Server != "" {
				cmd := exec.Command("ntpdate", req.Server)
				if err := cmd.Run(); err != nil {
					c.JSON(500, gin.H{"error": "NTP同步失败: " + err.Error()})
					return
				}
				h.Store.SaveAuditLog(h.getUsername(c), "NTP同步", req.Server, c.ClientIP())
			}
			c.JSON(200, gin.H{"success": true})
		})

		api.GET("/security-settings", h.roleMiddleware("admin"), func(c *gin.Context) {
			c.JSON(200, gin.H{
				"max_login_attempts": h.GetSecuritySetting("max_login_attempts", 5),
				"lock_minutes":       h.GetSecuritySetting("lock_minutes", 15),
				"min_password_len":   h.GetSecuritySetting("min_password_len", 8),
			})
		})
		api.POST("/security-settings", h.roleMiddleware("admin"), func(c *gin.Context) {
			var req struct {
				MaxLoginAttempts int `json:"max_login_attempts"`
				LockMinutes      int `json:"lock_minutes"`
				MinPasswordLen   int `json:"min_password_len"`
			}
			c.BindJSON(&req)
			if req.MaxLoginAttempts > 0 { h.SetIntSetting("max_login_attempts", req.MaxLoginAttempts) }
			if req.LockMinutes > 0 { h.SetIntSetting("lock_minutes", req.LockMinutes) }
			if req.MinPasswordLen > 0 { h.SetIntSetting("min_password_len", req.MinPasswordLen) }
			c.JSON(200, gin.H{"success": true})
		})

		api.GET("/log-settings", h.roleMiddleware("admin"), func(c *gin.Context) {
			eventDays, _ := h.Store.GetLogSetting("event_days")
			alertDays, _ := h.Store.GetLogSetting("alert_days")
			auditDays, _ := h.Store.GetLogSetting("audit_days")
			c.JSON(200, gin.H{
				"event_days": eventDays,
				"alert_days": alertDays,
				"audit_days": auditDays,
			})
		})
		api.POST("/log-settings", h.roleMiddleware("admin"), func(c *gin.Context) {
			var req struct {
				EventDays string `json:"event_days"`
				AlertDays string `json:"alert_days"`
				AuditDays string `json:"audit_days"`
			}
			c.BindJSON(&req)
			if req.EventDays != "" { h.Store.SetLogSetting("event_days", req.EventDays) }
			if req.AlertDays != "" { h.Store.SetLogSetting("alert_days", req.AlertDays) }
			if req.AuditDays != "" { h.Store.SetLogSetting("audit_days", req.AuditDays) }
			c.JSON(200, gin.H{"success": true})
		})
	}
}

// ListProbeConfigs 查询探针配置
// DeployProbe 下发/更新探针配置
// DestroyProbe 销毁探针配置

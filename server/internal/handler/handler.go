package handler

import (
	"fmt"
	"log"
	"os/exec"
	"sync"
	"time"

	"github.com/CoderXinNing/ebpf-system/proto/pb"
	"github.com/CoderXinNing/ebpf-system/server/internal/auth"
	"github.com/CoderXinNing/ebpf-system/server/internal/store"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	// GRPCPort Server 的 gRPC 监听端口（enrollment 时回报给 Agent）
	GRPCPort int

	movedGroups           map[string]string
	Store                 *store.Store
	Auth                  *auth.AuthManager
	Agents                map[string]*AgentInfo
	Events                []ProbeEvent
	Mu                    sync.RWMutex
	EventMu               sync.RWMutex
	sendCmd               func(agentID string, cmd *pb.ProbeCommand) error
	SaveEventFunc         func(evt ProbeEvent) error                        // PSQL 模式注入
	SaveAgentFunc         func(agent AgentInfo) error                       // PSQL 模式注入
	ListAlertsFunc        func(limit int) ([]map[string]interface{}, error) // PSQL 模式注入
	UpdateAlertStatusFunc func(ids []int64, status string) error            // 告警状态更新
	ListWhitelistFunc     func() ([]string, error)
	AddWhitelistFunc      func(processName, reason string) error
	RemoveWhitelistFunc   func(processName string) error
	Whitelist             []string                                                                // 白名单（进程名列表）
	WhitelistUpdateFunc   func([]string)                                                          // 白名单更新回调
	ListStarEventsFunc    func(corrID string) ([]map[string]interface{}, error)                   // PSQL 攻击链查询
	GetLatestAssetFunc    func(agentID string) (interface{}, interface{}, interface{}, error)     // PSQL 资产查询
	SaveAssetFunc         func(agentID string, processesJSON, usersJSON, systemJSON []byte) error // PSQL 资产保存
	GetAllAssetsFunc      func(agentID string) (map[string]interface{}, error)                    // 所有资产类型
	SaveTypedAssetFunc    func(agentID, assetType, assetName string, data interface{}) error      // 保存指定类型资产
	GetSettingFunc        func(key string) (string, error)
	SetSettingFunc        func(key, value string) error
	ListSettingsFunc      func() (map[string]string, error)

	// Enrollment（Day 1-3）
	GenerateTokenFunc func(name string, groupID *int64, maxUses int, ttlHours int, createdBy string) (string, error)
	ListTokensFunc    func() ([]map[string]interface{}, error)
	RevokeTokenFunc   func(id int64) error

	// Enroll（事务化）
	EnrollAgentFunc           func(req EnrollRequest) (*EnrollResult, error)
	ComputeAgentIDFunc        func(publicKeyDER []byte) string
	UpdateAgentCertFunc       func(agentID, serial string, expiresAt time.Time) error
	GetAgentPublicKeyHashFunc func(agentID string) ([]byte, error)
	RenewCertFunc             func(agentID string, csrPEM []byte) (*RenewCertResult, error)
	RevokeAgentFunc           func(agentID string) error
	DeleteAgentFunc           func(agentID string) error
	ReloadAgentsFunc          func() (int, error)

	// CA 签名
	SignCSRFunc func(csrPEM []byte, agentID string, ttlHours int) ([]byte, string, time.Time, error)
	CACertPEM   []byte // CA 证书 PEM（返回给 Agent）
}

type AgentInfo struct {
	ID                string                       `json:"id"`
	Hostname          string                       `json:"hostname"`
	IPAddr            string                       `json:"ip_addr"`
	Token             string                       `json:"-"`
	Version           string                       `json:"version"`
	Group             string                       `json:"group"`
	CapabilityLevel   string                       `json:"capability_level"`
	ActiveProbes      int32                        `json:"active_probes"`
	ProbeDetails      string                       `json:"probe_details"`
	BaselineState     string                       `json:"baseline_state"`
	BaselineRemaining int64                        `json:"baseline_remaining"`
	LastSeen          int64                        `json:"last_seen"`
	FirstSeen         int64                        `json:"first_seen"`
	Framework         *pb.FrameworkInfo            `json:"framework"`
	KernelInfo        *pb.KernelInfo               `json:"kernel_info"`
	Commands          []*pb.ProbeCommand           `json:"-"`
	ProbeStatus       map[string]*ProbeStatusEntry `json:"probe_status,omitempty"`
}

// ProbeStatusEntry 单个探针的详细状态（由 Agent 通过 ReportProbeStatus 上报）
type ProbeStatusEntry struct {
	Name                string `json:"name"`
	Status              string `json:"status"`
	Reason              string `json:"reason,omitempty"`
	LastEventAt         int64  `json:"last_event_at"`
	LastCheckAt         int64  `json:"last_check_at"`
	SelfTestOk          bool   `json:"selftest_ok"`
	ConsecutiveFailures int32  `json:"consecutive_failures"`
	LoadedAt            int64  `json:"loaded_at"`
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

// SetSaveEventFunc 设置事件保存回调（PSQL 模式）
func (h *Handler) SetSaveEventFunc(fn func(ProbeEvent) error) {
	h.SaveEventFunc = fn
}

// SetSaveAgentFunc 设置 Agent 保存回调（PSQL 模式）
func (h *Handler) SetSaveAgentFunc(fn func(AgentInfo) error) {
	h.SaveAgentFunc = fn
}

// SetSaveAssetFunc 设置资产保存回调
func (h *Handler) SetSaveAssetFunc(fn func(string, []byte, []byte, []byte) error) {
	h.SaveAssetFunc = fn
}

// SetSettingCallbacks 设置配置读写回调（PSQL 模式）
func (h *Handler) SetSettingCallbacks(get func(string) (string, error), set func(string, string) error, list func() (map[string]string, error)) {
	h.GetSettingFunc = get
	h.SetSettingFunc = set
	h.ListSettingsFunc = list
}

// SetSaveTypedAssetFunc 设置指定类型资产保存回调
func (h *Handler) SetSaveTypedAssetFunc(fn func(string, string, string, interface{}) error) {
	h.SaveTypedAssetFunc = fn
}

// SetGetAllAssetsFunc 设置所有资产查询回调
func (h *Handler) SetGetAllAssetsFunc(fn func(string) (map[string]interface{}, error)) {
	h.GetAllAssetsFunc = fn
}

// SetGetLatestAssetFunc 设置资产查询回调
func (h *Handler) SetGetLatestAssetFunc(fn func(string) (interface{}, interface{}, interface{}, error)) {
	h.GetLatestAssetFunc = fn
}

// SetListStarEventsFunc 设置攻击链查询回调
func (h *Handler) SetListStarEventsFunc(fn func(string) ([]map[string]interface{}, error)) {
	h.ListStarEventsFunc = fn
}

// SetWhitelistUpdateFunc 设置白名单更新回调
func (h *Handler) SetWhitelistUpdateFunc(fn func([]string)) {
	h.WhitelistUpdateFunc = fn
}

// SetListWhitelistFunc 设置白名单查询回调
func (h *Handler) SetListWhitelistFunc(fn func() ([]string, error)) {
	h.ListWhitelistFunc = fn
}

// SetAddWhitelistFunc 设置白名单添加回调
func (h *Handler) SetAddWhitelistFunc(fn func(string, string) error) {
	h.AddWhitelistFunc = fn
}

// SetRemoveWhitelistFunc 设置白名单移除回调
func (h *Handler) SetRemoveWhitelistFunc(fn func(string) error) {
	h.RemoveWhitelistFunc = fn
}

// SetUpdateAlertStatusFunc 设置告警状态更新回调
func (h *Handler) SetUpdateAlertStatusFunc(fn func([]int64, string) error) {
	h.UpdateAlertStatusFunc = fn
}

// SetListAlertsFunc 设置告警列表回调（PSQL 模式）
func (h *Handler) SetListAlertsFunc(fn func(int) ([]map[string]interface{}, error)) {
	h.ListAlertsFunc = fn
}

func NewHandler(st *store.Store, am *auth.AuthManager, sendCmd func(string, *pb.ProbeCommand) error) *Handler {
	return &Handler{
		Store:       st,
		Auth:        am,
		Agents:      make(map[string]*AgentInfo),
		movedGroups: make(map[string]string),
		Events:      make([]ProbeEvent, 0, 10000),
		sendCmd:     sendCmd,
	}
}

// NewHandlerWithNilStore 创建无 Store 的 Handler（PSQL 模式过渡期使用）
func NewHandlerWithNilStore(am *auth.AuthManager, sendCmd func(string, *pb.ProbeCommand) error) *Handler {
	return &Handler{
		Store:       nil,
		Auth:        am,
		Agents:      make(map[string]*AgentInfo),
		movedGroups: make(map[string]string),
		Events:      make([]ProbeEvent, 0, 10000),
		sendCmd:     sendCmd,
	}
}

func (h *Handler) SetupRoutes(r *gin.Engine) {
	r.POST("/api/login", h.Login)

	api := r.Group("/api")
	api.Use(h.authMiddleware)
	{
		api.GET("/health", h.Health)
		api.GET("/agents", h.ListAgents)
		api.POST("/agents/revoke", h.rbacMiddleware("agents", "write"), h.RevokeAgent)
		api.POST("/agents/delete", h.rbacMiddleware("agents", "write"), h.DeleteAgent)
		api.POST("/agents/reload", h.rbacMiddleware("agents", "write"), h.ReloadAgents)
		api.GET("/events", h.ListEvents)
		api.GET("/star/:correlation_id", h.rbacMiddleware("events", "read"), h.GetStarChain)
		api.GET("/star/search", h.rbacMiddleware("events", "read"), h.SearchStarChain)
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
			var req struct {
				Name string `json:"name"`
			}
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
		api.GET("/whitelist", h.rbacMiddleware("probes", "read"), h.ListWhitelist)
		api.POST("/whitelist", h.rbacMiddleware("probes", "write"), h.AddWhitelist)
		api.DELETE("/whitelist/:process_name", h.rbacMiddleware("probes", "write"), h.RemoveWhitelist)

		api.GET("/alerts", func(c *gin.Context) {
			log.Printf("DEBUG: ListAlertsFunc = %v", h.ListAlertsFunc != nil)
			if h.ListAlertsFunc != nil {
				alerts, err := h.ListAlertsFunc(100)
				if err != nil {
					c.JSON(500, gin.H{"error": err.Error()})
					return
				}
				c.JSON(200, gin.H{"alerts": alerts})
				return
			}
			if h.Store != nil {
				alerts, _ := h.Store.GetAlerts(100)
				if alerts == nil {
					alerts = []store.AlertRecord{}
				}
				c.JSON(200, gin.H{"alerts": alerts})
				return
			}
			c.JSON(200, gin.H{"alerts": []interface{}{}})
		})
		api.POST("/alerts/batch-resolve", h.rbacMiddleware("alerts", "write"), func(c *gin.Context) {
			var req struct {
				IDs    []int64 `json:"ids"`
				Status string  `json:"status"`
			}
			if err := c.BindJSON(&req); err != nil {
				c.JSON(400, gin.H{"error": "请求格式错误"})
				return
			}
			if req.Status == "" {
				req.Status = "resolved"
			}
			if h.UpdateAlertStatusFunc != nil {
				if err := h.UpdateAlertStatusFunc(req.IDs, req.Status); err != nil {
					c.JSON(500, gin.H{"error": err.Error()})
					return
				}
			}
			c.JSON(200, gin.H{"success": true, "message": fmt.Sprintf("已更新 %d 条告警", len(req.IDs))})
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
		api.POST("/users", h.rbacMiddleware("users", "write"), h.CreateUser)
		api.PUT("/users", h.rbacMiddleware("users", "write"), h.UpdateUser)
		api.DELETE("/users", h.rbacMiddleware("users", "write"), h.DeleteUser)

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

		// Enrollment（免认证，Agent 用 Token 换证书）
		r.POST("/api/agent/enroll", h.Enroll)

		// Token 管理（管理员）
		api.GET("/enrollment-tokens", h.rbacMiddleware("agents", "read"), h.ListEnrollmentTokens)
		api.POST("/enrollment-tokens", h.rbacMiddleware("agents", "write"), h.CreateEnrollmentToken)
		api.DELETE("/enrollment-tokens", h.rbacMiddleware("agents", "write"), h.RevokeEnrollmentToken)

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
			if req.MaxLoginAttempts > 0 {
				h.SetIntSetting("max_login_attempts", req.MaxLoginAttempts)
			}
			if req.LockMinutes > 0 {
				h.SetIntSetting("lock_minutes", req.LockMinutes)
			}
			if req.MinPasswordLen > 0 {
				h.SetIntSetting("min_password_len", req.MinPasswordLen)
			}
			c.JSON(200, gin.H{"success": true})
		})

		api.GET("/log-settings", h.roleMiddleware("admin"), func(c *gin.Context) {
			c.JSON(200, gin.H{
				"event_days": h.GetStringSetting("event_days", "30"),
				"alert_days": h.GetStringSetting("alert_days", "90"),
				"audit_days": h.GetStringSetting("audit_days", "180"),
			})
		})
		api.POST("/log-settings", h.roleMiddleware("admin"), func(c *gin.Context) {
			var req struct {
				EventDays string `json:"event_days"`
				AlertDays string `json:"alert_days"`
				AuditDays string `json:"audit_days"`
			}
			c.BindJSON(&req)
			if req.EventDays != "" {
				h.SetStringSetting("event_days", req.EventDays)
			}
			if req.AlertDays != "" {
				h.SetStringSetting("alert_days", req.AlertDays)
			}
			if req.AuditDays != "" {
				h.SetStringSetting("audit_days", req.AuditDays)
			}
			c.JSON(200, gin.H{"success": true})
		})

		// 通用设置接口
		api.GET("/settings", h.roleMiddleware("admin"), func(c *gin.Context) {
			if h.ListSettingsFunc != nil {
				settings, err := h.ListSettingsFunc()
				if err != nil {
					c.JSON(500, gin.H{"error": err.Error()})
					return
				}
				c.JSON(200, gin.H{"settings": settings})
				return
			}
			c.JSON(200, gin.H{"settings": map[string]string{}})
		})
		api.POST("/settings", h.roleMiddleware("admin"), func(c *gin.Context) {
			var req map[string]string
			if err := c.BindJSON(&req); err != nil {
				c.JSON(400, gin.H{"error": "请求格式错误"})
				return
			}
			for k, v := range req {
				h.SetStringSetting(k, v)
			}
			c.JSON(200, gin.H{"success": true, "message": fmt.Sprintf("已保存 %d 项设置", len(req))})
		})
	}
}

// ListProbeConfigs 查询探针配置
// DeployProbe 下发/更新探针配置
// DestroyProbe 销毁探针配置

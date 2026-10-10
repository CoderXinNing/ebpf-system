package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"sync"
	"time"

	"github.com/CoderXinNing/ebpf-system/proto/pb"
	"github.com/CoderXinNing/ebpf-system/server/internal/audit"
	"github.com/CoderXinNing/ebpf-system/server/internal/auth"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	// GRPCPort Server 的 gRPC 监听端口（enrollment 时回报给 Agent）
	GRPCPort int

	movedGroups    map[string]string
	Auth           *auth.AuthManager
	Agents         map[string]*AgentInfo
	Events         []ProbeEvent
	Mu             sync.RWMutex
	EventMu        sync.RWMutex
	sendCmd        func(agentID string, cmd *pb.ProbeCommand) error
	SaveEventFunc  func(evt ProbeEvent) error                        // PSQL 模式注入
	SaveAgentFunc  func(agent AgentInfo) error                       // PSQL 模式注入
	ListAlertsFunc func(limit int) ([]map[string]interface{}, error) // PSQL 模式注入
	SaveAuditFunc  func(rec audit.Record) error                      // PSQL 模式注入：写审计
	ListAuditFunc  func(limit int) ([]map[string]interface{}, error) // PSQL 模式注入：读审计

	// Step 2：SQLite 移除迁移新增
	ListGroupsFunc              func() ([]string, error)
	CreateGroupFunc             func(name string) error
	DeleteGroupFunc             func(name string) error
	GetAlertStatsFunc           func() map[string]interface{}
	SaveAlertFeedbackFunc       func(alertID string, feedback, username string) error
	SaveFeedbackFeatureFunc     func(featureKey string) error
	GetFeedbackFeaturesFunc     func() ([]string, error)
	GetAllLatestAssetsFunc      func() (map[string]map[string]int, error)
	GetProbeConfigsFunc         func(agentID string) ([]map[string]interface{}, error)
	GetEventsAsRecordsFunc      func(limit int, agentID string) ([]map[string]interface{}, error)
	CleanupFunc                 func(target, mode string, days int) (int64, error) // 数据/日志清理
	UpdateAlertStatusFunc       func(ids []int64, status string) error             // 告警状态更新
	ListProbeExcludeCommsFunc   func() ([]string, error)
	AddProbeExcludeCommsFunc    func(comm, reason string) error
	RemoveProbeExcludeCommsFunc func(comm string) error
	ProbeExcludeComms           []string // 探针排除名单（comm 列表）
	ProbeExcludeCommsUpdateFunc func([]string)

	// 三维度 #11/#12：file_access 独立 comm + tcp 独立 IP
	ListFileAccessExcludeCommsFunc   func() ([]string, error)
	AddFileAccessExcludeCommsFunc    func(comm, reason string) error
	RemoveFileAccessExcludeCommsFunc func(comm string) error
	ListExcludeIPsFunc               func() ([]string, error)
	AddExcludeIPFunc                 func(ip, reason string) error
	RemoveExcludeIPFunc              func(ip string) error

	// 统一 Apply（三维度一次性提交）
	GetAllExcludesFunc     func() (execComms, fileComms, ips []string, err error)
	ReplaceAllExcludesFunc func(execComms, fileComms, ips []string) error
	RebuildRulesFunc       func() error                                                                    // 排除名单更新回调
	ListStarEventsFunc     func(corrID string) ([]map[string]interface{}, error)                           // PSQL 攻击链查询
	GetLatestAssetFunc     func(agentID string) (json.RawMessage, json.RawMessage, json.RawMessage, error) // PSQL 资产查询
	SaveAssetFunc          func(agentID string, processesJSON, usersJSON, systemJSON []byte) error         // PSQL 资产保存
	GetAllAssetsFunc       func(agentID string) (map[string]interface{}, error)                            // 所有资产类型
	SaveTypedAssetFunc     func(agentID, assetType, assetName string, data interface{}) error              // 保存指定类型资产
	GetSettingFunc         func(key string) (string, error)
	SetSettingFunc         func(key, value string) error
	ListSettingsFunc       func() (map[string]string, error)

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
func (h *Handler) SetGetLatestAssetFunc(fn func(string) (json.RawMessage, json.RawMessage, json.RawMessage, error)) {
	h.GetLatestAssetFunc = fn
}

// SetListStarEventsFunc 设置攻击链查询回调
func (h *Handler) SetListStarEventsFunc(fn func(string) ([]map[string]interface{}, error)) {
	h.ListStarEventsFunc = fn
}

// SetProbeExcludeCommsUpdateFunc 设置探针排除名单更新回调
func (h *Handler) SetProbeExcludeCommsUpdateFunc(fn func([]string)) {
	h.ProbeExcludeCommsUpdateFunc = fn
}

// SetListProbeExcludeCommsFunc 设置探针排除名单查询回调
func (h *Handler) SetListProbeExcludeCommsFunc(fn func() ([]string, error)) {
	h.ListProbeExcludeCommsFunc = fn
}

// SetAddProbeExcludeCommsFunc 设置探针排除名单添加回调
func (h *Handler) SetAddProbeExcludeCommsFunc(fn func(string, string) error) {
	h.AddProbeExcludeCommsFunc = fn
}

// SetRemoveProbeExcludeCommsFunc 设置探针排除名单移除回调
func (h *Handler) SetRemoveProbeExcludeCommsFunc(fn func(string) error) {
	h.RemoveProbeExcludeCommsFunc = fn
}

// SetListFileAccessExcludeCommsFunc 设置 file_access 独立 comm 查询回调
func (h *Handler) SetListFileAccessExcludeCommsFunc(fn func() ([]string, error)) {
	h.ListFileAccessExcludeCommsFunc = fn
}

// SetAddFileAccessExcludeCommsFunc 设置 file_access 独立 comm 添加回调
func (h *Handler) SetAddFileAccessExcludeCommsFunc(fn func(comm, reason string) error) {
	h.AddFileAccessExcludeCommsFunc = fn
}

// SetRemoveFileAccessExcludeCommsFunc 设置 file_access 独立 comm 移除回调
func (h *Handler) SetRemoveFileAccessExcludeCommsFunc(fn func(comm string) error) {
	h.RemoveFileAccessExcludeCommsFunc = fn
}

// SetListExcludeIPsFunc 设置 tcp 独立 IP 查询回调
func (h *Handler) SetListExcludeIPsFunc(fn func() ([]string, error)) {
	h.ListExcludeIPsFunc = fn
}

// SetAddExcludeIPFunc 设置 tcp 独立 IP 添加回调
func (h *Handler) SetAddExcludeIPFunc(fn func(ip, reason string) error) {
	h.AddExcludeIPFunc = fn
}

// SetRemoveExcludeIPFunc 设置 tcp 独立 IP 移除回调
func (h *Handler) SetRemoveExcludeIPFunc(fn func(ip string) error) {
	h.RemoveExcludeIPFunc = fn
}

// SetGetAllExcludesFunc 设置三维度一次读回调
func (h *Handler) SetGetAllExcludesFunc(fn func() ([]string, []string, []string, error)) {
	h.GetAllExcludesFunc = fn
}

// SetReplaceAllExcludesFunc 设置三维度全量替换回调
func (h *Handler) SetReplaceAllExcludesFunc(fn func([]string, []string, []string) error) {
	h.ReplaceAllExcludesFunc = fn
}

// SetRebuildRulesFunc 设置规则重建回调
// Add/Remove 探针排除名单后触发，把变化合并进 RuleSet 并重新签名下发
func (h *Handler) SetRebuildRulesFunc(fn func() error) {
	h.RebuildRulesFunc = fn
}

// SetUpdateAlertStatusFunc 设置告警状态更新回调
func (h *Handler) SetUpdateAlertStatusFunc(fn func([]int64, string) error) {
	h.UpdateAlertStatusFunc = fn
}

// SetListAlertsFunc 设置告警列表回调（PSQL 模式）
func (h *Handler) SetListAlertsFunc(fn func(int) ([]map[string]interface{}, error)) {
	h.ListAlertsFunc = fn
}

// SetAuditCallbacks 设置审计回调（PSQL 模式）
// save: 写一条审计；list: 列审计记录（兼容旧 UI 的 map 格式）
func (h *Handler) SetAuditCallbacks(
	save func(audit.Record) error,
	list func(limit int) ([]map[string]interface{}, error),
) {
	h.SaveAuditFunc = save
	h.ListAuditFunc = list
}

// ============================================================
// Step 2：SQLite 移除迁移 setter
// ============================================================

func (h *Handler) SetListGroupsFunc(fn func() ([]string, error)) {
	h.ListGroupsFunc = fn
}
func (h *Handler) SetCreateGroupFunc(fn func(name string) error) {
	h.CreateGroupFunc = fn
}
func (h *Handler) SetDeleteGroupFunc(fn func(name string) error) {
	h.DeleteGroupFunc = fn
}
func (h *Handler) SetGetAlertStatsFunc(fn func() map[string]interface{}) {
	h.GetAlertStatsFunc = fn
}
func (h *Handler) SetSaveAlertFeedbackFunc(fn func(alertID string, feedback, username string) error) {
	h.SaveAlertFeedbackFunc = fn
}
func (h *Handler) SetSaveFeedbackFeatureFunc(fn func(featureKey string) error) {
	h.SaveFeedbackFeatureFunc = fn
}
func (h *Handler) SetGetFeedbackFeaturesFunc(fn func() ([]string, error)) {
	h.GetFeedbackFeaturesFunc = fn
}
func (h *Handler) SetGetAllLatestAssetsFunc(fn func() (map[string]map[string]int, error)) {
	h.GetAllLatestAssetsFunc = fn
}
func (h *Handler) SetGetProbeConfigsFunc(fn func(agentID string) ([]map[string]interface{}, error)) {
	h.GetProbeConfigsFunc = fn
}
func (h *Handler) SetGetEventsAsRecordsFunc(fn func(limit int, agentID string) ([]map[string]interface{}, error)) {
	h.GetEventsAsRecordsFunc = fn
}
func (h *Handler) SetCleanupFunc(fn func(target, mode string, days int) (int64, error)) {
	h.CleanupFunc = fn
}

// writeAudit 写入一条审计，自动补全环境字段
//
// 设计：
//   - nil-safe：callback 未注入时静默跳过，不 panic
//   - 自动从 context 补 username / ip / user_agent / result / event_type
//   - 失败不阻塞业务，仅打日志
func (h *Handler) writeAudit(c *gin.Context, rec audit.Record) {
	if h.SaveAuditFunc == nil {
		return
	}
	if rec.Username == "" {
		rec.Username = h.getUsername(c)
	}
	if rec.IP == "" {
		rec.IP = c.ClientIP()
	}
	if rec.UserAgent == "" {
		rec.UserAgent = c.Request.UserAgent()
	}
	if rec.Result == "" {
		rec.Result = audit.ResultSuccess
	}
	if rec.EventType == "" {
		rec.EventType = audit.EventConsoleAction
	}
	// 从 context 补 session_id（登录时无，其他接口有）
	if rec.SessionID == nil {
		if sid, ok := c.Get("session_id"); ok {
			if id, ok := sid.(int64); ok && id > 0 {
				rec.SessionID = &id
			}
		}
	}
	if err := h.SaveAuditFunc(rec); err != nil {
		log.Printf("⚠️ 审计写入失败: action=%s user=%s err=%v",
			rec.ActionCode, rec.Username, err)
	}
}

// auditFromCtx 便捷构造：从 context 拿环境字段，业务字段由调用方填
func (h *Handler) auditFromCtx(c *gin.Context, action, actionCode, targetType, targetID, targetName string) audit.Record {
	return audit.Record{
		Username:   h.getUsername(c),
		IP:         c.ClientIP(),
		UserAgent:  c.Request.UserAgent(),
		Action:     action,
		ActionCode: actionCode,
		TargetType: targetType,
		TargetID:   targetID,
		TargetName: targetName,
		Result:     audit.ResultSuccess,
		EventType:  audit.EventConsoleAction,
	}
}

func NewHandler(am *auth.AuthManager, sendCmd func(string, *pb.ProbeCommand) error) *Handler {
	return &Handler{
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
			if h.DeleteAgentFunc != nil {
				if err := h.DeleteAgentFunc(agentID); err != nil {
					log.Printf("⚠️ DB 删除 Agent 失败: %v", err)
					c.JSON(500, gin.H{"error": err.Error()})
					return
				}
			}
			h.Mu.Lock()
			delete(h.Agents, agentID)
			h.Mu.Unlock()
			h.writeAudit(c, audit.Record{
				Action:     "删除主机",
				ActionCode: audit.ActionAgentDelete,
				TargetType: audit.TargetAgent,
				TargetID:   agentID,
				EventRW:    audit.RWWrite,
			})
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
			h.writeAudit(c, audit.Record{
				Action:     "移动主机",
				ActionCode: audit.ActionAgentMove,
				TargetType: audit.TargetAgent,
				TargetID:   fmt.Sprintf("%v", req.AgentIDs),
				Detail:     fmt.Sprintf("%v -> %s", req.AgentIDs, req.Group),
				EventRW:    audit.RWWrite,
			})
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
			if h.ListGroupsFunc != nil {
				groups, _ := h.ListGroupsFunc()
				c.JSON(200, gin.H{"groups": groups})
				return
			}
			c.JSON(200, gin.H{"groups": []interface{}{}})
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
			var createErr error
			if h.CreateGroupFunc != nil {
				createErr = h.CreateGroupFunc(req.Name)
			} else {
				c.JSON(501, gin.H{"error": "分组创建未初始化"})
				return
			}
			if createErr != nil {
				c.JSON(500, gin.H{"error": "创建失败"})
				return
			}
			log.Printf("📋 创建分组: %s", req.Name)
			c.JSON(200, gin.H{"success": true})
		})
		api.DELETE("/groups/:name", h.roleMiddleware("admin"), func(c *gin.Context) {
			name := c.Param("name")
			var delErr error
			if h.DeleteGroupFunc != nil {
				delErr = h.DeleteGroupFunc(name)
			} else {
				c.JSON(501, gin.H{"error": "分组删除未初始化"})
				return
			}
			if delErr != nil {
				c.JSON(500, gin.H{"error": "删除失败"})
				return
			}
			log.Printf("🗑️ 删除分组: %s", name)
			c.JSON(200, gin.H{"success": true})
		})
		api.GET("/assets/category", h.AssetsByCategory)
		api.GET("/probe-exclude-comms", h.rbacMiddleware("probes", "read"), h.ListProbeExcludeComms)
		api.POST("/probe-exclude-comms", h.rbacMiddleware("probes", "write"), h.AddProbeExcludeComms)
		api.DELETE("/probe-exclude-comms/:comm", h.rbacMiddleware("probes", "write"), h.RemoveProbeExcludeComms)

		// 三维度 #11/#12
		api.GET("/probe-exclude-comms-file-access", h.rbacMiddleware("probes", "read"), h.ListFileAccessExcludeComms)
		api.POST("/probe-exclude-comms-file-access", h.rbacMiddleware("probes", "write"), h.AddFileAccessExcludeComms)
		api.DELETE("/probe-exclude-comms-file-access/:comm", h.rbacMiddleware("probes", "write"), h.RemoveFileAccessExcludeComms)
		api.GET("/probe-exclude-ips", h.rbacMiddleware("probes", "read"), h.ListExcludeIPs)
		api.POST("/probe-exclude-ips", h.rbacMiddleware("probes", "write"), h.AddExcludeIP)
		api.DELETE("/probe-exclude-ips", h.rbacMiddleware("probes", "write"), h.RemoveExcludeIP)

		// 统一 Apply（前端一页三维度用）
		api.GET("/probe-exclude/all", h.rbacMiddleware("probes", "read"), h.GetAllExcludes)
		api.POST("/probe-exclude/apply", h.rbacMiddleware("probes", "write"), h.ApplyProbeExclude)

		api.GET("/alerts", func(c *gin.Context) {
			if h.ListAlertsFunc != nil {
				alerts, err := h.ListAlertsFunc(100)
				if err != nil {
					c.JSON(500, gin.H{"error": err.Error()})
					return
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
			if h.GetAlertStatsFunc != nil {
				c.JSON(200, h.GetAlertStatsFunc())
				return
			}
			c.JSON(200, gin.H{})
		})
		api.POST("/alerts/:id/feedback", h.rbacMiddleware("alerts", "write"), func(c *gin.Context) {
			id := c.Param("id")
			var req struct {
				Type string `json:"type"`
			}
			c.BindJSON(&req)
			var fbErr error
			if h.SaveAlertFeedbackFunc != nil {
				fbErr = h.SaveAlertFeedbackFunc(id, req.Type, h.getUsername(c))
			} else {
				c.JSON(501, gin.H{"error": "告警反馈未初始化"})
				return
			}
			if fbErr != nil {
				log.Printf("⚠️ 保存告警反馈失败: %v", fbErr)
			}
			c.JSON(200, gin.H{"success": true})
		})
		api.GET("/users", h.rbacMiddleware("users", "read"), h.ListUsers)
		api.POST("/users", h.rbacMiddleware("users", "write"), h.CreateUser)
		api.PUT("/users", h.rbacMiddleware("users", "write"), h.UpdateUser)
		api.DELETE("/users", h.rbacMiddleware("users", "write"), h.DeleteUser)

		// 审计日志
		api.POST("/logout", h.authMiddleware, func(c *gin.Context) {
			// 撤销会话（JWT 立即失效）
			if sid, ok := c.Get("session_id"); ok {
				if id, ok := sid.(int64); ok {
					if err := h.Auth.RevokeSessionByID(c.Request.Context(), id); err != nil {
						log.Printf("⚠️ 撤销会话失败: %v", err)
					}
				}
			}
			h.writeAudit(c, audit.Record{
				Action:     "注销",
				ActionCode: audit.ActionLogout,
				TargetType: audit.TargetSession,
				Detail:     "退出登录",
				EventRW:    audit.RWWrite,
			})
			c.JSON(200, gin.H{"success": true})
		})

		// 会话管理
		api.POST("/session/keepalive", h.authMiddleware, h.SessionKeepalive)
		api.POST("/session/close", h.authMiddleware, h.SessionClose)
		api.GET("/session/config", h.authMiddleware, h.SessionConfig)
		api.POST("/session/heartbeat", h.authMiddleware, h.SessionHeartbeat)

		api.GET("/logs/export", h.rbacMiddleware("audit", "export"), func(c *gin.Context) {
			var logs []map[string]interface{}
			if h.ListAuditFunc != nil {
				logs, _ = h.ListAuditFunc(10000)
			}
			c.Header("Content-Type", "text/csv")
			c.Header("Content-Disposition", "attachment; filename=audit_logs.csv")
			c.String(200, "id,username,action,detail,ip,created_at\n")
			for _, l := range logs {
				c.String(200, "%v,%s,%s,%s,%s,%v\n",
					l["id"], l["username"], l["action"], l["detail"], l["ip"], l["created_at"])
			}
		})

		api.GET("/logs", h.rbacMiddleware("audit", "read"), func(c *gin.Context) {
			var logs []map[string]interface{}
			if h.ListAuditFunc != nil {
				logs, _ = h.ListAuditFunc(200)
			}
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
			h.writeAudit(c, audit.Record{
				Action:     "访问页面",
				ActionCode: audit.ActionSystemPageVisit,
				TargetType: audit.TargetSystem,
				TargetName: pageName,
				EventType:  audit.EventConsoleAction,
				EventRW:    audit.RWRead,
			})
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
				h.writeAudit(c, audit.Record{
					Action:     "修改系统时间",
					ActionCode: audit.ActionSystemTimeSet,
					TargetType: audit.TargetSystem,
					TargetName: req.Datetime,
					EventRW:    audit.RWWrite,
				})
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
				h.writeAudit(c, audit.Record{
					Action:     "NTP同步",
					ActionCode: audit.ActionSystemNTPSync,
					TargetType: audit.TargetSystem,
					TargetName: req.Server,
					EventRW:    audit.RWWrite,
				})
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
				"event_days": h.GetStringSetting("event_days", "180"),
				"alert_days": h.GetStringSetting("alert_days", "90"),
				"audit_days": h.GetStringSetting("audit_days", "180"),
				"token_days": h.GetStringSetting("token_days", "180"),
			})
		})
		api.POST("/log-settings", h.roleMiddleware("admin"), func(c *gin.Context) {
			var req struct {
				EventDays string `json:"event_days"`
				AlertDays string `json:"alert_days"`
				AuditDays string `json:"audit_days"`
				TokenDays string `json:"token_days"`
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
			if req.TokenDays != "" {
				h.SetStringSetting("token_days", req.TokenDays)
			}
			c.JSON(200, gin.H{"success": true})
		})

		// 数据 / 日志清理（admin only + confirm 二次确认）
		api.POST("/admin/cleanup", h.roleMiddleware("admin"), func(c *gin.Context) {
			var req struct {
				Target  string `json:"target"`
				Mode    string `json:"mode"`
				Days    int    `json:"days"`
				Confirm string `json:"confirm"`
			}
			if err := c.BindJSON(&req); err != nil {
				c.JSON(400, gin.H{"error": "请求格式错误"})
				return
			}

			// 1. target 校验
			validTargets := map[string]bool{
				"events": true, "alerts": true,
				"audit_logs": true, "tokens": true,
			}
			if !validTargets[req.Target] {
				c.JSON(400, gin.H{"error": "无效的 target"})
				return
			}

			// 2. mode 校验
			if req.Mode != "all" && req.Mode != "before_days" {
				c.JSON(400, gin.H{"error": "mode 必须为 all 或 before_days"})
				return
			}
			if req.Mode == "before_days" && req.Days <= 0 {
				c.JSON(400, gin.H{"error": "before_days 模式必须指定正整数 days"})
				return
			}

			// 3. audit_logs 特殊规则（等保）
			if req.Target == "audit_logs" {
				if req.Mode == "all" {
					c.JSON(400, gin.H{"error": "审计日志不允许全清（等保要求）"})
					return
				}
				if req.Days < 180 {
					c.JSON(400, gin.H{"error": "审计日志至少保留 180 天（等保要求）"})
					return
				}
			}

			// 4. confirm 分级
			//    普通清理：CLEANUP
			//    全清（危险）：I_UNDERSTAND_TOTAL_LOSS
			expectedConfirm := "CLEANUP"
			if req.Mode == "all" {
				expectedConfirm = "I_UNDERSTAND_TOTAL_LOSS"
			}
			if req.Confirm != expectedConfirm {
				c.JSON(400, gin.H{
					"error": fmt.Sprintf("二次确认失败：mode=%s 时 confirm 必须为 %s",
						req.Mode, expectedConfirm),
				})
				return
			}

			if h.CleanupFunc == nil {
				c.JSON(501, gin.H{"error": "清理功能未初始化"})
				return
			}

			affected, err := h.CleanupFunc(req.Target, req.Mode, req.Days)
			if err != nil {
				h.writeAudit(c, audit.Record{
					Action:     "数据清理失败",
					ActionCode: "system.data_cleanup",
					TargetType: audit.TargetSystem,
					TargetName: req.Target,
					Detail:     fmt.Sprintf("mode=%s days=%d err=%v", req.Mode, req.Days, err),
					EventRW:    audit.RWWrite,
					Result:     audit.ResultFailure,
				})
				c.JSON(500, gin.H{"error": err.Error()})
				return
			}

			actionCode := "system.data_cleanup"
			if req.Target != "events" {
				actionCode = "system.log_cleanup"
			}
			h.writeAudit(c, audit.Record{
				Action:     "数据清理",
				ActionCode: actionCode,
				TargetType: audit.TargetSystem,
				TargetName: req.Target,
				Detail:     fmt.Sprintf("mode=%s days=%d affected=%d", req.Mode, req.Days, affected),
				EventRW:    audit.RWWrite,
				Result:     audit.ResultSuccess,
			})

			log.Printf("🧹 手动清理: target=%s mode=%s days=%d affected=%d user=%s",
				req.Target, req.Mode, req.Days, affected, h.getUsername(c))
			c.JSON(200, gin.H{
				"success":  true,
				"target":   req.Target,
				"mode":     req.Mode,
				"affected": affected,
			})
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

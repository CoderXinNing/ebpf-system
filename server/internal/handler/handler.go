package handler

import (
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"log"
	"time"

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
	LastSeen     int64             `json:"last_seen"`
	FirstSeen    int64             `json:"first_seen"`
	Framework    *pb.FrameworkInfo `json:"framework"`
	KernelInfo   *pb.KernelInfo    `json:"kernel_info"`
	Commands     []*pb.ProbeCommand `json:"-"`
}

type ProbeEvent struct {
	ID        string `json:"id"`
	AgentID   string `json:"agent_id"`
	ProbeName string `json:"probe_name"`
	Timestamp int64  `json:"timestamp"`
	EventType string `json:"event_type"`
	PID       int32  `json:"pid"`
	Comm      string `json:"comm"`
	Filename  string `json:"filename"`
	Details   string `json:"details,omitempty"`
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

func (h *Handler) SetupRoutes(r *gin.Engine) {
	r.POST("/api/login", h.Login)

	api := r.Group("/api")
	api.Use(h.authMiddleware)
	{
		api.GET("/health", h.Health)
		api.GET("/agents", h.ListAgents)
		api.GET("/events", h.ListEvents)
		api.POST("/move", h.roleMiddleware("admin", "operator"), func(c *gin.Context) {
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
			c.JSON(200, gin.H{"success": true})
		})
		api.POST("/command", h.roleMiddleware("admin", "operator"), h.Command)

		// 探针管理
		api.GET("/probes/config", h.roleMiddleware("admin", "operator"), h.ListProbeConfigs)
		api.POST("/probes/deploy", h.roleMiddleware("admin"), h.DeployProbe)
		api.POST("/probes/destroy", h.roleMiddleware("admin"), h.DestroyProbe)
		api.GET("/assets", h.AssetsOverview)
		api.GET("/assets/:agent_id", h.AssetDetail)
		api.GET("/groups", func(c *gin.Context) {
			h.Mu.RLock()
			defer h.Mu.RUnlock()
			groups := make(map[string]int)
			for _, a := range h.Agents {
				g := a.Group
				if g == "" { g = "默认组" }
				groups[g]++
			}
			c.JSON(200, gin.H{"groups": groups})
		})
		api.GET("/assets/category", h.AssetsByCategory)
		api.GET("/alerts", func(c *gin.Context) {
			alerts, _ := h.Store.GetAlerts(100)
			c.JSON(200, gin.H{"alerts": alerts})
		})
		api.GET("/users", h.roleMiddleware("admin"), h.ListUsers)
	}
}

func (h *Handler) Login(c *gin.Context) {
	var req struct{ Username, Password string }
	c.BindJSON(&req)
	user, err := h.Auth.VerifyPassword(req.Username, req.Password)
	if err != nil {
		c.JSON(401, gin.H{"error": "用户名或密码错误"})
		return
	}
	token, _ := h.Auth.GenerateToken(user)
	c.JSON(200, gin.H{"token": token, "user": user})
}

func (h *Handler) Health(c *gin.Context) {
	h.Mu.RLock()
	defer h.Mu.RUnlock()
	now := time.Now().Unix()
	online := 0
	for _, a := range h.Agents {
		if now-a.LastSeen < 60 {
			online++
		}
	}
	c.JSON(200, gin.H{"status": "ok", "online": online, "total": len(h.Agents)})
}

func (h *Handler) ListAgents(c *gin.Context) {
	h.Mu.RLock()
	defer h.Mu.RUnlock()
	agents := make([]AgentInfo, 0, len(h.Agents))
	for _, a := range h.Agents {
		agents = append(agents, *a)
	}
	c.JSON(200, gin.H{"total": len(agents), "agents": agents})
}

func (h *Handler) ListEvents(c *gin.Context) {
	agentID := c.Query("agent_id")
	limit := 100
	if l := c.Query("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	dbEvents, dbErr := h.Store.GetEvents(limit, agentID)
	if dbErr == nil && len(dbEvents) > 0 {
		c.JSON(200, gin.H{"total": len(dbEvents), "events": dbEvents, "source": "sqlite"})
		return
	}
	h.EventMu.RLock()
	defer h.EventMu.RUnlock()
	evts := h.Events
	if len(evts) > limit {
		evts = evts[len(evts)-limit:]
	}
	c.JSON(200, gin.H{"total": len(h.Events), "events": evts, "source": "memory"})
}
func (h *Handler) Command(c *gin.Context) {
	var req struct {
		AgentID     string `json:"agent_id"`
		ProbeName   string `json:"probe_name"`
		Action      string `json:"action"`
		ProbeData   string `json:"probe_data"`
		ProbeConfig string `json:"probe_config"`
	}
	c.BindJSON(&req)

	var cmdType pb.ProbeCommand_CommandType
	switch req.Action {
	case "load":
		cmdType = pb.ProbeCommand_LOAD
	case "unload":
		cmdType = pb.ProbeCommand_UNLOAD
	case "install":
		cmdType = pb.ProbeCommand_INSTALL
	case "collect":
		cmdType = pb.ProbeCommand_COLLECT
	case "reload":
		cmdType = pb.ProbeCommand_RELOAD
	default:
		c.JSON(400, gin.H{"error": "action无效"})
		return
	}

	cmd := &pb.ProbeCommand{
		Type:        cmdType,
		ProbeName:   req.ProbeName,
		ProbeData:   []byte(req.ProbeData),
		ProbeConfig: req.ProbeConfig,
	}
	if err := h.sendCmd(req.AgentID, cmd); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	log.Printf("📋 指令: %s -> %s (%s)", req.AgentID, req.ProbeName, req.Action)
	c.JSON(200, gin.H{"success": true, "message": "指令已排队"})
}

func (h *Handler) AssetsOverview(c *gin.Context) {
	data, err := h.Store.GetAllLatestAssets()
	if err != nil {
		c.JSON(500, gin.H{"error": "查询失败"})
		return
	}
	type AssetSummary struct {
		AgentID      string `json:"agent_id"`
		Hostname     string `json:"hostname"`
		OS           string `json:"os"`
		ProcessCount int    `json:"process_count"`
		UserCount    int    `json:"user_count"`
		Online       bool    `json:"online"`
		CPUPercent   float64 `json:"cpu_percent"`
		MemPercent   float64 `json:"mem_percent"`
		DiskPercent  float64 `json:"disk_percent"`
	}
	summaries := make([]AssetSummary, 0, len(data))
	now := time.Now().Unix()
	for agentID, counts := range data {
		h.Mu.RLock()
		agent := h.Agents[agentID]
		h.Mu.RUnlock()
		hostname := ""
		online := false
		if agent != nil {
			hostname = agent.Hostname
			if now-agent.LastSeen < 60 {
				online = true
			}
		}
		var cpuP, memP, diskP float64
			if _, _, sysJSON, err := h.Store.GetLatestAsset(agentID); err == nil {
				var sysData map[string]interface{}
				json.Unmarshal(sysJSON, &sysData)
				if perf, ok := sysData["perf"].(map[string]interface{}); ok {
					if v, ok := perf["cpu_percent"].(float64); ok { cpuP = v }
					if v, ok := perf["mem_percent"].(float64); ok { memP = v }
					if du, ok := perf["disk_usage"].([]interface{}); ok && len(du) > 0 {
						if dm, ok := du[0].(map[string]interface{}); ok {
							if p, ok := dm["percent"].(string); ok {
								p = strings.TrimSuffix(p, "%")
								if f, err := strconv.ParseFloat(p, 64); err == nil { diskP = f }
							}
						}
					}
				}
			}
			summaries = append(summaries, AssetSummary{
				OS:           h.getOS(agentID),
			AgentID:      agentID,
			Hostname:     hostname,
			ProcessCount: counts["process_count"],
			UserCount:    counts["user_count"],
			Online:       online,
				CPUPercent:   cpuP,
				MemPercent:   memP,
				DiskPercent:  diskP,
		})
	}
	c.JSON(200, gin.H{"agents": summaries})
}

func (h *Handler) AssetDetail(c *gin.Context) {
	agentID := c.Param("agent_id")
	procJSON, userJSON, sysJSON, err := h.Store.GetLatestAsset(agentID)
	if err != nil {
		c.JSON(404, gin.H{"error": "无资产数据"})
		return
	}
	var procs, users, sys interface{}
	json.Unmarshal(procJSON, &procs)
	json.Unmarshal(userJSON, &users)
	json.Unmarshal(sysJSON, &sys)
	c.JSON(200, gin.H{"processes": procs, "users": users, "system": sys})
}

func (h *Handler) AssetsByCategory(c *gin.Context) {
	category := c.Query("type") // 数据库/Web服务器/中间件/运行时/Web组件/所有
	agentID := c.Query("agent_id")

	// 遍历所有Agent的资产，按类型筛选
	type AssetItem struct {
		AgentID     string `json:"agent_id"`
		Hostname    string `json:"hostname"`
		ServiceName string `json:"service_name"`
		Type        string   `json:"type"`
		Version     string `json:"version"`
	Group       string            `json:"group"`
		PID         int32  `json:"pid"`
		ListenPort  []string `json:"listen_port"`
		ExePath     string `json:"exe_path"`
		ConfigPath  string `json:"config_path"`
	}

	var items []AssetItem
	h.Mu.RLock()
	defer h.Mu.RUnlock()

	for aid, agent := range h.Agents {
		if agentID != "" && aid != agentID {
			continue
		}

		// 从store获取该Agent最新资产的services
		_, _, sysJSON, err := h.Store.GetLatestAsset(aid)
		if err != nil {
			continue
		}

		var sysData map[string]interface{}
		json.Unmarshal(sysJSON, &sysData)

		// 解析识别的服务
		if svcs, ok := sysData["services"].([]interface{}); ok {
			for _, svc := range svcs {
				s := svc.(map[string]interface{})
				svcType := getString(s, "type")
				if category != "" && category != "所有" && svcType != category {
					continue
				}
				ports := []string{}
				if p, ok := s["listen_port"].([]interface{}); ok {
					for _, pp := range p {
						ports = append(ports, pp.(string))
					}
				}
				items = append(items, AssetItem{
					Type:        svcType,
					AgentID:     aid,
					Hostname:    agent.Hostname,
					ServiceName: s["name"].(string),
					Version:     getString(s, "version"),
					PID:         int32(getFloat(s, "pid")),
					ListenPort:  ports,
					ExePath:     getString(s, "exe_path"),
					ConfigPath:  getString(s, "config_path"),
				})
			}
		}

		// 解析Web组件
		if wcs, ok := sysData["web_components"].([]interface{}); ok {
			for _, wc := range wcs {
				w := wc.(map[string]interface{})
				wcType := getString(w, "type")
				if category != "" && category != "所有" && wcType != category {
					continue
				}
				items = append(items, AssetItem{
					Type:        wcType,
					AgentID:     aid,
					Hostname:    agent.Hostname,
					ServiceName: w["name"].(string),
					Version:     getString(w, "version"),
					PID:         int32(getFloat(w, "pid")),
					ExePath:     getString(w, "base_path"),
					ConfigPath:  getString(w, "config_path"),
				})
			}
		}
	}

	c.JSON(200, gin.H{"total": len(items), "items": items})
}

func (h *Handler) getOS(agentID string) string {
	_, _, sysJSON, err := h.Store.GetLatestAsset(agentID)
	if err != nil { return "-" }
	var sysData map[string]interface{}
	json.Unmarshal(sysJSON, &sysData)
	if s, ok := sysData["system"].(map[string]interface{}); ok {
		if os, ok := s["os"].(map[string]interface{}); ok {
			if name, ok := os["name"].(string); ok { return name }
		}
	}
	return "-"
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok && v != nil {
		return v.(string)
	}
	return ""
}

func getFloat(m map[string]interface{}, key string) float64 {
	if v, ok := m[key]; ok && v != nil {
		if f, ok := v.(float64); ok {
			return f
		}
	}
	return 0
}

func (h *Handler) ListUsers(c *gin.Context) {
	users, _ := h.Auth.ListUsers()
	c.JSON(200, gin.H{"users": users})
}

func (h *Handler) authMiddleware(c *gin.Context) {
	header := c.GetHeader("Authorization")
	if header == "" || len(header) < 8 {
		c.JSON(401, gin.H{"error": "未登录"})
		c.Abort()
		return
	}
	user, err := h.Auth.ValidateToken(header[7:])
	if err != nil {
		c.JSON(401, gin.H{"error": "token无效"})
		c.Abort()
		return
	}
	c.Set("user", user)
	c.Next()
}

func (h *Handler) roleMiddleware(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		u := c.MustGet("user").(*auth.User)
		for _, r := range roles {
			if u.Role == r {
				c.Next()
				return
			}
		}
		c.JSON(403, gin.H{"error": "权限不足"})
		c.Abort()
	}
}

// ListProbeConfigs 查询探针配置
func (h *Handler) ListProbeConfigs(c *gin.Context) {
	agentID := c.Query("agent_id")
	if agentID == "" {
		c.JSON(400, gin.H{"error": "缺少agent_id"})
		return
	}
	configs, err := h.Store.GetProbeConfigs(agentID)
	if err != nil {
		c.JSON(500, gin.H{"error": "查询失败"})
		return
	}
	c.JSON(200, gin.H{"configs": configs})
}

// DeployProbe 下发/更新探针配置
func (h *Handler) DeployProbe(c *gin.Context) {
	var req struct {
		AgentID   string `json:"agent_id"`
		ProbeName string `json:"probe_name"`
		Enabled   bool   `json:"enabled"`
		Remove    bool   `json:"remove"`
		Path      string `json:"path"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	if req.AgentID == "" || req.ProbeName == "" {
		c.JSON(400, gin.H{"error": "agent_id和probe_name必填"})
		return
	}
	if req.Path == "" {
		// 默认路径
		paths := map[string]string{
			"exec_monitor": "probes/templates/exec_monitor_ebpf/exec_monitor.o",
			"bash_monitor": "probes/templates/bash_monitor/bash_monitor.o",
			"tcp_monitor":  "probes/templates/tcp_monitor/tcp_monitor.o",
		}
		req.Path = paths[req.ProbeName]
	}

	err := h.Store.UpsertProbeConfig(store.ProbeConfigRecord{
		AgentID:   req.AgentID,
		ProbeName: req.ProbeName,
		Enabled:   req.Enabled,
		Remove:    req.Remove,
		Path:      req.Path,
	})
	if err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	log.Printf("📋 探针下发: %s -> %s (enabled=%v)", req.AgentID, req.ProbeName, req.Enabled)
	c.JSON(200, gin.H{"success": true, "message": "已下发"})
}

// DestroyProbe 销毁探针配置
func (h *Handler) DestroyProbe(c *gin.Context) {
	var req struct {
		AgentID   string `json:"agent_id"`
		ProbeName string `json:"probe_name"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	if err := h.Store.DeleteProbeConfig(req.AgentID, req.ProbeName); err != nil {
		c.JSON(500, gin.H{"error": "删除失败"})
		return
	}
	log.Printf("🗑️ 探针销毁: %s -> %s", req.AgentID, req.ProbeName)
	c.JSON(200, gin.H{"success": true, "message": "已销毁"})
}

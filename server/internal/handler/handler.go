package handler

import (
	"encoding/json"
	"sync"
	"log"
	"time"

	"github.com/CoderXinNing/ebpf-system/proto/pb"
	"github.com/CoderXinNing/ebpf-system/server/internal/auth"
	"github.com/CoderXinNing/ebpf-system/server/internal/store"
	"github.com/gin-gonic/gin"
)

type Handler struct {
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
}

func NewHandler(st *store.Store, am *auth.AuthManager, sendCmd func(string, *pb.ProbeCommand) error) *Handler {
	return &Handler{
		Store:   st,
		Auth:    am,
		Agents:  make(map[string]*AgentInfo),
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
		api.POST("/command", h.roleMiddleware("admin", "operator"), h.Command)
		api.GET("/assets", h.AssetsOverview)
		api.GET("/assets/:agent_id", h.AssetDetail)
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
	h.EventMu.RLock()
	defer h.EventMu.RUnlock()
	events := h.Events
	if len(events) > 100 {
		events = events[len(events)-100:]
	}
	c.JSON(200, gin.H{"total": len(h.Events), "events": events})
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
		ProcessCount int    `json:"process_count"`
		UserCount    int    `json:"user_count"`
		Online       bool   `json:"online"`
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
		summaries = append(summaries, AssetSummary{
			AgentID:      agentID,
			Hostname:     hostname,
			ProcessCount: counts["process_count"],
			UserCount:    counts["user_count"],
			Online:       online,
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

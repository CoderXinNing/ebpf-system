package main

import (
	"crypto/rand"
	"context"
	"encoding/json"
	"fmt"
	"encoding/hex"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/CoderXinNing/ebpf-system/proto/pb"
	"github.com/CoderXinNing/ebpf-system/server/internal/auth"
	"github.com/CoderXinNing/ebpf-system/server/internal/store"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
)

// ====== 数据结构 ======

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

type Server struct {
	pb.UnimplementedSentinelServer
	mu        sync.RWMutex
	agents    map[string]*AgentInfo
	events    []ProbeEvent
	eventMu   sync.RWMutex
	store     *store.Store
	auth      *auth.AuthManager
}

func NewServer(am *auth.AuthManager, s *store.Store) *Server {
	return &Server{
		agents: make(map[string]*AgentInfo),
		events: make([]ProbeEvent, 0, 10000),
		store:  s,
		auth:   am,
	}
}

func genToken() string { b := make([]byte, 16); rand.Read(b); return hex.EncodeToString(b) }

// ====== gRPC ======

func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	if old, ok := s.agents[req.AgentId]; ok {
		old.IPAddr = req.IpAddress; old.LastSeen = now
		if req.Framework != nil { old.Framework = req.Framework }
		if req.KernelInfo != nil { old.KernelInfo = req.KernelInfo }
		return &pb.RegisterResponse{Success: true, Message: "已更新", AgentToken: old.Token}, nil
	}
	tk := genToken()
	s.agents[req.AgentId] = &AgentInfo{
		ID: req.AgentId, Hostname: req.Hostname, IPAddr: req.IpAddress,
		Token: tk, FirstSeen: now, LastSeen: now,
		Framework: req.Framework, KernelInfo: req.KernelInfo,
		Commands: make([]*pb.ProbeCommand, 0),
	}
	log.Printf("✅ Agent注册: %s (%s)", req.Hostname, req.IpAddress)
	return &pb.RegisterResponse{Success: true, Message: "注册成功", AgentToken: tk}, nil
}

func (s *Server) Heartbeat(stream pb.Sentinel_HeartbeatServer) error {
	req, _ := stream.Recv()
	s.mu.Lock()
	agent, ok := s.agents[req.AgentId]
	if !ok || agent.Token != req.AgentToken {
		s.mu.Unlock()
		stream.Send(&pb.HeartbeatResponse{Success: false})
		return nil
	}
	agent.LastSeen = req.Timestamp
	agent.ActiveProbes = req.ActiveProbes
	agentID := req.AgentId
	s.mu.Unlock()
	stream.Send(&pb.HeartbeatResponse{Success: true})

	go func() {
		for {
			_, err := stream.Recv()
			if err == nil {
				s.mu.Lock()
				agent.LastSeen = time.Now().Unix()
				s.mu.Unlock()
			}
			if err != nil { return }
		}
	}()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		cmds := agent.Commands
		agent.Commands = make([]*pb.ProbeCommand, 0)
		s.mu.Unlock()
		if len(cmds) > 0 {
			stream.Send(&pb.HeartbeatResponse{Success: true, Commands: cmds})
			log.Printf("DEBUG Server: Send完成, cmds=%d条", len(cmds))
			log.Printf("DEBUG Server: Send完成, cmds=%d条", len(cmds))
			log.Printf("📤 下发: %s (%d条)", agentID, len(cmds))
		}
	}
	return nil
}

func (s *Server) ReportAssets(ctx context.Context, req *pb.AssetReport) (*pb.HeartbeatResponse, error) {
	// 转JSON存数据库
	procJSON, _ := json.Marshal(req.Processes)
	userJSON, _ := json.Marshal(req.Users)
	if err := s.store.SaveAsset(req.AgentId, procJSON, userJSON); err != nil {
		log.Printf("⚠️ 资产存库失败: %v", err)
	}
	log.Printf("📊 收到资产: %s (%d进程, %d用户)", req.AgentId, len(req.Processes), len(req.Users))
	return &pb.HeartbeatResponse{Success: true}, nil
}

func (s *Server) ReportEvents(ctx context.Context, req *pb.EventReport) (*pb.HeartbeatResponse, error) {
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	for _, evt := range req.Events {
		b := make([]byte, 8); rand.Read(b)
		s.events = append(s.events, ProbeEvent{
			ID: hex.EncodeToString(b), AgentID: req.AgentId, ProbeName: evt.ProbeName,
			Timestamp: evt.Timestamp, EventType: evt.EventType,
			PID: evt.Pid, Comm: evt.Comm, Filename: evt.Filename,
		})
		if len(s.events) > 10000 { s.events = s.events[len(s.events)-1000:] }
	}
	return &pb.HeartbeatResponse{Success: true}, nil
}

func (s *Server) sendCommand(agentID string, cmd *pb.ProbeCommand) error {
	log.Printf("DEBUG: sendCommand agentID=%q, agents数=%d", agentID, len(s.agents))
	s.mu.Lock(); defer s.mu.Unlock()
	agent, ok := s.agents[agentID]
	if !ok { return fmt.Errorf("Agent不存在") }
	agent.Commands = append(agent.Commands, cmd)
	return nil
}

// ====== 中间件 ======

func (s *Server) authMiddleware(c *gin.Context) {
	h := c.GetHeader("Authorization")
	if h == "" || !strings.HasPrefix(h, "Bearer ") { c.JSON(401, gin.H{"error": "未登录"}); c.Abort(); return }
	user, err := s.auth.ValidateToken(h[7:])
	if err != nil { c.JSON(401, gin.H{"error": "token无效"}); c.Abort(); return }
	c.Set("user", user)
	c.Next()
}

func (s *Server) roleMiddleware(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		u := c.MustGet("user").(*auth.User)
		for _, r := range roles { if u.Role == r { c.Next(); return } }
		c.JSON(403, gin.H{"error": "权限不足"}); c.Abort()
	}
}

// ====== HTTP路由 ======

func (s *Server) setupRoutes(r *gin.Engine) {
	r.POST("/api/login", func(c *gin.Context) {
		var req struct{ Username, Password string }
		c.BindJSON(&req)
		user, err := s.auth.VerifyPassword(req.Username, req.Password)
		if err != nil { c.JSON(401, gin.H{"error": "用户名或密码错误"}); return }
		token, _ := s.auth.GenerateToken(user)
		c.JSON(200, gin.H{"token": token, "user": user})
	})

	api := r.Group("/api")
	api.Use(s.authMiddleware)
	{
		api.GET("/health", func(c *gin.Context) {
			s.mu.RLock(); defer s.mu.RUnlock()
			now := time.Now().Unix(); online := 0
			for _, a := range s.agents { if now-a.LastSeen < 30 { online++ } }
			c.JSON(200, gin.H{"status": "ok", "online": online, "total": len(s.agents)})
		})

		api.GET("/agents", func(c *gin.Context) {
			s.mu.RLock(); defer s.mu.RUnlock()
			agents := make([]AgentInfo, 0, len(s.agents))
			for _, a := range s.agents { agents = append(agents, *a) }
			c.JSON(200, gin.H{"total": len(agents), "agents": agents})
		})

		api.GET("/events", func(c *gin.Context) {
			s.eventMu.RLock(); defer s.eventMu.RUnlock()
			events := s.events
			if len(events) > 100 { events = events[len(events)-100:] }
			c.JSON(200, gin.H{"total": len(s.events), "events": events})
		})

		api.POST("/command", s.roleMiddleware("admin", "operator"), func(c *gin.Context) {
			var req struct {
				AgentID string `json:"agent_id"`; ProbeName string `json:"probe_name"`; Action string `json:"action"`; ProbeData string `json:"probe_data"`; ProbeConfig string `json:"probe_config"`
			}
			c.BindJSON(&req)

			var cmdType pb.ProbeCommand_CommandType
			switch req.Action {
			case "load": cmdType = pb.ProbeCommand_LOAD
			case "unload": cmdType = pb.ProbeCommand_UNLOAD
			case "install": cmdType = pb.ProbeCommand_INSTALL
			case "reload": cmdType = pb.ProbeCommand_RELOAD
			default: c.JSON(400, gin.H{"error": "action无效"}); return
			}

			cmd := &pb.ProbeCommand{
				Type: cmdType, ProbeName: req.ProbeName,
				ProbeData: []byte(req.ProbeData), ProbeConfig: req.ProbeConfig,
			}
			if err := s.sendCommand(req.AgentID, cmd); err != nil {
				c.JSON(400, gin.H{"error": err.Error()}); return
			}
			log.Printf("📋 指令: %s -> %s (%s)", req.AgentID, req.ProbeName, req.Action)
			c.JSON(200, gin.H{"success": true, "message": "指令已排队"})
		})

		api.GET("/assets", func(c *gin.Context) {
			data, err := s.store.GetAllLatestAssets()
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
				s.mu.RLock()
				agent := s.agents[agentID]
				s.mu.RUnlock()
				hostname := ""
				online := false
				if agent != nil {
					hostname = agent.Hostname
					if now-agent.LastSeen < 60 { online = true }
				}
				summaries = append(summaries, AssetSummary{
					AgentID: agentID, Hostname: hostname,
					ProcessCount: counts["process_count"], UserCount: counts["user_count"], Online: online,
				})
			}
			c.JSON(200, gin.H{"agents": summaries})
		})
		api.GET("/assets/:agent_id", func(c *gin.Context) {
			agentID := c.Param("agent_id")
			procJSON, userJSON, err := s.store.GetLatestAsset(agentID)
			if err != nil {
				c.JSON(404, gin.H{"error": "无资产数据"})
				return
			}
			var procs interface{}
			var users interface{}
			json.Unmarshal(procJSON, &procs)
			json.Unmarshal(userJSON, &users)
			c.JSON(200, gin.H{"processes": procs, "users": users})
		})
		api.GET("/users", s.roleMiddleware("admin"), func(c *gin.Context) {
			users, _ := s.auth.ListUsers()
			c.JSON(200, gin.H{"users": users})
		})
	}
}

// ====== main ======

func main() {
	store, err := store.NewStore("sentinel.db")
	if err != nil { log.Fatalf("数据库初始化失败: %v", err) }
	defer store.Close()

	am, err := auth.NewAuthManager(store.DB())
	if err != nil { log.Fatalf("auth初始化失败: %v", err) }

	server := NewServer(am, store)
	// gRPC
	lis, _ := net.Listen("tcp", ":50051")
	grpcServer := grpc.NewServer()
	pb.RegisterSentinelServer(grpcServer, server)
	go func() { log.Println("🛡️  gRPC :50051"); grpcServer.Serve(lis) }()

	// HTTP
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if c.Request.Method == "OPTIONS" { c.AbortWithStatus(204); return }
		c.Next()
	})
	server.setupRoutes(r)

	log.Println("🌐 HTTP API :8080")
	log.Println("   账户: admin/admin123  operator/operator123")
	r.Run(":8080")
}

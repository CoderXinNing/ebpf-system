package main

import (
	"crypto/rand"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/CoderXinNing/ebpf-system/proto/pb"
	"github.com/CoderXinNing/ebpf-system/server/internal/auth"
	"github.com/CoderXinNing/ebpf-system/server/internal/handler"
	"github.com/CoderXinNing/ebpf-system/server/internal/alert"
	"github.com/CoderXinNing/ebpf-system/server/internal/udp"
	"github.com/CoderXinNing/ebpf-system/server/internal/ws"
	"github.com/CoderXinNing/ebpf-system/server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/BurntSushi/toml"
	"google.golang.org/grpc"
)

type Server struct {
	pb.UnimplementedSentinelServer
	handler *handler.Handler
}

var alertEngine *alert.Engine
var correlationEngine *alert.CorrelationEngine
// baselineEngine 已下沉到 Agent 本地
type ServerConfig struct {
	Server   struct {
		HTTPPort  int    `toml:"http_port"`
		GRPCPort  int    `toml:"grpc_port"`
		JWTSecret string `toml:"jwt_secret"`
	} `toml:"server"`
	Database struct {
		Path string `toml:"path"`
	} `toml:"database"`
}

func main() {
	// 加载配置
	cfg := loadConfig("server/configs/server.toml")
	dbPath := "sentinel.db"
	if cfg != nil {
		dbPath = cfg.Database.Path
	}

	st, err := store.NewStore(dbPath)
	if err != nil {
		log.Fatalf("数据库初始化失败: %v", err)
	}
	defer st.Close()
	st.InitAlertTable()
	st.InitEventTable()

	am, err := auth.NewAuthManager(st.DB())
	if err != nil {
		log.Fatalf("auth初始化失败: %v", err)
	}

	srv := &Server{}
	correlationEngine = alert.NewCorrelationEngine("server/configs/correlation.toml")

	// Server 端不再做软基线计算，由 Agent 本地完成

	// 启动关联引擎清理（每分钟）
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			correlationEngine.Cleanup()
		}
	}()

	alertEngine = alert.NewEngine("server/configs/rules.toml", func(a alert.Alert) {
		log.Printf("🚨 告警: [%s] %s - PID=%d %s", a.Severity, a.RuleName, a.PID, a.Comm)
		// 从 details 提取执行用户
		alertUser := a.Comm
		if idx := strings.Index(a.Details, ":"); idx > 0 && idx < 30 {
			alertUser = strings.TrimSpace(a.Details[:idx])
		}
		st.SaveAlert(store.AlertRecord{
			RuleName: a.RuleName, Severity: a.Severity, Description: a.Description,
			AgentID: a.AgentID, PID: a.PID, Comm: alertUser, Filename: a.Filename,
			Details: a.Details,
		})
	})
	srv.handler = handler.NewHandler(st, am, srv.sendCommand)

	// 从 SQLite 恢复已注册的 Agent
	restoredAgents, _ := st.GetRegisteredAgents()
	for _, ra := range restoredAgents {
		srv.handler.Agents[ra["agent_id"].(string)] = &handler.AgentInfo{
			ID:        ra["agent_id"].(string),
			Hostname:  ra["hostname"].(string),
			IPAddr:    ra["ip_addr"].(string),
			Version:   ra["version"].(string),
			Group:     ra["group"].(string),
			Token:     ra["token"].(string),
			FirstSeen: ra["first_seen"].(int64),
			LastSeen:  ra["last_seen"].(int64),
			Commands:  make([]*pb.ProbeCommand, 0),
		}
	}
	if len(restoredAgents) > 0 {
		log.Printf("📥 从数据库恢复 %d 个 Agent 注册信息", len(restoredAgents))
	}

	// Agent 离线检测（每 15 秒）
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now().Unix()
			srv.handler.Mu.RLock()
			for id, agent := range srv.handler.Agents {
				if agent.LastSeen > 0 && now-agent.LastSeen > 15 {
					ws.Broadcast("agent_offline", map[string]string{
						"agent_id": id,
						"hostname": agent.Hostname,
					})
					log.Printf("🔴 Agent离线: %s (%.0fs无心跳)", agent.Hostname, float64(now-agent.LastSeen))
				}
			}
			srv.handler.Mu.RUnlock()
		}
	}()

	// 启动日志定时清理（每小时）
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			st.CleanExpiredLogs()
		}
	}()

	// gRPC
	lis, _ := net.Listen("tcp", ":50051")
	grpcServer := grpc.NewServer()
	pb.RegisterSentinelServer(grpcServer, srv)
	go func() {
		log.Println("🛡️  gRPC :50051")
		grpcServer.Serve(lis)
	}()

	// HTTP
	gin.SetMode(gin.ReleaseMode)
	// 启动UDP接收端
	_ = udp.NewUDPServer(9999, func(evt udp.UDPEvent) {
		// 收到eBPF事件
	})
	r := gin.Default()
	r.StaticFile("/install.sh", "./server/static/install.sh")
	r.Static("/bin", "./server/static")
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})
	srv.handler.SetupRoutes(r)
	r.GET("/ws", func(c *gin.Context) {
		ws.HandleWS(c.Writer, c.Request)
	})

	log.Println("🌐 HTTP API :8080")
	log.Println("   账户: admin/admin123  operator/operator123")
	r.Run(":8080")
}

func (s *Server) sendCommand(agentID string, cmd *pb.ProbeCommand) error {
	agent := s.handler.Agents[agentID]
	if agent == nil {
		return fmt.Errorf("Agent不存在")
	}
	agent.Commands = append(agent.Commands, cmd)
	return nil
}

// gRPC handlers
func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	now := time.Now().Unix()
	h := s.handler
	h.Mu.Lock()
	defer h.Mu.Unlock()

	if old, ok := h.Agents[req.AgentId]; ok {
		old.IPAddr = req.IpAddress
		old.LastSeen = now
		if req.Framework != nil {
			old.Framework = req.Framework
		}
		if req.KernelInfo != nil {
			old.KernelInfo = req.KernelInfo
		}
		return &pb.RegisterResponse{Success: true, Message: "已更新", AgentToken: old.Token}, nil
	}

	tk := genToken()
	h.Agents[req.AgentId] = &handler.AgentInfo{
		ID: req.AgentId, Hostname: req.Hostname, IPAddr: req.IpAddress,
		Version:     req.AgentVersion,
		Group:       getGroup(req.AgentGroup),
		Token: tk, FirstSeen: now, LastSeen: now,
		Framework: req.Framework, KernelInfo: req.KernelInfo,
		Commands: make([]*pb.ProbeCommand, 0),
	}
	// 持久化到 SQLite
	s.handler.Store.SaveAgent(req.AgentId, req.Hostname, req.IpAddress,
		req.AgentVersion, getGroup(req.AgentGroup), tk, now, now)
	log.Printf("✅ Agent注册: %s (%s)", req.Hostname, req.IpAddress)
	return &pb.RegisterResponse{Success: true, Message: "注册成功", AgentToken: tk}, nil
}

func (s *Server) Heartbeat(stream pb.Sentinel_HeartbeatServer) error {
	req, err := stream.Recv()
	if err != nil || req == nil {
		return nil
	}
	h := s.handler
	h.Mu.Lock()
	agent, ok := h.Agents[req.AgentId]
	if agent == nil {
		h.Mu.Unlock()
		stream.Send(&pb.HeartbeatResponse{Success: false})
		return nil
	}
	if !ok || agent == nil {
		h.Mu.Unlock()
		stream.Send(&pb.HeartbeatResponse{Success: false})
		return nil
	}
	if !ok || agent.Token != req.AgentToken {
		h.Mu.Unlock()
		stream.Send(&pb.HeartbeatResponse{Success: false})
		return nil
	}
	agent.LastSeen = req.Timestamp
	agent.ActiveProbes = req.ActiveProbes
	agent.ProbeDetails = req.ProbeDetails
	agent.BaselineState = req.BaselineState
	agent.BaselineRemaining = req.BaselineRemaining
	agentID := req.AgentId
	h.Mu.Unlock()
	stream.Send(&pb.HeartbeatResponse{Success: true})

	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				return
			}
			h.Mu.Lock()
			if a, ok := h.Agents[req.AgentId]; ok {
				a.LastSeen = req.Timestamp
				a.ActiveProbes = req.ActiveProbes
				a.ProbeDetails = req.ProbeDetails
				a.BaselineState = req.BaselineState
				a.BaselineRemaining = req.BaselineRemaining
			}
			h.Mu.Unlock()
		}
	}()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		h.Mu.Lock()
		cmds := agent.Commands
		agent.Commands = make([]*pb.ProbeCommand, 0)
		h.Mu.Unlock()
		if len(cmds) > 0 {
			stream.Send(&pb.HeartbeatResponse{Success: true, Commands: cmds})
			log.Printf("📤 下发: %s (%d条)", agentID, len(cmds))
		}
	}
	return nil
}

func (s *Server) ReportEvents(ctx context.Context, req *pb.EventReport) (*pb.HeartbeatResponse, error) {
	// 获取该 Agent 的 IP
	ip := ""
	if agent, ok := s.handler.Agents[req.AgentId]; ok {
		ip = agent.IPAddr
	}

	for _, evt := range req.Events {
		// 软基线异常事件直接写告警
		if evt.EventType == "baseline_anomaly" {
			desc := fmt.Sprintf("%s 基线异常: %s %s", evt.Comm, evt.Filename, evt.Details)
			s.handler.Store.SaveAlert(store.AlertRecord{
				RuleName:    "软基线异常检测",
				Severity:    "HIGH",
				Description: desc,
				AgentID:     req.AgentId,
				PID:         evt.Pid,
				Comm:        evt.Comm,
				Filename:    evt.Filename,
				Details:     desc,
				Source:      "baseline",
			})
			log.Printf("🚨 软基线告警入库: %s", desc)
			continue
		}

		// 硬规则引擎
		alertEngine.CheckEvent(req.AgentId, evt.Pid, evt.Comm, evt.Details, evt.Filename, evt.EventType)

		// 上下文关联（按 IP + PID）
		if ip != "" {
			chain := correlationEngine.AddEvent(ip, uint32(evt.Pid), 0, evt.EventType, evt.Comm, evt.Details)
			correlationEngine.CheckCorrelation(chain)
		}

		// 软基线由 Agent 本地计算，Server 不做统计
	}
	h := s.handler
	h.EventMu.Lock()
	defer h.EventMu.Unlock()
	for _, evt := range req.Events {
		b := make([]byte, 8)
		rand.Read(b)
		evtRecord := handler.ProbeEvent{
			ID:        hex.EncodeToString(b),
			AgentID:   req.AgentId,
			ProbeName: evt.ProbeName,
			Timestamp: evt.Timestamp,
			EventType: evt.EventType,
			PID:       evt.Pid,
			Comm:      evt.Comm,
			Filename:  evt.Filename,
			Details:   evt.Details,
		}
		h.Events = append(h.Events, evtRecord)
		ws.Broadcast("event", evtRecord)
		s.handler.Store.SaveEvent(store.EventRecord{
				AgentID:   req.AgentId,
				ProbeName: evt.ProbeName,
				Timestamp: evt.Timestamp,
				EventType: evt.EventType,
				PID:       evt.Pid,
				Comm:      evt.Comm,
				Filename:  evt.Filename,
				Details:   evt.Details,
			})
		if len(h.Events) > 10000 {
			h.Events = h.Events[len(h.Events)-1000:]
		}
		ws.Broadcast("event", evtRecord)
	}
	return &pb.HeartbeatResponse{Success: true}, nil
}

func (s *Server) ReportAssets(ctx context.Context, req *pb.AssetReport) (*pb.HeartbeatResponse, error) {
	procJSON, _ := json.Marshal(req.Processes)
	userJSON, _ := json.Marshal(req.Users)
	sysData := map[string]interface{}{
		"system":          req.System,
		"crons":           req.Crons,
		"packages":        req.Packages,
		"services":        req.Services,
		"web_components":  req.WebComponents,
		"hardware":        req.Hardware,
		"kernel_modules":  req.KernelModules,
		"env_variables":   req.EnvVariables,
		"disk_usages":     req.DiskUsages,
		"network_details": req.NetworkDetails,
		"gateway_dns":     req.GatewayDns,
		"service_status":  req.ServiceStatus,
		"jar_packages":    req.JarPackages,
		"python_packages": req.PythonPackages,
		"npm_packages":    req.NpmPackages,
		"agent_self":      req.AgentSelf,
		"perf":           req.Perf,
	}
	sysJSON, _ := json.Marshal(sysData)
	s.handler.Store.SaveAsset(req.AgentId, procJSON, userJSON, sysJSON)
	log.Printf("📊 收到资产: %s (%d进程, %d用户)", req.AgentId, len(req.Processes), len(req.Users))
	return &pb.HeartbeatResponse{Success: true}, nil
}

func genToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func getGroup(g string) string {
    if g == "" { return "未分组" }
    return g
}

func loadConfig(path string) *ServerConfig {
	var cfg ServerConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		log.Printf("⚠️ 配置文件读取失败，使用默认配置: %v", err)
		return nil
	}
	return &cfg
}


// probeLists 内存探针名单（agent_id -> 探针列表）
var probeLists = map[string][]*pb.ProbeInfo{
	// 默认所有主机都加载这三个探针
	// 后续可以通过管理接口动态调整
}

func (s *Server) GetProbeList(ctx context.Context, req *pb.ProbeListRequest) (*pb.ProbeListResponse, error) {
	// 验证 token
	h := s.handler
	h.Mu.RLock()
	agent, ok := h.Agents[req.AgentId]
	h.Mu.RUnlock()
	if !ok || agent.Token != req.AgentToken {
		return &pb.ProbeListResponse{Success: false, Message: "认证失败"}, nil
	}

	// 从 SQLite 查名单
	configs, err := s.handler.Store.GetProbeConfigs(req.AgentId)
	if err != nil {
		return &pb.ProbeListResponse{Success: false, Message: "查询失败"}, nil
	}

	// 如果没有配置，返回默认名单
	if len(configs) == 0 {
		configs = []store.ProbeConfigRecord{
			{AgentID: req.AgentId, ProbeName: "exec_monitor", Enabled: true, Remove: true, Path: "probes/templates/exec_monitor_ebpf/exec_monitor.o"},
			{AgentID: req.AgentId, ProbeName: "bash_monitor", Enabled: true, Remove: true, Path: "probes/templates/bash_monitor/bash_monitor.o"},
			{AgentID: req.AgentId, ProbeName: "tcp_monitor", Enabled: true, Remove: true, Path: "probes/templates/tcp_monitor/tcp_monitor.o"},
		}
	}

	probes := make([]*pb.ProbeInfo, 0, len(configs))
	for _, cfg := range configs {
		probes = append(probes, &pb.ProbeInfo{
			Name:    cfg.ProbeName,
			Enabled: cfg.Enabled,
			Remove:  cfg.Remove,
			Path:    cfg.Path,
			Sha256:  cfg.Sha256,
		})
	}

	log.Printf("📋 %s 查询探针名单: %d个", req.AgentId, len(probes))
	// 获取误报特征黑名单
	fpFeatures, _ := s.handler.Store.GetFeedbackFeatures()

	return &pb.ProbeListResponse{Success: true, Probes: probes, FalsePositiveFeatures: fpFeatures}, nil
}



func (s *Server) ReportShutdown(ctx context.Context, req *pb.ShutdownRequest) (*pb.ShutdownResponse, error) {
	h := s.handler
	h.Mu.Lock()
	if agent, ok := h.Agents[req.AgentId]; ok {
		if agent.Token == req.AgentToken {
			agent.LastSeen = 0 // 标记为主动离线
			h.Store.SaveAgent(agent.ID, agent.Hostname, agent.IPAddr, agent.Version, agent.Group, agent.Token, agent.FirstSeen, 0)
			log.Printf("👋 Agent正常下线: %s", agent.Hostname)
		}
	}
	h.Mu.Unlock()
	return &pb.ShutdownResponse{Success: true}, nil
}

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
	"sync"
	"time"

	"github.com/CoderXinNing/ebpf-system/proto/pb"
	"github.com/CoderXinNing/ebpf-system/server/internal/auth"
	"github.com/CoderXinNing/ebpf-system/server/internal/handler"
	"github.com/CoderXinNing/ebpf-system/server/internal/alert"
	"github.com/CoderXinNing/ebpf-system/server/internal/udp"
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
var baselineEngine *alert.BaselineEngine
var eventCounter = struct {
	sync.Map // key: ip:metric  value: int
}{}
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

	baselineEngine = alert.NewBaselineEngine("server/configs/baseline.toml")

	// 基线状态更新（每分钟）
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			baselineEngine.UpdateState()
			baselineEngine.IsProbeOnline()
			// 每分钟把窗口计数送基线，然后重置
			eventCounter.Range(func(k, v interface{}) bool {
				key := k.(string)
				count := v.(int)
				// key 格式: ip:dimension:metric
				parts := strings.Split(key, ":")
				if len(parts) >= 3 {
					ip := parts[0]
					user := parts[1]
					metric := parts[2]

					featureKey := user + ":" + metric
					isAnomaly, zScore := baselineEngine.Update(alert.Feature{IP: ip, Key: featureKey, Value: float64(count)})
					log.Printf("📊 基线窗口: %s user=%s %s=%d", ip, user, metric, count)
					
					// 软基线异常接入告警流
					if isAnomaly {
						desc := fmt.Sprintf("%s 基线异常: %s=%d z=%.2f", user, metric, count, zScore)
						st.SaveAlert(store.AlertRecord{
							RuleName:    "软基线异常检测",
							Severity:    "HIGH",
							Description: desc,
							AgentID:     ip,
							PID:         0,
							Comm:        user,     // 执行用户
							Filename:    metric,
							Details:     desc,
							Source:      "baseline",
						})
						log.Printf("🚨 软基线告警入库: %s", desc)
					}
				}
				eventCounter.Delete(k)
				return true
			})
		}
	}()

	// 基线持久化（每5分钟）
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			baselineEngine.Persist()
		}
	}()

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
		// 硬规则引擎
		alertEngine.CheckEvent(req.AgentId, evt.Pid, evt.Comm, evt.Details, evt.Filename, evt.EventType)

		// 上下文关联（按 IP + PID）
		if ip != "" {
			chain := correlationEngine.AddEvent(ip, uint32(evt.Pid), 0, evt.EventType, evt.Comm, evt.Details)
			correlationEngine.CheckCorrelation(chain)
		}

		// 软基线统计（按事件类型）
		if ip != "" {
			// 按事件类型选择维度
			dimension := "unknown"
			if evt.EventType == "tcp_connect" {
				// tcp 用进程名
				dimension = strings.TrimRight(evt.Comm, "\x00")
				if dimension == "" {
					dimension = "unknown"
				}
			} else {
				// exec/bash 用用户
				if idx := strings.Index(evt.Details, ":"); idx > 0 && idx < 30 {
					dimension = strings.TrimSpace(evt.Details[:idx])
				}
			}

			switch evt.EventType {
			case "execve":
				incrementCounter(ip + ":" + dimension + ":exec_count")
			case "tcp_connect":
				incrementCounter(ip + ":" + dimension + ":tcp_count")
			case "bash_input":
				incrementCounter(ip + ":" + dimension + ":bash_count")
			}
		}
	}
	h := s.handler
	h.EventMu.Lock()
	defer h.EventMu.Unlock()
	for _, evt := range req.Events {
		b := make([]byte, 8)
		rand.Read(b)
		h.Events = append(h.Events, handler.ProbeEvent{
			ID:        hex.EncodeToString(b),
			AgentID:   req.AgentId,
			ProbeName: evt.ProbeName,
			Timestamp: evt.Timestamp,
			EventType: evt.EventType,
			PID:       evt.Pid,
			Comm:      evt.Comm,
			Filename:  evt.Filename,
			Details:   evt.Details,
		})
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
		})
	}

	log.Printf("📋 %s 查询探针名单: %d个", req.AgentId, len(probes))
	return &pb.ProbeListResponse{Success: true, Probes: probes}, nil
}


func incrementCounter(key string) int {
	val, _ := eventCounter.LoadOrStore(key, 0)
	count := val.(int) + 1
	eventCounter.Store(key, count)
	return count
}

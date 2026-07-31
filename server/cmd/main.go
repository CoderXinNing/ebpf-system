package main

import (
	"crypto/rand"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/CoderXinNing/ebpf-system/proto/pb"
	"github.com/CoderXinNing/ebpf-system/server/internal/auth"
	"github.com/CoderXinNing/ebpf-system/server/internal/handler"
	"github.com/CoderXinNing/ebpf-system/server/internal/store"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
)

type Server struct {
	pb.UnimplementedSentinelServer
	handler *handler.Handler
}

func main() {
	st, err := store.NewStore("sentinel.db")
	if err != nil {
		log.Fatalf("数据库初始化失败: %v", err)
	}
	defer st.Close()

	am, err := auth.NewAuthManager(st.DB())
	if err != nil {
		log.Fatalf("auth初始化失败: %v", err)
	}

	srv := &Server{}
	srv.handler = handler.NewHandler(st, am, srv.sendCommand)

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
		Group:       req.AgentGroup,
		Token: tk, FirstSeen: now, LastSeen: now,
		Framework: req.Framework, KernelInfo: req.KernelInfo,
		Commands: make([]*pb.ProbeCommand, 0),
	}
	log.Printf("✅ Agent注册: %s (%s)", req.Hostname, req.IpAddress)
	return &pb.RegisterResponse{Success: true, Message: "注册成功", AgentToken: tk}, nil
}

func (s *Server) Heartbeat(stream pb.Sentinel_HeartbeatServer) error {
	req, _ := stream.Recv()
	h := s.handler
	h.Mu.Lock()
	agent, ok := h.Agents[req.AgentId]
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
		"service_status":  req.ServiceStatus,
		"jar_packages":    req.JarPackages,
		"python_packages": req.PythonPackages,
		"npm_packages":    req.NpmPackages,
		"agent_self":      req.AgentSelf,
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

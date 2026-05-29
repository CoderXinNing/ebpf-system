package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
	"google.golang.org/grpc"
)

// AgentInfo Agent完整信息
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
}

// AgentListResponse API响应
type AgentListResponse struct {
	Total  int         `json:"total"`
	Agents []AgentInfo `json:"agents"`
}

type Server struct {
	pb.UnimplementedSentinelServer
	mu     sync.RWMutex
	agents map[string]*AgentInfo
}

func NewServer() *Server {
	return &Server{
		agents: make(map[string]*AgentInfo),
	}
}

func generateToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, exists := s.agents[req.AgentId]; exists {
		// 已存在，更新信息
		existing.IPAddr = req.IpAddress
		existing.LastSeen = time.Now().Unix()
		if req.Framework != nil {
			existing.Framework = req.Framework
		}
		if req.KernelInfo != nil {
			existing.KernelInfo = req.KernelInfo
		}
		return &pb.RegisterResponse{
			Success:    true,
			Message:    "已更新",
			AgentToken: existing.Token,
		}, nil
	}

	token := generateToken()
	now := time.Now().Unix()

	s.agents[req.AgentId] = &AgentInfo{
		ID:        req.AgentId,
		Hostname:  req.Hostname,
		IPAddr:    req.IpAddress,
		Token:     token,
		FirstSeen: now,
		LastSeen:  now,
		Framework: req.Framework,
		KernelInfo: req.KernelInfo,
	}

	log.Printf("✅ Agent注册: %s (%s) [%s]", req.Hostname, req.IpAddress, req.KernelVersion)
	if req.Framework != nil {
		log.Printf("   框架: BCC=%v libbpf=%v bpftrace=%v clang=%v Go=%v",
			req.Framework.BccAvailable,
			req.Framework.LibbpfAvailable,
			req.Framework.BpftraceAvailable,
			req.Framework.ClangAvailable,
			req.Framework.GoEbpfAvailable)
	}

	return &pb.RegisterResponse{
		Success:    true,
		Message:    "注册成功",
		AgentToken: token,
	}, nil
}

func (s *Server) Heartbeat(stream pb.Sentinel_HeartbeatServer) error {
	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}

		s.mu.Lock()
		agent, exists := s.agents[req.AgentId]
		if exists && agent.Token == req.AgentToken {
			agent.ActiveProbes = req.ActiveProbes
			agent.LastSeen = req.Timestamp
		}
		s.mu.Unlock()

		if !exists {
			log.Printf("⚠️ 未知Agent心跳: %s", req.AgentId)
			continue
		}

		err = stream.Send(&pb.HeartbeatResponse{
			Success: true,
		})
		if err != nil {
			return err
		}

		log.Printf("💓 心跳: %s (活跃探针: %d)", req.AgentId, req.ActiveProbes)
	}
}

func (s *Server) Report(ctx context.Context, req *pb.AgentReport) (*pb.HeartbeatResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.agents[req.AgentId]; !exists {
		return &pb.HeartbeatResponse{Success: false}, fmt.Errorf("未知Agent")
	}

	for _, alert := range req.Alerts {
		log.Printf("🚨 告警: [%s] %s - %s (PID:%d)",
			alert.Severity, alert.Title, alert.ProcessName, alert.Pid)
	}

	return &pb.HeartbeatResponse{Success: true}, nil
}

// === HTTP API ===

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agents := make([]AgentInfo, 0, len(s.agents))
	for _, agent := range s.agents {
		agents = append(agents, *agent)
	}

	resp := AgentListResponse{
		Total:  len(agents),
		Agents: agents,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("id")
	if agentID == "" {
		http.Error(w, "缺少agent id参数", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	agent, exists := s.agents[agentID]
	if !exists {
		http.Error(w, "Agent不存在", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agent)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().Unix()
	online := 0
	offline := 0

	for _, agent := range s.agents {
		if now-agent.LastSeen < 30 {
			online++
		} else {
			offline++
		}
	}

	resp := map[string]interface{}{
		"status":   "ok",
		"online":   online,
		"offline":  offline,
		"total":    len(s.agents),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) startHTTP(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/agents", s.handleListAgents)
	mux.HandleFunc("/api/agent", s.handleGetAgent)
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"service": "eBPF Sentinel Server",
			"version": "0.1.0",
			"endpoints": "/api/agents | /api/agent?id=xxx | /api/health",
		})
	})

	log.Printf("🌐 HTTP API 启动在 %s", addr)
	log.Printf("   试试: curl %s/api/agents", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("HTTP服务启动失败: %v", err)
	}
}

func main() {
	// 启动gRPC服务
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}

	server := NewServer()

	grpcServer := grpc.NewServer()
	pb.RegisterSentinelServer(grpcServer, server)

	go func() {
		log.Println("🛡️  eBPF Sentinel gRPC Server 启动在 :50051")
		log.Println("   等待Agent连接...")
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("gRPC服务启动失败: %v", err)
		}
	}()

	// 启动HTTP API
	server.startHTTP(":8080")
}

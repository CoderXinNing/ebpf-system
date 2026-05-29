package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
	"google.golang.org/grpc"
)

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

type ProbeEvent struct {
	ID        string `json:"id"`
	AgentID   string `json:"agent_id"`
	ProbeID   string `json:"probe_id"`
	ProbeName string `json:"probe_name"`
	Timestamp int64  `json:"timestamp"`
	EventType string `json:"event_type"`
	PID       int32  `json:"pid"`
	Comm      string `json:"comm"`
	Filename  string `json:"filename"`
	Details   string `json:"details"`
}

type Server struct {
	pb.UnimplementedSentinelServer
	mu      sync.RWMutex
	agents  map[string]*AgentInfo
	events  []ProbeEvent
	eventMu sync.RWMutex
}

func NewServer() *Server {
	return &Server{
		agents: make(map[string]*AgentInfo),
		events: make([]ProbeEvent, 0, 10000),
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

	now := time.Now().Unix()

	if existing, exists := s.agents[req.AgentId]; exists {
		existing.IPAddr = req.IpAddress
		existing.LastSeen = now
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

	log.Printf("✅ Agent注册: %s (%s)", req.Hostname, req.IpAddress)
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
			continue
		}

		stream.Send(&pb.HeartbeatResponse{Success: true})
		log.Printf("💓 心跳: %s (探针: %d)", req.AgentId, req.ActiveProbes)
	}
}

// ReportEvents Agent上报探针事件
func (s *Server) ReportEvents(ctx context.Context, req *pb.EventReport) (*pb.HeartbeatResponse, error) {
	s.eventMu.Lock()
	defer s.eventMu.Unlock()

	for _, evt := range req.Events {
		event := ProbeEvent{
			ID:        hex.EncodeToString(make([]byte, 8)),
			AgentID:   req.AgentId,
			ProbeID:   evt.ProbeId,
			ProbeName: evt.ProbeName,
			Timestamp: evt.Timestamp,
			EventType: evt.EventType,
			PID:       evt.Pid,
			Comm:      evt.Comm,
			Filename:  evt.Filename,
			Details:   evt.Details,
		}
		// 生成随机ID
		b := make([]byte, 8)
		rand.Read(b)
		event.ID = hex.EncodeToString(b)

		s.events = append(s.events, event)

		log.Printf("📩 [%s] %s PID=%d COMM=%s FILE=%s",
			req.AgentId, evt.ProbeName, evt.Pid, evt.Comm, evt.Filename)

		// 限制最多存10000条
		if len(s.events) > 10000 {
			s.events = s.events[len(s.events)-1000:]
		}
	}

	return &pb.HeartbeatResponse{Success: true}, nil
}

// === HTTP API ===

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agents := make([]AgentInfo, 0, len(s.agents))
	for _, a := range s.agents {
		agents = append(agents, *a)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"total":  len(agents),
		"agents": agents,
	})
}

func (s *Server) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	s.eventMu.RLock()
	defer s.eventMu.RUnlock()

	limit := 100
	events := s.events
	if len(events) > limit {
		events = events[len(events)-limit:]
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"total":  len(s.events),
		"events": events,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().Unix()
	online := 0
	for _, a := range s.agents {
		if now-a.LastSeen < 30 {
			online++
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"online":  online,
		"total":   len(s.agents),
	})
}

func (s *Server) startHTTP(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/agents", s.handleListAgents)
	mux.HandleFunc("/api/events", s.handleGetEvents)
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"service":   "eBPF Sentinel Server",
			"endpoints": "/api/agents | /api/events | /api/health",
		})
	})

	log.Printf("🌐 HTTP API: %s", addr)
	http.ListenAndServe(addr, mux)
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}

	server := NewServer()

	grpcServer := grpc.NewServer()
	pb.RegisterSentinelServer(grpcServer, server)

	go func() {
		log.Println("🛡️  gRPC Server :50051")
		grpcServer.Serve(lis)
	}()

	server.startHTTP(":8080")
}

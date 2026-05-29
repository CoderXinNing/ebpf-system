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
		if req.Framework != nil { existing.Framework = req.Framework }
		if req.KernelInfo != nil { existing.KernelInfo = req.KernelInfo }
		return &pb.RegisterResponse{Success: true, Message: "已更新", AgentToken: existing.Token}, nil
	}

	token := generateToken()
	s.agents[req.AgentId] = &AgentInfo{
		ID: req.AgentId, Hostname: req.Hostname, IPAddr: req.IpAddress,
		Token: token, FirstSeen: now, LastSeen: now,
		Framework: req.Framework, KernelInfo: req.KernelInfo,
		Commands: make([]*pb.ProbeCommand, 0),
	}
	log.Printf("✅ Agent注册: %s (%s)", req.Hostname, req.IpAddress)
	return &pb.RegisterResponse{Success: true, Message: "注册成功", AgentToken: token}, nil
}

func (s *Server) Heartbeat(stream pb.Sentinel_HeartbeatServer) error {
	// 第一条消息认证
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	s.mu.Lock()
	agent, exists := s.agents[req.AgentId]
	if !exists || agent.Token != req.AgentToken {
		s.mu.Unlock()
		stream.Send(&pb.HeartbeatResponse{Success: false})
		return fmt.Errorf("认证失败")
	}
	agent.LastSeen = req.Timestamp
	agent.ActiveProbes = req.ActiveProbes
	agentID := req.AgentId
	s.mu.Unlock()

	log.Printf("💓 心跳流建立: %s", agentID)

	// 后台接收后续心跳
	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				return
			}
			s.mu.Lock()
			if a, ok := s.agents[req.AgentId]; ok {
				a.LastSeen = req.Timestamp
				a.ActiveProbes = req.ActiveProbes
			}
			s.mu.Unlock()
		}
	}()

	// 定期检查指令
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		cmds := agent.Commands
		agent.Commands = make([]*pb.ProbeCommand, 0)
		s.mu.Unlock()

		if len(cmds) > 0 {
			if err := stream.Send(&pb.HeartbeatResponse{Success: true, Commands: cmds}); err != nil {
				return err
			}
			log.Printf("📤 下发指令: %s (%d条)", agentID, len(cmds))
		}
	}
	return nil
}

func (s *Server) ReportEvents(ctx context.Context, req *pb.EventReport) (*pb.HeartbeatResponse, error) {
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	for _, evt := range req.Events {
		b := make([]byte, 8)
		rand.Read(b)
		s.events = append(s.events, ProbeEvent{
			ID: hex.EncodeToString(b), AgentID: req.AgentId,
			ProbeID: evt.ProbeId, ProbeName: evt.ProbeName,
			Timestamp: evt.Timestamp, EventType: evt.EventType,
			PID: evt.Pid, Comm: trimNull(evt.Comm),
			Filename: trimNull(evt.Filename), Details: evt.Details,
		})
		if len(s.events) > 10000 { s.events = s.events[len(s.events)-1000:] }
	}
	return &pb.HeartbeatResponse{Success: true}, nil
}

func (s *Server) sendCommand(agentID string, cmd *pb.ProbeCommand) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	agent, exists := s.agents[agentID]
	if !exists { keys := make([]string, 0, len(s.agents)); for k := range s.agents { keys = append(keys, k) }; return fmt.Errorf("Agent不存在: %s, 已知: %v", agentID, keys) }
	agent.Commands = append(agent.Commands, cmd)
	log.Printf("📋 指令已排队: %s -> %s (%s)", agentID, cmd.ProbeName, cmd.Type)
	return nil
}

func trimNull(s string) string {
	for i, c := range s { if c == 0 { return s[:i] } }
	return s
}

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock(); defer s.mu.RUnlock()
	agents := make([]AgentInfo, 0, len(s.agents))
	for _, a := range s.agents { agents = append(agents, *a) }
	json.NewEncoder(w).Encode(map[string]interface{}{"total": len(agents), "agents": agents})
}

func (s *Server) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	s.eventMu.RLock(); defer s.eventMu.RUnlock()
	limit := 100; events := s.events
	if len(events) > limit { events = events[len(events)-limit:] }
	json.NewEncoder(w).Encode(map[string]interface{}{"total": len(s.events), "events": events})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock(); defer s.mu.RUnlock()
	now := time.Now().Unix(); online := 0
	for _, a := range s.agents { if now-a.LastSeen < 30 { online++ } }
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "online": online, "total": len(s.agents)})
}

func (s *Server) handleCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" { http.Error(w, "only POST", http.StatusMethodNotAllowed); return }
	var req struct {
		AgentID string `json:"agent_id"`; ProbeID string `json:"probe_id"`; ProbeName string `json:"probe_name"`; Action string `json:"action"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	var cmdType pb.ProbeCommand_CommandType
	switch req.Action {
	case "load": cmdType = pb.ProbeCommand_LOAD
	case "unload": cmdType = pb.ProbeCommand_UNLOAD
	default: json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "action must be load or unload"}); return
	}
	cmd := &pb.ProbeCommand{Type: cmdType, ProbeId: req.ProbeID, ProbeName: req.ProbeName}
	if err := s.sendCommand(req.AgentID, cmd); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()}); return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "指令已排队"})
}

func (s *Server) startHTTP(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/agents", s.handleListAgents)
	mux.HandleFunc("/api/events", s.handleGetEvents)
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/command", s.handleCommand)
	log.Printf("🌐 HTTP API: %s", addr)
	http.ListenAndServe(addr, mux)
}

func main() {
	lis, _ := net.Listen("tcp", ":50051")
	server := NewServer()
	grpcServer := grpc.NewServer()
	pb.RegisterSentinelServer(grpcServer, server)
	go func() { log.Println("🛡️  gRPC :50051"); grpcServer.Serve(lis) }()
	server.startHTTP(":8080")
}

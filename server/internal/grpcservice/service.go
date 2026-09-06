package grpcservice

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/CoderXinNing/ebpf-system/proto/pb"
	"github.com/CoderXinNing/ebpf-system/server/internal/handler"
	"github.com/CoderXinNing/ebpf-system/server/internal/middleware"
	"github.com/CoderXinNing/ebpf-system/server/internal/service"
	"github.com/CoderXinNing/ebpf-system/server/internal/store"
)

// Service 实现 gRPC Sentinel 服务
type Service struct {
	pb.UnimplementedSentinelServer
	handler     *handler.Handler
	agentAuth   *middleware.AgentAuthInterceptor
	starService *service.StarActivationService
}

func NewService(h *handler.Handler, auth *middleware.AgentAuthInterceptor) *Service {
	return &Service{
		handler:     h,
		agentAuth:   auth,
		starService: service.NewStarActivationService(),
	}
}

// sendCommand 向 Agent 下发命令
func (s *Service) sendCommand(agentID string, cmd *pb.ProbeCommand) error {
	s.handler.Mu.Lock()
	defer s.handler.Mu.Unlock()
	agent := s.handler.Agents[agentID]
	if agent == nil {
		return fmt.Errorf("Agent不存在")
	}
	agent.Commands = append(agent.Commands, cmd)
	return nil
}

// Register Agent 注册
func (s *Service) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	now := time.Now().Unix()
	tk := genToken()
	agentInfo := &handler.AgentInfo{
		ID: req.AgentId, Hostname: req.Hostname, IPAddr: req.IpAddress,
		Version: req.AgentVersion, Group: getGroup(req.AgentGroup),
		Token: tk, FirstSeen: now, LastSeen: now,
		Framework: req.Framework, KernelInfo: req.KernelInfo,
		Commands: make([]*pb.ProbeCommand, 0),
	}
	s.handler.Mu.Lock()
	s.handler.Agents[req.AgentId] = agentInfo
	s.handler.Mu.Unlock()

	// 持久化（SQLite 模式下；PSQL 模式后续通过 repository 写入）
	log.Printf("DEBUG: handler.Store = %v", s.handler.Store)
	if s.handler != nil && s.handler.Store != nil && s.handler.Store.DB() != nil {
		s.handler.Store.SaveAgent(req.AgentId, req.Hostname, req.IpAddress,
			req.AgentVersion, getGroup(req.AgentGroup), tk, now, now)
	}
	log.Printf("✅ Agent注册: %s (%s)", req.Hostname, req.IpAddress)

	// 设置 token 到鉴权拦截器
	if s.agentAuth != nil {
		s.agentAuth.SetToken(req.AgentId, tk)
	}
	return &pb.RegisterResponse{Success: true, Message: "注册成功", AgentToken: tk}, nil
}

// Heartbeat 心跳（Unary）
func (s *Service) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	s.handler.Mu.Lock()
	agent := s.handler.Agents[req.AgentId]
	if agent == nil {
		s.handler.Mu.Unlock()
		return &pb.HeartbeatResponse{Success: false}, nil
	}
	agent.LastSeen = time.Now().Unix()
	commands := agent.Commands
	agent.Commands = make([]*pb.ProbeCommand, 0)
	s.handler.Mu.Unlock()

	if s.handler.Store != nil {
		s.handler.Store.SaveAgent(agent.ID, agent.Hostname, agent.IPAddr, agent.Version, agent.Group, agent.Token, agent.FirstSeen, agent.LastSeen)
	}
	return &pb.HeartbeatResponse{Success: true, Commands: commands}, nil
}

// ReportEvents 事件上报
func (s *Service) ReportEvents(ctx context.Context, req *pb.EventReport) (*pb.ReportResponse, error) {
	log.Printf("📥 Server 收到事件上报: %d 个事件", len(req.Events))
	if len(req.Events) > 0 {
		log.Printf("🔑 第一个事件 correlation_key=%d correlation_id=%s", req.Events[0].CorrelationKey, req.Events[0].CorrelationId)
	}
	h := s.handler
	for _, evt := range req.Events {
		// 优先用事件级 correlation_id，兼容旧版外层
		corrID := evt.CorrelationId
		if corrID == "" {
			corrID = req.CorrelationId
		}
		evtRecord := handler.ProbeEvent{
			ID:            genToken()[:8],
			AgentID:       req.AgentId,
			ProbeName:     evt.ProbeName,
			Timestamp:     evt.Timestamp,
			EventType:     evt.EventType,
			PID:           evt.Pid,
			Comm:          evt.Comm,
			Filename:      evt.Filename,
			Details:       evt.Details,
			CorrelationID:  corrID,
			CorrelationKey: evt.CorrelationKey,
		}
		h.EventMu.Lock()
		h.Events = append(h.Events, evtRecord)
		if len(h.Events) > 10000 {
			h.Events = h.Events[len(h.Events)-1000:]
		}
		h.EventMu.Unlock()
	}
	return &pb.ReportResponse{Success: true}, nil
}

// 资产上报方法（11 个）
func (s *Service) ReportProcesses(ctx context.Context, req *pb.ProcessReport) (*pb.ReportResponse, error) {
	procJSON, _ := json.Marshal(req.Processes)
	if s.handler.Store != nil { s.handler.Store.SaveAsset(req.AgentId, procJSON, nil, nil) }
	return &pb.ReportResponse{Success: true}, nil
}

func (s *Service) ReportUsers(ctx context.Context, req *pb.UserReport) (*pb.ReportResponse, error) {
	userJSON, _ := json.Marshal(req.Users)
	if s.handler.Store != nil { s.handler.Store.SaveAsset(req.AgentId, nil, userJSON, nil) }
	return &pb.ReportResponse{Success: true}, nil
}

func (s *Service) ReportSystemInfo(ctx context.Context, req *pb.SystemReport) (*pb.ReportResponse, error) {
	sysJSON, _ := json.Marshal(req.System)
	if s.handler.Store != nil { s.handler.Store.SaveAsset(req.AgentId, nil, nil, sysJSON) }
	return &pb.ReportResponse{Success: true}, nil
}

func (s *Service) ReportPackages(ctx context.Context, req *pb.PackageReport) (*pb.ReportResponse, error) {
	sysData := map[string]interface{}{
		"packages":        req.Packages,
		"jar_packages":    req.JarPackages,
		"python_packages": req.PythonPackages,
		"npm_packages":    req.NpmPackages,
	}
	sysJSON, _ := json.Marshal(sysData)
	if s.handler.Store != nil { s.handler.Store.SaveAsset(req.AgentId, nil, nil, sysJSON) }
	return &pb.ReportResponse{Success: true}, nil
}

func (s *Service) ReportCronJobs(ctx context.Context, req *pb.CronReport) (*pb.ReportResponse, error) {
	sysData := map[string]interface{}{"crons": req.Crons}
	sysJSON, _ := json.Marshal(sysData)
	if s.handler.Store != nil { s.handler.Store.SaveAsset(req.AgentId, nil, nil, sysJSON) }
	return &pb.ReportResponse{Success: true}, nil
}

func (s *Service) ReportServices(ctx context.Context, req *pb.ServiceReport) (*pb.ReportResponse, error) {
	sysData := map[string]interface{}{
		"services":       req.Services,
		"service_status": req.ServiceStatus,
	}
	sysJSON, _ := json.Marshal(sysData)
	if s.handler.Store != nil { s.handler.Store.SaveAsset(req.AgentId, nil, nil, sysJSON) }
	return &pb.ReportResponse{Success: true}, nil
}

func (s *Service) ReportWebComponents(ctx context.Context, req *pb.WebComponentReport) (*pb.ReportResponse, error) {
	sysData := map[string]interface{}{"web_components": req.WebComponents}
	sysJSON, _ := json.Marshal(sysData)
	if s.handler.Store != nil { s.handler.Store.SaveAsset(req.AgentId, nil, nil, sysJSON) }
	return &pb.ReportResponse{Success: true}, nil
}

func (s *Service) ReportHardware(ctx context.Context, req *pb.HardwareReport) (*pb.ReportResponse, error) {
	sysData := map[string]interface{}{
		"hardware":       req.Hardware,
		"kernel_modules": req.KernelModules,
		"env_variables":  req.EnvVariables,
	}
	sysJSON, _ := json.Marshal(sysData)
	if s.handler.Store != nil { s.handler.Store.SaveAsset(req.AgentId, nil, nil, sysJSON) }
	return &pb.ReportResponse{Success: true}, nil
}

func (s *Service) ReportNetwork(ctx context.Context, req *pb.NetworkReport) (*pb.ReportResponse, error) {
	sysData := map[string]interface{}{
		"gateway_dns":     req.GatewayDns,
		"network_details": req.NetworkDetails,
		"disk_usages":     req.DiskUsages,
	}
	sysJSON, _ := json.Marshal(sysData)
	if s.handler.Store != nil { s.handler.Store.SaveAsset(req.AgentId, nil, nil, sysJSON) }
	return &pb.ReportResponse{Success: true}, nil
}

func (s *Service) ReportPerformance(ctx context.Context, req *pb.PerfReport) (*pb.ReportResponse, error) {
	sysData := map[string]interface{}{"perf": req.Perf}
	sysJSON, _ := json.Marshal(sysData)
	if s.handler.Store != nil { s.handler.Store.SaveAsset(req.AgentId, nil, nil, sysJSON) }
	return &pb.ReportResponse{Success: true}, nil
}

func (s *Service) ReportAgentSelf(ctx context.Context, req *pb.AgentSelfReport) (*pb.ReportResponse, error) {
	sysData := map[string]interface{}{"agent_self": req.AgentSelf}
	sysJSON, _ := json.Marshal(sysData)
	if s.handler.Store != nil { s.handler.Store.SaveAsset(req.AgentId, nil, nil, sysJSON) }
	return &pb.ReportResponse{Success: true}, nil
}

// GetProbeList 探针名单查询
func (s *Service) GetProbeList(ctx context.Context, req *pb.ProbeListRequest) (*pb.ProbeListResponse, error) {
	var configs []store.ProbeConfigRecord
	var err error
	if s.handler.Store != nil {
		configs, err = s.handler.Store.GetProbeConfigs(req.AgentId)
	}
	if err != nil {
		return &pb.ProbeListResponse{Success: false, Message: "查询失败"}, nil
	}

	probes := make([]*pb.ProbeInfo, 0)
	for _, cfg := range configs {
		probes = append(probes, &pb.ProbeInfo{
			Name:    cfg.ProbeName,
			Enabled: cfg.Enabled,
			Remove:  cfg.Remove,
			Path:    cfg.Path,
			Sha256:  cfg.Sha256,
		})
	}

	if len(probes) == 0 {
		// 默认名单
		probes = []*pb.ProbeInfo{
			{Name: "exec_monitor", Enabled: true, Path: "probes/templates/exec_monitor_ebpf/exec_monitor.o"},
			{Name: "bash_monitor", Enabled: true, Path: "probes/templates/bash_monitor/bash_monitor.o"},
			{Name: "tcp_monitor", Enabled: true, Path: "probes/templates/tcp_monitor/tcp_monitor.o"},
			{Name: "file_access", Enabled: true, Path: "v3_engine/probes/file_access.o"},
		}
	}

	// 误报特征
	var features []string
	if s.handler.Store != nil {
		features, _ = s.handler.Store.GetFeedbackFeatures()
	}

	return &pb.ProbeListResponse{Success: true, Probes: probes, FalsePositiveFeatures: features}, nil
}

// ReportShutdown 下线通知
func (s *Service) ReportShutdown(ctx context.Context, req *pb.ShutdownRequest) (*pb.ShutdownResponse, error) {
	s.handler.Mu.Lock()
	if agent, ok := s.handler.Agents[req.AgentId]; ok {
		agent.LastSeen = 0
		if s.handler.Store != nil {
			s.handler.Store.SaveAgent(agent.ID, agent.Hostname, agent.IPAddr, agent.Version, agent.Group, agent.Token, agent.FirstSeen, 0)
		}
		log.Printf("👋 Agent正常下线: %s", agent.Hostname)
	}
	s.handler.Mu.Unlock()
	if s.agentAuth != nil {
		s.agentAuth.RemoveToken(req.AgentId)
	}
	return &pb.ShutdownResponse{Success: true}, nil
}

// genToken 生成随机 token
func genToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// getGroup 获取分组（默认为"未分组"）
func getGroup(g string) string {
	if g == "" {
		return "未分组"
	}
	return g
}

// ReportMutation 处理 Agent 上报的突变触发
func (s *Service) ReportMutation(ctx context.Context, req *pb.MutationTrigger) (*pb.ReportResponse, error) {
	corrID := s.starService.HandleMutation(req.AgentId, req.Pid)
	log.Printf("⭐ 星轨触发: agent=%s pid=%d type=%s corr=%s",
		req.AgentId, req.Pid, req.TriggerType, corrID)
	return &pb.ReportResponse{Success: true, Message: corrID}, nil
}

// ActivateStarMode 广播警戒模式（Server → Agent）
// Agent 端实现此 RPC，Server 端作为客户端调用
func (s *Service) ActivateStarMode(ctx context.Context, req *pb.StarActivation) (*pb.StarActivationAck, error) {
	// Server 端不直接实现此方法（是 Agent 端的方法）
	// 这里返回"未实现"，实际调用由 Agent 处理
	return &pb.StarActivationAck{
		ModeActivated: false,
		ErrorMessage:  "此方法在 Agent 端实现",
	}, nil
}

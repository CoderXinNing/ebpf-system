package main

import (
	"context"
	"crypto/md5"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/CoderXinNing/ebpf-system/agent/internal/guardian"
	"github.com/CoderXinNing/ebpf-system/agent/internal/loader"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	serverAddr = "127.0.0.1:50051"
	retryDelay = 5 * time.Second
)

func getHostname() string {
	name, _ := os.Hostname()
	return name
}

func getIPAddress() string {
	conn, _ := net.Dial("udp", "8.8.8.8:80")
	if conn != nil {
		defer conn.Close()
		return conn.LocalAddr().(*net.UDPAddr).IP.String()
	}
	return "unknown"
}

func generateAgentID(hostname string) string {
	hash := md5.Sum([]byte(hostname))
	return fmt.Sprintf("agent-%x", hash[:8])
}

type Agent struct {
	id           string
	hostname     string
	kernelVer    string
	ipAddr       string
	token        string
	capabilities *probe.AgentCapabilities
	guardian     *guardian.Guardian
	probes       map[string]*loader.Probe
	probesMu     sync.RWMutex
	eventQueue   chan *pb.ProbeEvent
	conn         *grpc.ClientConn
	client       pb.SentinelClient
}

func NewAgent() *Agent {
	hostname := getHostname()
	return &Agent{
		id:         generateAgentID(hostname),
		hostname:   hostname,
		ipAddr:     getIPAddress(),
		probes:     make(map[string]*loader.Probe),
		eventQueue: make(chan *pb.ProbeEvent, 1000),
	}
}

func (a *Agent) RunProbe() error {
	log.Println("🔍 正在探测Agent环境...")
	caps, err := probe.Detect()
	if err != nil {
		return fmt.Errorf("环境探测失败: %w", err)
	}
	a.capabilities = caps
	a.kernelVer = caps.KernelVersion
	fmt.Print(caps.Summary())
	return nil
}

func (a *Agent) startGuardian() error {
	a.guardian = guardian.NewGuardian(nil)
	return a.guardian.Start()
}

func (a *Agent) loadProbe(cmd *pb.ProbeCommand) error {
	a.probesMu.Lock()
	defer a.probesMu.Unlock()

	if _, exists := a.probes[cmd.ProbeId]; exists {
		return fmt.Errorf("探针 %s 已加载", cmd.ProbeId)
	}

	switch cmd.ProbeName {
	case "exec_monitor":
		probeID := cmd.ProbeId
		probeName := cmd.ProbeName
		probe, err := loader.LoadExecMonitor(cmd.ProbeName, func(event loader.ExecEvent) {
			// 放入上报队列
			a.eventQueue <- &pb.ProbeEvent{
				ProbeId:   probeID,
				ProbeName: probeName,
				Timestamp: time.Now().Unix(),
				EventType: "execve",
				Pid:       int32(event.PID),
				Comm:      event.Comm,
				Filename:  event.Filename,
			}
		})
		if err != nil {
			return err
		}
		a.probes[cmd.ProbeId] = probe
	default:
		return fmt.Errorf("未知探针: %s", cmd.ProbeName)
	}
	return nil
}

func (a *Agent) unloadProbe(probeID string) error {
	a.probesMu.Lock()
	defer a.probesMu.Unlock()

	probe, exists := a.probes[probeID]
	if !exists {
		return fmt.Errorf("探针 %s 未加载", probeID)
	}
	probe.Stop()
	delete(a.probes, probeID)
	return nil
}

func (a *Agent) activeProbeCount() int32 {
	a.probesMu.RLock()
	defer a.probesMu.RUnlock()
	return int32(len(a.probes))
}

// eventReporter 批量上报事件
func (a *Agent) eventReporter() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	batch := make([]*pb.ProbeEvent, 0, 100)

	for {
		select {
		case evt := <-a.eventQueue:
			batch = append(batch, evt)
			if len(batch) >= 50 {
				a.flushEvents(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				a.flushEvents(batch)
				batch = batch[:0]
			}
		}
	}
}

func (a *Agent) flushEvents(events []*pb.ProbeEvent) {
	if a.client == nil || a.token == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := a.client.ReportEvents(ctx, &pb.EventReport{
		AgentId:    a.id,
		AgentToken: a.token,
		Events:     events,
	})
	if err != nil {
		log.Printf("⚠️ 上报事件失败: %v", err)
	}
}

func (a *Agent) buildRegisterRequest() *pb.RegisterRequest {
	fw := a.capabilities.Framework
	return &pb.RegisterRequest{
		AgentId:       a.id,
		Hostname:      a.hostname,
		KernelVersion: a.kernelVer,
		IpAddress:     a.ipAddr,
		Framework: &pb.FrameworkInfo{
			BccAvailable:          fw.BCCAvailable,
			LibbpfAvailable:       fw.LibBPFAvailable,
			LibbpfCore:            fw.LibBPFCORE,
			BpftraceAvailable:     fw.BpftraceAvailable,
			ClangAvailable:        fw.ClangAvailable,
			LlvmAvailable:         fw.LLVMAvailable,
			KernelHeadersAvailable: fw.KernelHeadersAvailable,
			GoEbpfAvailable:       fw.GoEBPFAvailable,
		},
		KernelInfo: &pb.KernelInfo{
			Version:    a.capabilities.KernelVersion,
			Arch:       a.capabilities.Arch,
			BtfEnabled: a.capabilities.BTFEnabled,
		},
	}
}

func (a *Agent) Register() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := a.client.Register(ctx, a.buildRegisterRequest())
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf("注册被拒绝")
	}
	a.token = resp.AgentToken
	log.Printf("✅ 注册成功! Agent ID: %s", a.id)
	return nil
}

func (a *Agent) HeartbeatLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := a.client.Heartbeat(ctx)
		if err != nil {
			log.Printf("⚠️ 心跳失败: %v", err)
			cancel()
			continue
		}
		resp.Send(&pb.HeartbeatRequest{
			AgentId:      a.id,
			AgentToken:   a.token,
			Timestamp:    time.Now().Unix(),
			ActiveProbes: a.activeProbeCount(),
		})
		resp.CloseSend()
		cancel()
	}
}

func (a *Agent) handleCommand(cmd *pb.ProbeCommand) {
	switch cmd.Type {
	case pb.ProbeCommand_LOAD:
		log.Printf("📥 加载指令: %s", cmd.ProbeName)
		if err := a.loadProbe(cmd); err != nil {
			log.Printf("❌ 失败: %v", err)
		} else {
			log.Printf("✅ 成功: %s", cmd.ProbeName)
		}
	case pb.ProbeCommand_UNLOAD:
		log.Printf("📤 卸载: %s", cmd.ProbeId)
		a.unloadProbe(cmd.ProbeId)
	}
}

func (a *Agent) Connect() error {
	var err error
	a.conn, err = grpc.Dial(serverAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return err
	}
	a.client = pb.NewSentinelClient(a.conn)
	log.Printf("🔗 已连接: %s", serverAddr)
	return nil
}

func (a *Agent) Start() {
	log.Printf("🛡️  eBPF Sentinel Agent")
	log.Printf("   ID: %s  主机: %s", a.id, a.hostname)

	if err := a.RunProbe(); err != nil {
		log.Fatalf("❌ %v", err)
	}
	if err := a.startGuardian(); err != nil {
		log.Printf("⚠️ 守护探针失败: %v", err)
	}

	// 临时测试
	a.loadProbe(&pb.ProbeCommand{ProbeId: "test-001", ProbeName: "exec_monitor", Type: pb.ProbeCommand_LOAD})

	for {
		if err := a.Connect(); err != nil {
			log.Printf("❌ %v", err)
			time.Sleep(retryDelay)
			continue
		}
		break
	}
	defer a.conn.Close()

	for {
		if err := a.Register(); err != nil {
			log.Printf("❌ %v", err)
			time.Sleep(retryDelay)
			continue
		}
		break
	}

	// 启动事件上报
	go a.eventReporter()

	a.HeartbeatLoop()
}

func main() {
	agent := NewAgent()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("\n🛑 退出...")
		if agent.guardian != nil {
			agent.guardian.Stop()
		}
		os.Exit(0)
	}()
	agent.Start()
}

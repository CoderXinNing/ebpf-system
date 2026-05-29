package main

import (
	"context"
	"crypto/md5"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/CoderXinNing/ebpf-system/agent/internal/config"
	"github.com/CoderXinNing/ebpf-system/agent/internal/guardian"
	"github.com/CoderXinNing/ebpf-system/agent/internal/loader"
	"github.com/CoderXinNing/ebpf-system/agent/internal/loader/registry"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	configPath = flag.String("config", "agent/configs/agent.yaml", "配置文件路径")
	genConfig  = flag.Bool("gen-config", false, "生成默认配置文件")
	listProbes = flag.Bool("list-probes", false, "列出所有可用探针")
)

func getHostname() string {
	name, _ := os.Hostname(); return name
}
func getIPAddress() string {
	conn, _ := net.Dial("udp", "8.8.8.8:80")
	if conn != nil { defer conn.Close(); return conn.LocalAddr().(*net.UDPAddr).IP.String() }
	return "unknown"
}
func generateAgentID(hostname string) string {
	hash := md5.Sum([]byte(hostname))
	return fmt.Sprintf("agent-%x", hash[:8])
}

type Agent struct {
	id, hostname, kernelVer, ipAddr, token string
	cfg        *config.AgentConfig
	capabilities *probe.AgentCapabilities
	guardian   *guardian.Guardian
	probes     map[string]registry.ProbeInstance
	probesMu   sync.RWMutex
	eventQueue chan *pb.ProbeEvent
	conn       *grpc.ClientConn
	client     pb.SentinelClient
}

func NewAgent(cfg *config.AgentConfig) *Agent {
	hostname := getHostname()
	if cfg.Agent.Name != "" { hostname = cfg.Agent.Name }
	return &Agent{
		id: generateAgentID(hostname), hostname: hostname, ipAddr: getIPAddress(), cfg: cfg,
		probes: make(map[string]registry.ProbeInstance), eventQueue: make(chan *pb.ProbeEvent, 1000),
	}
}

func (a *Agent) RunProbe() error {
	caps, err := probe.Detect()
	if err != nil { return err }
	a.capabilities = caps; a.kernelVer = caps.KernelVersion
	fmt.Print(caps.Summary())
	return nil
}

func (a *Agent) startGuardian() error {
	if !a.cfg.Guardian.Enabled { return nil }
	a.guardian = guardian.NewGuardian(nil)
	return a.guardian.Start()
}

func (a *Agent) autoLoadProbes() {
	for _, pc := range a.cfg.Autoload {
		if !pc.Enabled { continue }
		a.loadProbeByName(pc.Name, pc.ID)
	}
}

func (a *Agent) loadProbeByName(name, id string) {
	a.probesMu.Lock()
	defer a.probesMu.Unlock()
	if _, exists := a.probes[id]; exists { return }
	inst, err := loader.LoadByName(name, func(event registry.Event) {
		a.eventQueue <- &pb.ProbeEvent{
			ProbeId: id, ProbeName: name, Timestamp: time.Now().Unix(),
			EventType: name, Pid: int32(event.PID), Comm: event.Comm,
			Filename: event.Filename, Details: event.Details,
		}
	})
	if err != nil { log.Printf("❌ 加载失败 [%s]: %v", name, err); return }
	a.probes[id] = inst
	log.Printf("✅ 探针已加载: %s (%s)", name, id)
}

func (a *Agent) loadProbe(cmd *pb.ProbeCommand) {
	a.loadProbeByName(cmd.ProbeName, cmd.ProbeId)
}

func (a *Agent) unloadProbe(probeID string) {
	a.probesMu.Lock(); defer a.probesMu.Unlock()
	inst, exists := a.probes[probeID]
	if !exists { return }
	inst.Stop()
	delete(a.probes, probeID)
	log.Printf("✅ 探针已卸载: %s", probeID)
}

func (a *Agent) activeProbeCount() int32 {
	a.probesMu.RLock(); defer a.probesMu.RUnlock()
	return int32(len(a.probes))
}

func (a *Agent) eventReporter() {
	ticker := time.NewTicker(3 * time.Second); defer ticker.Stop()
	batch := make([]*pb.ProbeEvent, 0, 100)
	for {
		select {
		case evt := <-a.eventQueue:
			batch = append(batch, evt)
			if len(batch) >= 50 { a.flushEvents(batch); batch = batch[:0] }
		case <-ticker.C:
			if len(batch) > 0 { a.flushEvents(batch); batch = batch[:0] }
		}
	}
}

func (a *Agent) flushEvents(events []*pb.ProbeEvent) {
	if a.client == nil || a.token == "" { return }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a.client.ReportEvents(ctx, &pb.EventReport{AgentId: a.id, AgentToken: a.token, Events: events})
}

func (a *Agent) buildRegisterRequest() *pb.RegisterRequest {
	fw := a.capabilities.Framework
	return &pb.RegisterRequest{
		AgentId: a.id, Hostname: a.hostname, KernelVersion: a.kernelVer, IpAddress: a.ipAddr,
		Framework: &pb.FrameworkInfo{
			BccAvailable: fw.BCCAvailable, LibbpfAvailable: fw.LibBPFAvailable, LibbpfCore: fw.LibBPFCORE,
			BpftraceAvailable: fw.BpftraceAvailable, ClangAvailable: fw.ClangAvailable,
			LlvmAvailable: fw.LLVMAvailable, KernelHeadersAvailable: fw.KernelHeadersAvailable, GoEbpfAvailable: fw.GoEBPFAvailable,
		},
		KernelInfo: &pb.KernelInfo{Version: a.capabilities.KernelVersion, Arch: a.capabilities.Arch, BtfEnabled: a.capabilities.BTFEnabled},
	}
}

func (a *Agent) Register() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second); defer cancel()
	resp, err := a.client.Register(ctx, a.buildRegisterRequest())
	if err != nil { return err }
	if !resp.Success { return fmt.Errorf("注册被拒绝") }
	a.token = resp.AgentToken
	log.Printf("✅ 注册成功! ID: %s", a.id)
	return nil
}

func (a *Agent) HeartbeatLoop() {
	for {
		stream, err := a.client.Heartbeat(context.Background())
		if err != nil { time.Sleep(a.cfg.Agent.RetryDelay); continue }
		log.Println("💓 心跳流已建立")
		go func() {
			ticker := time.NewTicker(a.cfg.Agent.HeartbeatInterval); defer ticker.Stop()
			for range ticker.C {
				stream.Send(&pb.HeartbeatRequest{AgentId: a.id, AgentToken: a.token, Timestamp: time.Now().Unix(), ActiveProbes: a.activeProbeCount()})
			}
		}()
		for {
			resp, err := stream.Recv()
			if err != nil { time.Sleep(a.cfg.Agent.RetryDelay); break }
			if resp.Success {
				for _, cmd := range resp.Commands {
					a.handleCommand(cmd)
				}
			}
		}
	}
}

func (a *Agent) handleCommand(cmd *pb.ProbeCommand) {
	switch cmd.Type {
	case pb.ProbeCommand_LOAD: a.loadProbe(cmd)
	case pb.ProbeCommand_UNLOAD: a.unloadProbe(cmd.ProbeId)
	}
}

func (a *Agent) Connect() error {
	conn, err := grpc.Dial(a.cfg.Agent.Server, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil { return err }
	a.conn = conn; a.client = pb.NewSentinelClient(conn)
	log.Printf("🔗 已连接: %s", a.cfg.Agent.Server)
	return nil
}

func (a *Agent) Start() {
	log.Printf("🛡️  eBPF Sentinel Agent  ID: %s", a.id)
	if err := a.RunProbe(); err != nil { log.Fatalf("❌ %v", err) }
	if err := a.startGuardian(); err != nil { log.Printf("⚠️ 守护: %v", err) }
	a.autoLoadProbes()
	for { if err := a.Connect(); err != nil { time.Sleep(a.cfg.Agent.RetryDelay); continue }; break }
	defer a.conn.Close()
	for { if err := a.Register(); err != nil { time.Sleep(a.cfg.Agent.RetryDelay); continue }; break }
	go a.eventReporter()
	a.HeartbeatLoop()
}

func main() {
	flag.Parse()
	if *listProbes {
		for _, m := range loader.ListProbes() { fmt.Printf("  %s - %s\n", m.Name, m.Description) }
		return
	}
	if *genConfig { config.GenerateDefault(*configPath); return }
	cfg, _ := config.Load(*configPath)
	agent := NewAgent(cfg)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigChan; if agent.guardian != nil { agent.guardian.Stop() }; os.Exit(0) }()
	agent.Start()
}

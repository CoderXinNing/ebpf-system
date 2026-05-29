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
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	configPath = flag.String("config", "agent/configs/agent.yaml", "配置文件路径")
	genConfig  = flag.Bool("gen-config", false, "生成默认配置文件")
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
	id         string
	hostname   string
	kernelVer  string
	ipAddr     string
	token      string
	cfg        *config.AgentConfig
	capabilities *probe.AgentCapabilities
	guardian   *guardian.Guardian
	probes     map[string]*loader.Probe
	probesMu   sync.RWMutex
	eventQueue chan *pb.ProbeEvent
	conn       *grpc.ClientConn
	client     pb.SentinelClient
}

func NewAgent(cfg *config.AgentConfig) *Agent {
	hostname := getHostname()
	if cfg.Agent.Name != "" {
		hostname = cfg.Agent.Name
	}
	return &Agent{
		id:         generateAgentID(hostname),
		hostname:   hostname,
		ipAddr:     getIPAddress(),
		cfg:        cfg,
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
	if !a.cfg.Guardian.Enabled {
		log.Println("🛡️  守护探针已禁用")
		return nil
	}
	a.guardian = guardian.NewGuardian(nil)
	return a.guardian.Start()
}

func (a *Agent) autoLoadProbes() {
	for _, pc := range a.cfg.Autoload {
		if !pc.Enabled {
			continue
		}
		cmd := &pb.ProbeCommand{
			Type:      pb.ProbeCommand_LOAD,
			ProbeId:   pc.ID,
			ProbeName: pc.Name,
		}
		if err := a.loadProbe(cmd); err != nil {
			log.Printf("⚠️ 自动加载失败 [%s]: %v", pc.Name, err)
		}
	}
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
		log.Printf("✅ 探针已加载: %s", cmd.ProbeName)
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
	log.Printf("✅ 探针已卸载: %s", probeID)
	return nil
}

func (a *Agent) activeProbeCount() int32 {
	a.probesMu.RLock()
	defer a.probesMu.RUnlock()
	return int32(len(a.probes))
}

func (a *Agent) eventReporter() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
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
	a.client.ReportEvents(ctx, &pb.EventReport{
		AgentId: a.id, AgentToken: a.token, Events: events,
	})
}

func (a *Agent) buildRegisterRequest() *pb.RegisterRequest {
	fw := a.capabilities.Framework
	return &pb.RegisterRequest{
		AgentId:       a.id,
		Hostname:      a.hostname,
		KernelVersion: a.kernelVer,
		IpAddress:     a.ipAddr,
		Framework: &pb.FrameworkInfo{
			BccAvailable: fw.BCCAvailable, LibbpfAvailable: fw.LibBPFAvailable, LibbpfCore: fw.LibBPFCORE,
			BpftraceAvailable: fw.BpftraceAvailable, ClangAvailable: fw.ClangAvailable,
			LlvmAvailable: fw.LLVMAvailable, KernelHeadersAvailable: fw.KernelHeadersAvailable,
			GoEbpfAvailable: fw.GoEBPFAvailable,
		},
		KernelInfo: &pb.KernelInfo{Version: a.capabilities.KernelVersion, Arch: a.capabilities.Arch, BtfEnabled: a.capabilities.BTFEnabled},
	}
}

func (a *Agent) Register() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := a.client.Register(ctx, a.buildRegisterRequest())
	if err != nil { return err }
	if !resp.Success { return fmt.Errorf("注册被拒绝") }
	a.token = resp.AgentToken
	log.Printf("✅ 注册成功! Agent ID: %s", a.id)
	return nil
}

func (a *Agent) HeartbeatLoop() {
	interval := a.cfg.Agent.HeartbeatInterval
	for {
		ctx := context.Background()
		stream, err := a.client.Heartbeat(ctx)
		if err != nil {
			log.Printf("⚠️ 心跳流建立失败: %v", err)
			time.Sleep(a.cfg.Agent.RetryDelay)
			continue
		}
		log.Println("💓 心跳流已建立")

		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for range ticker.C {
				stream.Send(&pb.HeartbeatRequest{
					AgentId: a.id, AgentToken: a.token,
					Timestamp: time.Now().Unix(), ActiveProbes: a.activeProbeCount(),
				})
			}
		}()

		for {
			resp, err := stream.Recv()
			if err != nil {
				log.Printf("⚠️ 心跳流断开: %v", err)
				time.Sleep(a.cfg.Agent.RetryDelay)
				break
			}
			if resp.Success && len(resp.Commands) > 0 {
				for _, cmd := range resp.Commands {
					a.handleCommand(cmd)
				}
			}
		}
	}
}

func (a *Agent) handleCommand(cmd *pb.ProbeCommand) {
	switch cmd.Type {
	case pb.ProbeCommand_LOAD:
		log.Printf("📥 收到加载指令: %s (%s)", cmd.ProbeName, cmd.ProbeId)
		a.loadProbe(cmd)
	case pb.ProbeCommand_UNLOAD:
		log.Printf("📤 收到卸载指令: %s", cmd.ProbeId)
		a.unloadProbe(cmd.ProbeId)
	}
}

func (a *Agent) Connect() error {
	var err error
	a.conn, err = grpc.Dial(a.cfg.Agent.Server,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil { return err }
	a.client = pb.NewSentinelClient(a.conn)
	log.Printf("🔗 已连接: %s", a.cfg.Agent.Server)
	return nil
}

func (a *Agent) Start() {
	log.Printf("🛡️  eBPF Sentinel Agent")
	log.Printf("   ID: %s  主机: %s  配置: %s", a.id, a.hostname, *configPath)

	if err := a.RunProbe(); err != nil { log.Fatalf("❌ %v", err) }
	if err := a.startGuardian(); err != nil { log.Printf("⚠️ 守护探针: %v", err) }

	a.autoLoadProbes()

	for {
		if err := a.Connect(); err != nil {
			log.Printf("❌ %v", err)
			time.Sleep(a.cfg.Agent.RetryDelay)
			continue
		}
		break
	}
	defer a.conn.Close()

	for {
		if err := a.Register(); err != nil {
			log.Printf("❌ %v", err)
			time.Sleep(a.cfg.Agent.RetryDelay)
			continue
		}
		break
	}

	go a.eventReporter()
	a.HeartbeatLoop()
}

func main() {
	flag.Parse()

	if *genConfig {
		if err := config.GenerateDefault(*configPath); err != nil {
			log.Fatalf("生成配置失败: %v", err)
		}
		fmt.Printf("✅ 默认配置已生成: %s\n", *configPath)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	agent := NewAgent(cfg)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("\n🛑 退出...")
		if agent.guardian != nil { agent.guardian.Stop() }
		os.Exit(0)
	}()

	agent.Start()
}

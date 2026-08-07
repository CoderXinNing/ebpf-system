package agent

import (
	"context"
	"fmt"
	"log"
	"time"
	"net"

	"github.com/CoderXinNing/ebpf-system/agent/internal/config"
	"github.com/CoderXinNing/ebpf-system/agent/internal/collector"
	"github.com/CoderXinNing/ebpf-system/agent/internal/ebpf"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const AgentVersion = "1.0.0"

type Agent struct {
	id, hostname, kernelVer, ipAddr, token string
	cfg          *config.AgentConfig
	capabilities *probe.AgentCapabilities
	eventQueue   chan *pb.ProbeEvent
	conn         *grpc.ClientConn
	client       pb.SentinelClient
}

func New(cfg *config.AgentConfig) *Agent {
	hostname := getHostname()
	if cfg.Agent.Name != "" {
		hostname = cfg.Agent.Name
	}
	return &Agent{
		id:         generateAgentID(hostname),
		hostname:   hostname,
		ipAddr:     getIPAddress(),
		cfg:        cfg,
		eventQueue: make(chan *pb.ProbeEvent, 1000),
	}
}

func (a *Agent) Init() error {
	caps, err := probe.Detect()
	if err != nil {
		return fmt.Errorf("环境探测失败: %w", err)
	}
	a.capabilities = caps
	a.kernelVer = caps.KernelVersion
	fmt.Print(caps.Summary())



	return nil
}

func (a *Agent) Run() {
	// XDP测试
	go func() {
		time.Sleep(5 * time.Second)
		cfg := ebpf.XDPConfig{
			SrcIP:   net.ParseIP("172.16.2.141"),
			DstIP:   net.ParseIP("172.16.2.141"),
			SrcPort: 12345,
			DstPort: 9999,
			SrcMAC:  net.HardwareAddr{0x00, 0x0c, 0x29, 0x35, 0xea, 0xfa},
			DstMAC:  net.HardwareAddr{0x00, 0x0c, 0x29, 0x35, 0xea, 0xfa},
			Iface:   "ens33",
		}
		if _, err := ebpf.LoadXDPReporter(cfg); err != nil {
			log.Printf("⚠️ XDP加载失败: %v", err)
		}
	}()
	log.Printf("🛡️  eBPF Sentinel Agent  ID: %s", a.id)
	// 采集测试
	jars := collector.CollectJarPackages()
	log.Printf("Jar包: %d个", len(jars))
	pyPkgs := collector.CollectPythonPackages()
	log.Printf("Python包: %d个", len(pyPkgs))
	npmPkgs := collector.CollectNpmPackages()
	log.Printf("Npm包: %d个", len(npmPkgs))
	svcs := collector.CollectServiceStatus()
	log.Printf("服务状态: %d个", len(svcs))

	a.connectAndRegister()
	go a.eventReporter()
	// 首次采集
	go func() {
		time.Sleep(3 * time.Second)
		a.collectAndReportAssets()
	}()
	// 定期采集
	go func() {
		ticker := time.NewTicker(a.cfg.Agent.CollectInterval)
		defer ticker.Stop()
		for range ticker.C {
			a.collectAndReportAssets()
		}
	}()

	a.runHeartbeatLoop()
}

func (a *Agent) connectAndRegister() {
	for {
		conn, err := grpc.Dial(a.cfg.Agent.Server,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		if err != nil {
			log.Printf("❌ 连接失败: %v", err)
			time.Sleep(a.cfg.Agent.RetryDelay)
			continue
		}

		if a.conn != nil {
			a.conn.Close()
		}
		a.conn = conn
		a.client = pb.NewSentinelClient(conn)
		log.Printf("🔗 已连接: %s", a.cfg.Agent.Server)

		if err := a.register(); err != nil {
			log.Printf("❌ %v", err)
			time.Sleep(a.cfg.Agent.RetryDelay)
			continue
		}
		break
	}
}

func (a *Agent) register() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fw := a.capabilities.Framework
	req := &pb.RegisterRequest{
		AgentId: a.id, Hostname: a.hostname, KernelVersion: a.kernelVer, IpAddress: a.ipAddr,
		AgentVersion: AgentVersion,
		Framework: &pb.FrameworkInfo{
			BccAvailable: fw.BCCAvailable, LibbpfAvailable: fw.LibBPFAvailable, LibbpfCore: fw.LibBPFCORE,
			BpftraceAvailable: fw.BpftraceAvailable, ClangAvailable: fw.ClangAvailable,
			LlvmAvailable: fw.LLVMAvailable, KernelHeadersAvailable: fw.KernelHeadersAvailable, GoEbpfAvailable: fw.GoEBPFAvailable,
		},
		KernelInfo: &pb.KernelInfo{Version: a.capabilities.KernelVersion, Arch: a.capabilities.Arch, BtfEnabled: a.capabilities.BTFEnabled},
	}

	resp, err := a.client.Register(ctx, req)
	if err != nil {
		return fmt.Errorf("注册失败: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("注册被拒绝")
	}
	a.token = resp.AgentToken
	log.Printf("✅ 注册成功! ID: %s", a.id)
	return nil
}

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
	a.client.ReportEvents(ctx, &pb.EventReport{AgentId: a.id, AgentToken: a.token, Events: events})
}

func (a *Agent) Shutdown() {
	if a.conn != nil {
		a.conn.Close()
	}
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

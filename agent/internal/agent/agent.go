package agent

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/CoderXinNing/ebpf-system/agent/internal/config"
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

	// 降级决策
	level := a.decideLevel()
	log.Printf("🔍 环境级别: %s", level)

	switch level {
	case "full":
		go a.startXDP()
		fallthrough
	case "ebpf":
		go a.startExecMonitor()
		go a.startBashMonitor()
		go a.startTCPMonitor()
		fallthrough
	case "basic":
		log.Println("✅ Agent运行在基础模式（纯CMDB采集）")
	case "none":
		return fmt.Errorf("环境不支持任何功能")
	}

	return nil
}

func (a *Agent) decideLevel() string {
	caps := a.capabilities
	cfg := a.cfg

	if caps.BTFEnabled && caps.Framework.GoEBPFAvailable {
		if cfg.XDP.Enabled {
			return "full"
		}
		return "ebpf"
	}

	if caps.Framework.LibBPFAvailable {
		return "ebpf"
	}

	return "basic"
}

func (a *Agent) Run() {
	log.Printf("🛡️  eBPF Sentinel Agent  ID: %s", a.id)

	// 信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		log.Printf("🛑 收到信号 %v，正常退出...", sig)
		a.Shutdown()
		os.Exit(0)
	}()

	a.connectAndRegister()
	go a.eventReporter()
	go func() {
		time.Sleep(3 * time.Second)
		a.collectAndReportAssets()
	}()
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
			if len(batch) >= 1 {
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
	resp, err := a.client.ReportEvents(ctx, &pb.EventReport{AgentId: a.id, AgentToken: a.token, Events: events})
	if err != nil {
		log.Printf("⚠️ 事件上报失败: %v", err)
	} else if !resp.Success {
		log.Printf("⚠️ 事件上报被拒绝")
	}
}

func (a *Agent) Shutdown() {
	log.Println("🧹 清理资源...")
	if xdpHandle != nil {
		xdpHandle.Close()
	}
	if a.conn != nil {
		a.conn.Close()
	}
	// FD 由内核在进程退出时自动清理
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func updateHeartbeatMap() {
	hbMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/ebpf-sentinel/agent_heartbeat", nil)
	if err != nil {
		return
	}
	defer hbMap.Close()
	var key uint32 = 0
	var val uint64 = uint64(time.Now().UnixNano())
	hbMap.Put(&key, &val)
}


func (a *Agent) getProbePath(name string) string {
	for _, p := range a.cfg.Autoload {
		if p.Name == name && p.Path != "" {
			return p.Path
		}
	}
	// 默认路径
	paths := map[string]string{
		"exec_monitor": "probes/templates/exec_monitor_ebpf/exec_monitor.o",
	}
	return paths[name]
}

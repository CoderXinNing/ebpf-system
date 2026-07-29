package agent

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"github.com/CoderXinNing/ebpf-system/agent/internal/config"
	"github.com/CoderXinNing/ebpf-system/agent/internal/guardian"
	"github.com/CoderXinNing/ebpf-system/agent/internal/loader"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Agent struct {
	id, hostname, kernelVer, ipAddr, token string
	cfg          *config.AgentConfig
	capabilities *probe.AgentCapabilities
	guardian     *guardian.Guardian
	pluginMgr    *loader.PluginManager
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

	if a.cfg.Guardian.Enabled {
		a.guardian = guardian.NewGuardian(nil)
		if err := a.guardian.Start(); err != nil {
			log.Printf("⚠️ 守护探针: %v", err)
		}
	}

	a.pluginMgr = loader.NewPluginManager("/opt/ebpf-sentinel/probes", func(name string, raw []byte) {
		var pid uint32
		var comm, filename string
		if len(raw) >= 92 {
			pid = binary.LittleEndian.Uint32(raw[0:4])
			comm = cstring(raw[12:28])
			filename = cstring(raw[28:92])
		}
		a.eventQueue <- &pb.ProbeEvent{
			ProbeId: name, ProbeName: name, Timestamp: time.Now().Unix(),
			EventType: "plugin", Pid: int32(pid), Comm: comm, Filename: filename,
		}
	})
	a.pluginMgr.ScanAndLoad()

	return nil
}

func (a *Agent) Run() {
	log.Printf("🛡️  eBPF Sentinel Agent  ID: %s", a.id)

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

	a.HeartbeatLoop()
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
	if a.guardian != nil {
		a.guardian.Stop()
	}
	if a.pluginMgr != nil {
		a.pluginMgr.Close()
	}
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

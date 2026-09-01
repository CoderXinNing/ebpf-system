package agent

import (
	"context"
	"strings"
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
	level        string
	cfg          *config.AgentConfig
	capabilities *probe.AgentCapabilities
	eventQueue   chan *pb.ProbeEvent
	conn         *grpc.ClientConn
	client       pb.SentinelClient
	probeStatus  map[string]string // probe_name -> "loaded" / "failed: reason"
	probePaths   map[string]string // probe_name -> path from Server
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
		probeStatus: make(map[string]string),
		probePaths:  make(map[string]string),
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

	// 降级决策先确定环境能力，但探针加载延后到注册后查名单
	level := a.decideLevel()
	log.Printf("🔍 环境级别: %s", level)
	a.level = level

	if level == "none" {
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

	if err := a.connectAndRegister(); err != nil {
		log.Println("⚠️ Server不可达，进入离线保命模式")
		// 后台重试连接（指数退避）
		go a.retryConnectLoop()
	} else {
		// 注册后查询探针名单
		probes := a.fetchProbeList()
		if probes == nil {
			log.Println("⚠️ 名单查询失败，不加载探针")
		} else {
			a.loadProbesByList(probes)
		}
	}

	go a.eventReporter()
	go func() {
		time.Sleep(3 * time.Second)
		a.collectAndReportAssets()
	}()
	go func() {
		interval := a.cfg.Agent.CollectInterval
		if a.client == nil {
			interval = 1 * time.Hour  // 离线时降频
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			a.collectAndReportAssets()
		}
	}()

	a.runHeartbeatLoop()
}

func (a *Agent) connectAndRegister() error {
	for {
		dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := grpc.DialContext(dialCtx, a.cfg.Agent.Server,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		cancel()
		if err != nil {
			log.Printf("❌ 连接失败: %v", err)
			return err
		}

		if a.conn != nil {
			a.conn.Close()
		}
		a.conn = conn
		a.client = pb.NewSentinelClient(conn)
		log.Printf("🔗 已连接: %s", a.cfg.Agent.Server)

		if err := a.register(); err != nil {
			log.Printf("❌ %v", err)
			return err
		}
		return nil
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
		log.Println("⚠️ Server未连接，跳过事件上报")
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
	// 按配置清理探针 pin（remove=true 的才清理）
	pinBase := "/sys/fs/bpf/ebpf-sentinel"
	for _, p := range a.cfg.Autoload {
		if !p.Remove {
			log.Printf("ℹ️ %s remove=false，保留 pin", p.Name)
			continue
		}
		log.Printf("🧹 清理 %s pin", p.Name)
		os.RemoveAll(pinBase + "/" + p.Name + "_prog")
		os.RemoveAll(pinBase + "/" + p.Name + "_events")
		os.RemoveAll(pinBase + "/" + p.Name + "_exec_whitelist")
		os.RemoveAll(pinBase + "/" + p.Name + "_agent_heartbeat")
		os.RemoveAll(pinBase + "/" + p.Name + "_tcp_conn_stats")
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
	// 优先从 Server 名单拿
	if path, ok := a.probePaths[name]; ok && path != "" {
		return path
	}
	for _, p := range a.cfg.Autoload {
		if p.Name == name && p.Path != "" {
			return p.Path
		}
	}
	// 默认路径
	paths := map[string]string{
		"exec_monitor": "probes/templates/exec_monitor_ebpf/exec_monitor.o",
		"bash_monitor": "probes/templates/bash_monitor/bash_monitor.o",
		"tcp_monitor":  "probes/templates/tcp_monitor/tcp_monitor.o",
	}
	return paths[name]
}


func (a *Agent) isProbeEnabled(name string) bool {
	for _, p := range a.cfg.Autoload {
		if p.Name == name {
			return p.Enabled
		}
	}
	return false
}


func (a *Agent) fetchProbeList() []*pb.ProbeInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := a.client.GetProbeList(ctx, &pb.ProbeListRequest{
		AgentId:    a.id,
		AgentToken: a.token,
	})
	if err != nil {
		log.Printf("⚠️ 查询探针名单失败: %v", err)
		return nil
	}
	if !resp.Success {
		log.Printf("⚠️ 探针名单查询被拒绝: %s", resp.Message)
		return nil
	}
	log.Printf("📋 收到探针名单: %d个", len(resp.Probes))
	return resp.Probes
}

func (a *Agent) loadProbesByList(probes []*pb.ProbeInfo) {
	for _, p := range probes {
		if !p.Enabled {
			log.Printf("🚫 %s 名单中未启用，跳过", p.Name)
			a.probeStatus[p.Name] = "disabled"
			continue
		}
		log.Printf("▶️ 加载探针: %s", p.Name)
		a.probePaths[p.Name] = p.Path
		switch p.Name {
		case "exec_monitor":
			a.probeStatus[p.Name] = "loading"
			go a.startExecMonitorWithStatus(p.Name)
		case "bash_monitor":
			a.probeStatus[p.Name] = "loading"
			go a.startBashMonitorWithStatus(p.Name)
		case "tcp_monitor":
			a.probeStatus[p.Name] = "loading"
			go a.startTCPMonitorWithStatus(p.Name)
		case "xdp_reporter":
			if a.level == "full" {
				a.probeStatus[p.Name] = "loading"
				go a.startXDP()
			} else {
				a.probeStatus[p.Name] = "skipped: xdp not available"
			}
		default:
			a.probeStatus[p.Name] = "unknown probe"
			log.Printf("⚠️ 未知探针: %s", p.Name)
		}
	}
}


func (a *Agent) retryConnectLoop() {
	backoff := []time.Duration{3, 6, 12, 30, 60}
	idx := 0
	for {
		wait := backoff[idx]
		if idx < len(backoff)-1 {
			idx++
		}
		time.Sleep(wait * time.Second)
		log.Printf("🔄 尝试重连 Server (间隔 %ds)...", int(wait.Seconds()))
		if err := a.connectAndRegister(); err != nil {
			log.Printf("⚠️ 重连失败: %v", err)
			continue
		}
		log.Println("✅ 重连成功！")
		// 重连后加载探针
		probes := a.fetchProbeList()
		if probes != nil {
			a.loadProbesByList(probes)
		}
		// 补报资产
		a.collectAndReportAssets()
		return
	}
}


func (a *Agent) startExecMonitorWithStatus(name string) {
	defer func() {
		if r := recover(); r != nil {
			a.probeStatus[name] = fmt.Sprintf("failed: %v", r)
			log.Printf("❌ %s 加载失败: %v", name, r)
		}
	}()
	a.startExecMonitor()
	a.probeStatus[name] = "loaded"
}

func (a *Agent) startBashMonitorWithStatus(name string) {
	if err := a.startBashMonitor(); err != nil {
		a.probeStatus[name] = fmt.Sprintf("failed: %v", err)
		log.Printf("❌ %s 加载失败: %v", name, err)
		return
	}
	a.probeStatus[name] = "loaded"
}

func (a *Agent) startTCPMonitorWithStatus(name string) {
	defer func() {
		if r := recover(); r != nil {
			a.probeStatus[name] = fmt.Sprintf("failed: %v", r)
			log.Printf("❌ %s 加载失败: %v", name, r)
		}
	}()
	a.startTCPMonitor()
	a.probeStatus[name] = "loaded"
}


func (a *Agent) getProbeDetailsJSON() string {
	if len(a.probeStatus) == 0 {
		return "{}"
	}
	parts := make([]string, 0, len(a.probeStatus))
	for name, status := range a.probeStatus {
		parts = append(parts, fmt.Sprintf(`"%s":"%s"`, name, status))
	}
	return "{" + strings.Join(parts, ",") + "}"
}



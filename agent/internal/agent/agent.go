package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/CoderXinNing/ebpf-system/agent/internal/actor"
	"github.com/CoderXinNing/ebpf-system/agent/internal/baseline"
	"github.com/CoderXinNing/ebpf-system/agent/internal/config"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/framework"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/plugins"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
	"crypto/tls"
	"crypto/x509"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

const AgentVersion = "1.0.0"

type Agent struct {
	id, hostname, kernelVer, ipAddr, token string
	level        string
	cfg          *config.AgentConfig
	capabilities *probe.AgentCapabilities
	conn         *grpc.ClientConn
	client       pb.SentinelClient

	// 并发安全组件
	probeStateActor *actor.Actor      // 状态收敛
	probeState      *ProbeState       // 缓存引用（只读，心跳非阻塞用）
	eventQueue      *EventQueue       // 非阻塞事件队列
	baseline        *baseline.BaselineEngine
	probeManager    *framework.Manager // 探针管理器

	// gRPC Metadata（token 鉴权）
	authContext context.Context

	// 星轨激活状态
	starCorrelationID string
	starMode          string

	// TCP 突变检测
	tcpAnomaly *TCPAnomalyDetector

	// 身份基线
	identityBaseline *IdentityBaseline

	// V3 星轨关联管理器
	correlationManager *CorrelationManager
}

func New(cfg *config.AgentConfig) *Agent {
	hostname := getHostname()
	if cfg.Agent.Name != "" {
		hostname = cfg.Agent.Name
	}
	baselineEngine := baseline.NewBaselineEngine("agent/configs/baseline.toml")

	probeState := newProbeState(baselineEngine)
	agent := &Agent{
		id:         generateAgentID(hostname),
		hostname:   hostname,
		ipAddr:     getIPAddress(),
		cfg:        cfg,
		probeState: probeState,
		eventQueue: NewEventQueue(100, 1000),
		baseline:   baselineEngine,
	}

	// 创建 ProbeStateActor
	agent.probeStateActor = actor.New(
		probeStateHandler,
		probeState,
		actor.ActorConfig{InboxSize: 1000},
	)
	agent.probeStateActor.Start()

	// 初始化探针管理器并注册插件
	agent.probeManager = framework.NewManager()
	agent.registerProbePlugins()

	// 初始化身份基线（学习期从 baseline.toml 读取）
	learningMinutes := 1
	if baselineEngine != nil {
		learningMinutes = baselineEngine.GetLearningMinutes()
	}
	agent.identityBaseline = NewIdentityBaseline(time.Duration(learningMinutes) * time.Minute)

	// 初始化星轨关联管理器（10 分钟 TTL）
	agent.correlationManager = NewCorrelationManager(agent.id, 10*time.Minute)

	// 初始化 TCP 突变检测器（默认配置，后续从配置文件读取）
	agent.tcpAnomaly = NewTCPAnomalyDetector(
		60, // 窗口秒数
		3,  // 端口阈值
		4,  // IP阈值
		[]uint16{22, 3389, 445, 21, 1433, 3306, 6379, 5985, 8080, 8443},
	)

	agent.baseline.Restore()
	return agent
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

func (a *Agent) Run(ctx context.Context) {
	log.Printf("🛡️  eBPF Sentinel Agent  ID: %s", a.id)

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
			interval = 1 * time.Hour // 离线时降频
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			a.collectAndReportAssets()
		}
	}()

	// 基线窗口定时器（每分钟汇总）
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			a.flushBaselineWindow()
		}
	}()

	// 基线持久化（每5分钟）
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			a.baseline.Persist()
		}
	}()

	// TCP 突变检测循环
	go a.tcpAnomalyLoop(ctx)

	// 心跳循环（阻塞直到 ctx 被取消）
	a.runHeartbeatLoopWithCtx(ctx)
}

func (a *Agent) connectAndRegister() error {
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// mTLS 配置：加载 CA + 客户端证书
	caCert, err := os.ReadFile("certs/ca.crt")
	if err != nil {
		log.Printf("⚠️ 读取 CA 证书失败: %v", err)
		return err
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		log.Printf("⚠️ 解析 CA 证书失败")
		return fmt.Errorf("解析 CA 证书失败")
	}

	clientCert, err := tls.LoadX509KeyPair("certs/agent.crt", "certs/agent.key")
	if err != nil {
		log.Printf("⚠️ 加载客户端证书失败: %v", err)
		return err
	}

	tlsConfig := &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientCert},
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	}
	tlsCreds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.DialContext(dialCtx, a.cfg.Agent.Server,
		grpc.WithTransportCredentials(tlsCreds),
		grpc.WithBlock(),
	)
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
	// 创建带 token 的 Metadata context
	a.authContext = metadata.NewOutgoingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+a.token))
	log.Printf("✅ 注册成功! ID: %s", a.id)
	return nil
}

func (a *Agent) eventReporter() {
	log.Println("🔄 eventReporter 启动")
	consumeCh := a.eventQueue.Consume()
	batch := make([]*pb.ProbeEvent, 0, 100)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case evt := <-consumeCh:
			if evt == nil {
				// channel 已关闭，退出
				return
			}
			log.Printf("📥 收到事件: %s PID=%d", evt.ProbeName, evt.Pid)
			batch = append(batch, evt)
			if len(batch) >= 100 {
				a.flushEvents(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			log.Printf("⏰ ticker 触发, batch=%d", len(batch))
			if len(batch) > 0 {
				a.flushEvents(batch)
				batch = batch[:0]
			}
			// 定期输出队列统计
			stats := a.eventQueue.Stats()
			if stats.DroppedHigh > 0 || stats.DroppedLow > 0 {
				log.Printf("📊 事件队列: 高优先丢弃=%d 低优先丢弃=%d 高优先总数=%d 低优先总数=%d",
					stats.DroppedHigh, stats.DroppedLow, stats.TotalHigh, stats.TotalLow)
			}
		}
	}
}

func (a *Agent) flushEvents(events []*pb.ProbeEvent) {
	log.Printf("🔄 flushEvents 被调用: %d 个事件", len(events))
	if a.client == nil || a.token == "" {
		log.Println("⚠️ Server未连接，跳过事件上报")
		return
	}
	log.Printf("🔗 client 正常，准备上报...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := a.client.ReportEvents(a.getAuthContext(ctx), &pb.EventReport{
		AgentId:       a.id,
		Events:        events,
		CorrelationId: a.starCorrelationID,
	})
	if err != nil {
		log.Printf("⚠️ 事件上报失败: %v", err)
	} else if !resp.Success {
		log.Printf("⚠️ 事件上报被拒绝")
	}
}

func (a *Agent) Shutdown() {
	log.Println("🧹 清理资源...")

	// 停止事件队列
	a.eventQueue.Stop()

	// 停止 ProbeStateActor
	a.probeStateActor.Stop()

	// 通知 Server 正常下线
	if a.client != nil && a.token != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		a.client.ReportShutdown(a.getAuthContext(ctx), &pb.ShutdownRequest{
			AgentId: a.id,
		})
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
	hbMap, err := ciliumebpf.LoadPinnedMap("/sys/fs/bpf/ebpf-sentinel/agent_heartbeat", nil)
	if err != nil {
		return
	}
	defer hbMap.Close()
	var key uint32 = 0
	var val uint64 = uint64(time.Now().UnixNano())
	hbMap.Put(&key, &val)
}

// getAuthContext 返回带 token 的 context，如果 authContext 未设置则使用传入的 ctx
func (a *Agent) getAuthContext(fallback context.Context) context.Context {
	if a.authContext != nil {
		return a.authContext
	}
	return fallback
}

func (a *Agent) getProbePath(name string) string {
	// 路径是相对静态的，直接从配置读，不走 Actor
	for _, p := range a.cfg.Autoload {
		if p.Name == name && p.Path != "" {
			return p.Path
		}
	}
	// 默认路径
	paths := map[string]string{
		"exec_monitor": "probes/new/exec_monitor/exec_monitor.o",
		"bash_monitor": "probes/new/bash_monitor/bash_monitor.o",
		"tcp_monitor":  "probes/new/tcp_monitor/tcp_monitor.o",
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

	resp, err := a.client.GetProbeList(a.getAuthContext(ctx), &pb.ProbeListRequest{
		AgentId: a.id,
	})
	if err != nil {
		log.Printf("⚠️ 查询探针名单失败: %v", err)
		return nil
	}
	if !resp.Success {
		log.Printf("⚠️ 探针名单查询被拒绝: %s", resp.Message)
		return nil
	}
	log.Printf("📋 收到探针名单: %d个 (误报特征%d个)", len(resp.Probes), len(resp.FalsePositiveFeatures))
	for _, fp := range resp.FalsePositiveFeatures {
		a.probeStateActor.Send(msgAddFalsePositive{feature: fp})
	}
	return resp.Probes
}

// registerProbePlugins 注册所有探针插件
func (a *Agent) registerProbePlugins() {
	agentHash := generateAgentHash(a.id)

	// V3 exec 探针
	a.probeManager.Register(plugins.NewExecProbe(
		"v3_engine/probes/exec_monitor.o",
		agentHash,
		func(pid uint32, comm string, cmdline string, correlationKey uint64) {
			a.handleExecEventV3(pid, comm, cmdline, correlationKey)
		},
	))

	// V3 TCP 探针
	a.probeManager.Register(plugins.NewTCPProbe(
		"v3_engine/probes/tcp_monitor.o",
		agentHash,
		func(pid uint32, comm string, count uint64) {
			a.handleTCPEvent(pid, comm, count)
		},
	))
}

// handleExecEvent 处理 exec 探针事件
// handleBashEvent 处理 bash 探针事件
// handleTCPEvent 处理 tcp 探针事件
func (a *Agent) handleExecEventV3(pid uint32, comm string, cmdline string, correlationKey uint64) {
	// 生成或复用 local_correlation_id
	var localCorrID string
	if correlationKey != 0 && a.correlationManager != nil {
		localCorrID = a.correlationManager.GetOrCreate(correlationKey)
	}

	// 上报事件
	a.eventQueue.Push(&pb.ProbeEvent{
		ProbeName:       "execve",
		Timestamp:       time.Now().Unix(),
		EventType:       "execve",
		Pid:             int32(pid),
		Comm:            comm,
		Filename:        "execve",
		Details:         cmdline,
		CorrelationKey:  correlationKey,
		CorrelationId:   localCorrID,
	}, PriorityNormal)

	if localCorrID != "" {
		log.Printf("⭐ 事件已关联: PID=%d corrID=%s", pid, localCorrID)
	}
}

func (a *Agent) handleTCPEvent(pid uint32, comm string, count uint64) {
	a.probeStateActor.Send(msgIncrementBaseline{key: strings.TrimRight(comm, "\x00") + ":tcp_count"})
	a.eventQueue.Push(&pb.ProbeEvent{
		ProbeName: "tcp_connect",
		Timestamp: time.Now().Unix(),
		EventType: "tcp_connect",
		Pid:       int32(pid),
		Comm:      strings.TrimRight(comm, "\x00"),
		Filename:  fmt.Sprintf("外联x%d次", count),
	}, PriorityNormal)
}

// handleXDPEvent 处理 XDP 事件
func (a *Agent) loadProbesByList(probes []*pb.ProbeInfo) {
	for _, p := range probes {
		if !p.Enabled {
			log.Printf("🚫 %s 名单中未启用，跳过", p.Name)
			a.probeStateActor.Send(msgSetProbeStatus{name: p.Name, status: "disabled"})
			continue
		}

		// SHA256 完整性校验
		if p.Sha256 != "" {
			localHash, err := calculateFileSHA256(p.Path)
			if err != nil {
				log.Printf("❌ %s 读取失败: %v", p.Name, err)
				a.probeStateActor.Send(msgSetProbeStatus{name: p.Name, status: "failed: 文件读取失败"})
				continue
			}
			if localHash != p.Sha256 {
				log.Printf("❌ %s SHA256不匹配！本地=%s 期望=%s", p.Name, localHash[:16], p.Sha256[:16])
				a.probeStateActor.Send(msgSetProbeStatus{name: p.Name, status: "failed: SHA256不匹配"})
				continue
			}
			log.Printf("✅ %s SHA256校验通过", p.Name)
		}

		log.Printf("▶️ 加载探针: %s", p.Name)
		a.probeStateActor.Send(msgSetProbePath{name: p.Name, path: p.Path})

		// 通过 Manager 启动探针
		probeInst, exists := a.probeManager.Get(p.Name)
		if !exists {
			a.probeStateActor.Send(msgSetProbeStatus{name: p.Name, status: "unknown probe"})
			log.Printf("⚠️ 未知探针: %s", p.Name)
			continue
		}

		a.probeStateActor.Send(msgSetProbeStatus{name: p.Name, status: "loading"})
		go func(name string, p framework.Probe) {
			defer func() {
				if r := recover(); r != nil {
					a.probeStateActor.Send(msgSetProbeStatus{name: name, status: fmt.Sprintf("failed: %v", r)})
				}
			}()
			if err := a.probeManager.Start(context.Background(), name); err != nil {
				a.probeStateActor.Send(msgSetProbeStatus{name: name, status: fmt.Sprintf("failed: %v", err)})
				log.Printf("❌ %s 加载失败: %v", name, err)
				return
			}
			a.probeStateActor.Send(msgSetProbeStatus{name: name, status: "loaded"})
		}(p.Name, probeInst)
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

func (a *Agent) getActiveProbeCount() int32 {
	return a.probeState.GetActiveProbeCount()
}

func (a *Agent) getProbeDetailsJSON() string {
	return a.probeState.GetProbeStatusJSON()
}

func (a *Agent) flushBaselineWindow() {
	events, err := a.probeStateActor.Ask(msgFlushBaselineWindow{ipAddr: a.ipAddr}, 500*time.Millisecond)
	if err != nil {
		log.Printf("⚠️ 基线窗口刷新超时: %v", err)
		return
	}
	if events == nil {
		return
	}
	eventList := events.([]*pb.ProbeEvent)
	for _, evt := range eventList {
		result := a.eventQueue.Push(evt, PriorityHigh)
		if result == actor.Full {
			log.Printf("⚠️ 基线异常事件被丢弃（队列满）")
		}
	}
}

func calculateFileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// tcpAnomalyLoop 定期分析 TCP 连接突变
func (a *Agent) tcpAnomalyLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.analyzeTCPAnomalies()
		}
	}
}

// analyzeTCPAnomalies 从 BPF Map 读连接统计并检测突变
func (a *Agent) analyzeTCPAnomalies() {
	log.Printf("🔍 V3 TCP 突变检测待适配")
}

package main

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/CoderXinNing/ebpf-system/agent/internal/config"
	"github.com/CoderXinNing/ebpf-system/agent/internal/collector"
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

func getHostname() string { name, _ := os.Hostname(); return name }
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
	cfg          *config.AgentConfig
	capabilities *probe.AgentCapabilities
	guardian     *guardian.Guardian
	pluginMgr    *loader.PluginManager
	eventQueue   chan *pb.ProbeEvent
	conn         *grpc.ClientConn
	client       pb.SentinelClient
}

func NewAgent(cfg *config.AgentConfig) *Agent {
	hostname := getHostname()
	if cfg.Agent.Name != "" { hostname = cfg.Agent.Name }
	return &Agent{
		id: generateAgentID(hostname), hostname: hostname, ipAddr: getIPAddress(), cfg: cfg,
		eventQueue: make(chan *pb.ProbeEvent, 1000),
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

func (a *Agent) initPluginMgr() {
	a.pluginMgr = loader.NewPluginManager("/opt/ebpf-sentinel/probes", func(name string, raw []byte) {
		var pid uint32; var comm, filename string
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
		if err != nil {
			log.Printf("⚠️ 心跳流建立失败: %v", err)
			time.Sleep(a.cfg.Agent.RetryDelay)
			continue
		}
		log.Println("💓 心跳流已建立")

		done := make(chan struct{})
		go func() {
			ticker := time.NewTicker(a.cfg.Agent.HeartbeatInterval)
			defer ticker.Stop()
			for {
				select {
				case <-done: return
				case <-ticker.C:
					stream.Send(&pb.HeartbeatRequest{
						AgentId: a.id, AgentToken: a.token,
						Timestamp: time.Now().Unix(),
						ActiveProbes: int32(len(a.pluginMgr.ListPlugins())),
					})
				}
			}
		}()

		for {
			resp, err := stream.Recv()
			if err != nil { close(done); break }
			if resp.Success && len(resp.Commands) > 0 {
				for _, cmd := range resp.Commands {
					a.handleCommand(cmd)
				}
			}
		}
		time.Sleep(a.cfg.Agent.RetryDelay)
	}
}

func (a *Agent) handleCommand(cmd *pb.ProbeCommand) {
	switch cmd.Type {
	case pb.ProbeCommand_LOAD:
		log.Printf("📥 Server指令: 加载 %s", cmd.ProbeName)
		a.pluginMgr.LoadSingle(cmd.ProbeName)
	case pb.ProbeCommand_UNLOAD:
		log.Printf("📤 Server指令: 卸载 %s", cmd.ProbeName)
		a.pluginMgr.Unload(cmd.ProbeName)
	case pb.ProbeCommand_RELOAD:
		log.Println("🔄 Server指令: 重新扫描")
		a.pluginMgr.ScanAndLoad()
	case pb.ProbeCommand_INSTALL:
		log.Printf("📦 Server指令: 安装 %s", cmd.ProbeName)
		a.pluginMgr.InstallProbe(cmd.ProbeName, cmd.ProbeData, cmd.ProbeConfig)
	}
}

func (a *Agent) Connect() error {
	conn, err := grpc.Dial(a.cfg.Agent.Server,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil { return err }
	if a.conn != nil { a.conn.Close() }
	a.conn = conn
	a.client = pb.NewSentinelClient(conn)
	log.Printf("🔗 已连接: %s", a.cfg.Agent.Server)
	return nil
}

func (a *Agent) Start() {
	log.Printf("🛡️  eBPF Sentinel Agent  ID: %s", a.id)
	if err := a.RunProbe(); err != nil { log.Fatalf("❌ %v", err) }
	if err := a.startGuardian(); err != nil { log.Printf("⚠️ 守护: %v", err) }
	a.initPluginMgr()


	for { if err := a.Connect(); err != nil { time.Sleep(a.cfg.Agent.RetryDelay); continue }; break }
	for { if err := a.Register(); err != nil { time.Sleep(a.cfg.Agent.RetryDelay); continue }; break }

	// 采集并上报主机资产
	go func() {
		procs, err := collector.CollectAllProcesses()
		if err != nil {
			log.Printf("⚠️ 进程采集失败: %v", err)
			return
		}
		users, _ := collector.CollectAllUsers()
		log.Printf("📊 资产采集: %d进程 %d用户", len(procs), len(users))
		assetReq := &pb.AssetReport{AgentId: a.id, AgentToken: a.token}
		sysInfo, _ := collector.CollectSystemInfo()
		if sysInfo != nil {
			assetReq.System = &pb.SystemAsset{
				Os: &pb.OSAsset{Name: sysInfo.OS.Name, Version: sysInfo.OS.Version, Kernel: sysInfo.OS.Kernel},
				Cpu: &pb.CPUAsset{Model: sysInfo.CPU.Model, Cores: int32(sysInfo.CPU.Cores)},
				Memory: &pb.MemoryAsset{TotalMb: int32(sysInfo.Memory.TotalMB), SwapTotalMb: int32(sysInfo.Memory.SwapTotalMB)},
				Locale: sysInfo.Locale, Timezone: sysInfo.Timezone,
			}
			for _, d := range sysInfo.Disks {
				assetReq.System.Disks = append(assetReq.System.Disks, &pb.DiskAsset{MountPoint: d.MountPoint, Filesystem: d.Filesystem, TotalMb: int32(d.TotalMB)})
			}
			for _, n := range sysInfo.Networks {
				assetReq.System.Networks = append(assetReq.System.Networks, &pb.NetworkAsset{Name: n.Name, Mac: n.MAC, Ips: n.IPs})
			}
			assetReq.System.KernelModules = sysInfo.Modules
			for _, s := range sysInfo.Services {
				assetReq.System.Services = append(assetReq.System.Services, &pb.ServiceAsset{Name: s.Name, Enabled: s.Enabled})
			}
			log.Printf("🖥️  系统采集: %s %s CPU=%d核 Mem=%dMB 磁盘=%d个 服务=%d个", sysInfo.OS.Name, sysInfo.OS.Kernel, sysInfo.CPU.Cores, sysInfo.Memory.TotalMB, len(sysInfo.Disks), len(sysInfo.Services))
		}
		crons := collector.CollectAllCronJobs()
		for _, c := range crons {
			assetReq.Crons = append(assetReq.Crons, &pb.CronAsset{
				User: c.User, Schedule: c.Schedule, Command: c.Command, Source: c.Source,
			})
		}
		log.Printf("⏰ 定时任务: %d个", len(crons))
		pkgs := collector.CollectAllPackages()
		for _, p := range pkgs {
			assetReq.Packages = append(assetReq.Packages, &pb.PackageAsset{
				Name: p.Name, Version: p.Version, Manager: p.Manager,
			})
		}
		log.Printf("📦 软件包: %d个 (%s)", len(pkgs), func() string { if len(pkgs) > 0 { return pkgs[0].Manager } else { return "未知" } }())
		for _, p := range procs {
			assetReq.Processes = append(assetReq.Processes, &pb.ProcessAsset{
				Pid: int32(p.PID), Ppid: int32(p.PPID), Name: p.Name, Cmdline: p.Cmdline,
				ExePath: p.ExePath, User: p.User, State: p.State, ListeningPorts: p.Ports,
			})
		}
		for _, u := range users {
			assetReq.Users = append(assetReq.Users, &pb.UserAsset{
				Username: u.Username, Uid: int32(u.UID), Gid: int32(u.GID),
				Home: u.Home, Shell: u.Shell, HasShell: u.HasShell,
				IsRoot: u.IsRoot, IsDisabled: u.IsDisabled, HasSudo: u.HasSudo,
				LastLogin: u.LastLogin, LastLoginIp: u.LastLoginIP,
			})
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err = a.client.ReportAssets(ctx, assetReq)
		if err != nil { log.Printf("⚠️ 资产上报失败: %v", err) }
		for _, p := range procs {
			if len(p.Ports) > 0 { log.Printf("   PID=%d %s 端口=%v", p.PID, p.Name, p.Ports) }
		}
		for _, u := range users {
			if u.HasShell { log.Printf("   👤 %s UID=%d Shell=%s", u.Username, u.UID, u.Shell) }
		}
	}()

	go a.eventReporter()
	a.HeartbeatLoop()
}

func cstring(b []byte) string {
	for i, c := range b { if c == 0 { return string(b[:i]) } }
	return string(b)
}

func main() {
	flag.Parse()
	if *genConfig { config.GenerateDefault(*configPath); return }
	cfg, _ := config.Load(*configPath)
	agent := NewAgent(cfg)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("\n🛑 退出...")
		if agent.guardian != nil { agent.guardian.Stop() }
		if agent.pluginMgr != nil { agent.pluginMgr.Close() }
		os.Exit(0)
	}()
	agent.Start()
}

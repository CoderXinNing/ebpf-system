package main

import (
	"context"
	"crypto/md5"
	"fmt"
	"log"
	"net"
	"os"
	"time"

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
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
}

func getIPAddress() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "unknown"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
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
	conn         *grpc.ClientConn
	client       pb.SentinelClient
}

func NewAgent() *Agent {
	hostname := getHostname()
	return &Agent{
		id:       generateAgentID(hostname),
		hostname: hostname,
		ipAddr:   getIPAddress(),
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

	if !caps.BTFEnabled {
		log.Println("⚠️  BTF未启用，CO-RE功能不可用")
	}

	fw := caps.Framework
	hasFramework := fw.BCCAvailable ||
		fw.LibBPFAvailable ||
		fw.BpftraceAvailable ||
		fw.GoEBPFAvailable

	if !hasFramework {
		log.Println("⚠️  未检测到任何eBPF框架，部分功能可能受限")
	} else {
		log.Println("✅ 环境探测完成，eBPF框架可用")
	}

	return nil
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
			BccVersion:            fw.BCCVersion,
			PythonBccAvailable:    fw.PythonBCCAvailable,
			LibbpfAvailable:       fw.LibBPFAvailable,
			LibbpfVersion:         fw.LibBPFVersion,
			LibbpfCore:            fw.LibBPFCORE,
			BpftraceAvailable:     fw.BpftraceAvailable,
			BpftraceVersion:       fw.BpftraceVersion,
			ClangAvailable:        fw.ClangAvailable,
			ClangVersion:          fw.ClangVersion,
			LlvmAvailable:         fw.LLVMAvailable,
			LlvmVersion:           fw.LLVMVersion,
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

	req := a.buildRegisterRequest()

	resp, err := a.client.Register(ctx, req)
	if err != nil {
		return fmt.Errorf("注册失败: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("注册被拒绝: %s", resp.Message)
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
			log.Printf("⚠️ 心跳连接失败: %v", err)
			cancel()
			continue
		}

		err = resp.Send(&pb.HeartbeatRequest{
			AgentId:      a.id,
			AgentToken:   a.token,
			Timestamp:    time.Now().Unix(),
			ActiveProbes: 0,
		})
		if err != nil {
			log.Printf("⚠️ 发送心跳失败: %v", err)
			resp.CloseSend()
			cancel()
			continue
		}

		cmdResp, err := resp.Recv()
		if err != nil {
			log.Printf("⚠️ 接收指令失败: %v", err)
			resp.CloseSend()
			cancel()
			continue
		}

		if cmdResp.Success && len(cmdResp.Commands) > 0 {
			for _, cmd := range cmdResp.Commands {
				a.handleCommand(cmd)
			}
		}

		resp.CloseSend()
		cancel()
	}
}

func (a *Agent) handleCommand(cmd *pb.ProbeCommand) {
	switch cmd.Type {
	case pb.ProbeCommand_LOAD:
		log.Printf("📥 收到加载指令: %s (%s)", cmd.ProbeName, cmd.ProbeId)
	case pb.ProbeCommand_UNLOAD:
		log.Printf("📤 收到卸载指令: %s (%s)", cmd.ProbeName, cmd.ProbeId)
	case pb.ProbeCommand_UPDATE:
		log.Printf("🔄 收到更新指令: %s (%s)", cmd.ProbeName, cmd.ProbeId)
	}
}

func (a *Agent) Connect() error {
	var err error
	a.conn, err = grpc.Dial(serverAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("连接Server失败: %w", err)
	}
	a.client = pb.NewSentinelClient(a.conn)
	log.Printf("🔗 已连接到Server: %s", serverAddr)
	return nil
}

func (a *Agent) Start() {
	log.Printf("🛡️  eBPF Sentinel Agent 启动中...")
	log.Printf("   Agent ID: %s", a.id)
	log.Printf("   主机名: %s", a.hostname)
	log.Printf("   IP地址: %s", a.ipAddr)
	log.Println()

	if err := a.RunProbe(); err != nil {
		log.Fatalf("❌ %v", err)
	}

	for {
		if err := a.Connect(); err != nil {
			log.Printf("❌ %v", err)
			log.Printf("⏳ %d秒后重试...", int(retryDelay.Seconds()))
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

	a.HeartbeatLoop()
}

func main() {
	agent := NewAgent()
	agent.Start()
}

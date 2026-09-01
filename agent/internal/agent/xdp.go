package agent

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/CoderXinNing/ebpf-system/agent/internal/ebpf"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
)

var xdpHandle *ebpf.XDPHandle

func (a *Agent) startXDP() {
	if !a.cfg.XDP.Enabled {
		log.Println("ℹ️  XDP未启用（配置关闭）")
		return
	}

	if !a.checkEBPFSupport() {
		log.Println("⚠️ 内核不支持eBPF/XDP，降级为纯CMDB模式")
		return
	}

	if xdpHandle != nil {
		xdpHandle.Close()
		xdpHandle = nil
	}

	cfg := ebpf.XDPConfig{
		Iface: a.cfg.XDP.Iface,
	}

	handle, err := ebpf.LoadXDPReporter(cfg, func(evt ebpf.XDPEvent) {
		if evt.PID == uint32(os.Getpid()) {
			return
		}
		a.eventQueue <- &pb.ProbeEvent{
			ProbeName: "xdp",
			Timestamp: time.Now().Unix(),
			EventType: "xdp_alert",
			Pid:       int32(evt.PID),
			Comm:      string(evt.Comm[:]),
			Filename:  "xdp_alert",
			Details:   string(evt.Details[:]),
		}
	})
	if err != nil {
		log.Printf("⚠️ XDP加载失败（降级为纯CMDB）: %v", err)
		return
	}
	xdpHandle = handle
}

func (a *Agent) checkEBPFSupport() bool {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return false
	}
	if a.capabilities == nil || !a.capabilities.BTFEnabled {
		return false
	}
	return true
}

func (a *Agent) startExecMonitor() {
	err := ebpf.LoadExecMonitor(a.getProbePath("exec_monitor"), func(evt ebpf.ExecEvent, cmdline string) {
		if int32(evt.PID) == int32(os.Getpid()) {
			return
		}
		userName := ebpf.ResolveUser(evt.UID)
		a.eventQueue <- &pb.ProbeEvent{
			ProbeName: "execve",
			Timestamp: time.Now().Unix(),
			EventType: "execve",
			Pid:       int32(evt.PID),
			Comm:      string(evt.Comm[:]),
			Filename:  "execve",
			Details:   userName + ": " + cmdline,
		}
	})
	if err != nil {
		log.Printf("⚠️ 进程监控探针加载失败（降级）: %v", err)
	}
}

func (a *Agent) startBashMonitor() error {
	err := ebpf.LoadBashMonitor(a.getProbePath("bash_monitor"), "/bin/bash", func(evt ebpf.BashEvent, userName string, line string) {
		if line == "" {
			return
		}
		a.eventQueue <- &pb.ProbeEvent{
			ProbeName: "bash_input",
			Timestamp: time.Now().Unix(),
			EventType: "bash_input",
			Pid:       int32(evt.PID),
			Comm:      string(evt.Comm[:]),
			Filename:  "bash_input",
			Details:   line,
		}
	})
	if err != nil {
		log.Printf("⚠️ Bash监控加载失败（降级）: %v", err)
		return err
	}
	return nil
}

func (a *Agent) startTCPMonitor() {
	err := ebpf.LoadTCPMonitor(a.getProbePath("tcp_monitor"), func(pid uint32, comm string, count uint64) {
		a.eventQueue <- &pb.ProbeEvent{
			ProbeName: "tcp_connect",
			Timestamp: time.Now().Unix(),
			EventType: "tcp_connect",
			Pid:       int32(pid),
			Comm:      comm,
			Filename:  fmt.Sprintf("外联x%d次", count),
		}
	})
	if err != nil {
		log.Printf("⚠️ TCP监控加载失败: %v", err)
	}
}

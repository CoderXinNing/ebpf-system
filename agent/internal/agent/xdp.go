package agent

import (
	"fmt"
	"log"
	"net"
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

	// 清理旧XDP（如果存在）
	if xdpHandle != nil {
		xdpHandle.Close()
		xdpHandle = nil
	}

	if _, err := net.InterfaceByName(a.cfg.XDP.Iface); err != nil {
		log.Printf("⚠️ 网卡 %s 不存在，XDP降级", a.cfg.XDP.Iface)
		return
	}

	cfg := ebpf.XDPConfig{
		Iface:    a.cfg.XDP.Iface,
		DstIP:    net.ParseIP(a.cfg.XDP.ServerIP),
		DstPort:  uint16(a.cfg.XDP.ServerPort),
		SrcPort:  12345,
	}

	if iface, err := net.InterfaceByName(cfg.Iface); err == nil {
		cfg.SrcMAC = iface.HardwareAddr
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				cfg.SrcIP = ipnet.IP
				break
			}
		}
	}
	cfg.DstMAC = cfg.SrcMAC

	var err error
	xdpHandle, err = ebpf.LoadXDPReporter(cfg, func(evt ebpf.XDPEvent) {
		if int32(evt.PID) == int32(os.Getpid()) {
			return
		}
		a.eventQueue <- &pb.ProbeEvent{
			ProbeName: "xdp",
			Timestamp: time.Now().Unix(),
			EventType: "xdp_packet",
			Pid:       int32(evt.PID),
			Comm:      string(evt.Comm[:]),
			Filename:  string(evt.Filename[:]),
		}
	})
	if err != nil {
		log.Printf("⚠️ XDP加载失败（降级为纯CMDB）: %v", err)
	}
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
	err := ebpf.LoadExecMonitor(func(evt ebpf.ExecEvent, cmdline string) {
		if int32(evt.PID) == int32(os.Getpid()) {
			return
		}
		a.eventQueue <- &pb.ProbeEvent{
			ProbeName: "execve",
			Timestamp: time.Now().Unix(),
			EventType: "execve",
			Pid:       int32(evt.PID),
			Comm:      string(evt.Comm[:]),
			Filename:  cmdline,
		}
	})
	if err != nil {
		log.Printf("⚠️ 进程监控探针加载失败（降级）: %v", err)
	}
}

func (a *Agent) startBashMonitor() {
	err := ebpf.LoadBashMonitor("/bin/bash", func(evt ebpf.BashEvent, userName string, line string) {
		if line == "" {
			return
		}
		a.eventQueue <- &pb.ProbeEvent{
			ProbeName: "bash_input",
			Timestamp: time.Now().Unix(),
			EventType: "bash_input",
			Pid:       int32(evt.PID),
			Comm:      string(evt.Comm[:]),
			Filename:  line,
			Details:   userName,
		}
	})
	if err != nil {
		log.Printf("⚠️ Bash监控加载失败（降级）: %v", err)
	}
}

func (a *Agent) startTCPMonitor() {
	err := ebpf.LoadTCPMonitor(func(pid uint32, comm string, count uint64) {
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

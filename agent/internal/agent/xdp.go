package agent

import (
	"log"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/CoderXinNing/ebpf-system/agent/internal/ebpf"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
)

func (a *Agent) startXDP() {
	if !a.cfg.XDP.Enabled {
		log.Println("ℹ️  XDP未启用（配置关闭）")
		return
	}

	if !a.checkEBPFSupport() {
		log.Println("⚠️ 内核不支持eBPF/XDP，降级为纯CMDB模式")
		return
	}

	// 清理旧XDP
	pinPath := "/sys/fs/bpf/ebpf-sentinel/xdp_reporter"
	os.Remove(pinPath)
	exec.Command("bpftool", "net", "detach", "xdp", "dev", a.cfg.XDP.Iface).Run()

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

	_, _, err := ebpf.LoadXDPReporter(cfg, func(evt ebpf.XDPEvent) {
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

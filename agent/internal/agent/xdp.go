package agent

import (
	"log"
	"net"
	"os"
	"time"

	"github.com/CoderXinNing/ebpf-system/agent/internal/ebpf"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
)

func (a *Agent) startXDP() {
	if !a.cfg.XDP.Enabled {
		log.Println("ℹ️  XDP未启用（配置关闭）")
		return
	}

	// 降级检测：检查内核是否支持eBPF/XDP
	if !a.checkEBPFSupport() {
		log.Println("⚠️ 内核不支持eBPF/XDP，降级为纯CMDB模式")
		a.cfg.XDP.Enabled = false
		return
	}

	// 检查网卡是否存在
	if _, err := net.InterfaceByName(a.cfg.XDP.Iface); err != nil {
		log.Printf("⚠️ 网卡 %s 不存在，XDP降级", a.cfg.XDP.Iface)
		a.cfg.XDP.Enabled = false
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
		a.cfg.XDP.Enabled = false
	}
}

// checkEBPFSupport 检查内核eBPF/XDP支持
func (a *Agent) checkEBPFSupport() bool {
	// 检查BTF（eBPF CO-RE的前提）
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		log.Println("⚠️ BTF不可用，eBPF功能受限")
		return false
	}

	// 内核版本检查（XDP需要≥4.8，但推荐≥5.8）
	// 由环境探测模块已经检查过，这里只需确认capabilities
	if a.capabilities == nil || !a.capabilities.BTFEnabled {
		return false
	}

	return true
}

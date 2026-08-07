package agent

import (
	"log"
	"net"

	"github.com/CoderXinNing/ebpf-system/agent/internal/ebpf"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
	"time"
)

func (a *Agent) startXDP() {
	if !a.cfg.XDP.Enabled {
		return
	}

	cfg := ebpf.XDPConfig{
		Iface:    a.cfg.XDP.Iface,
		DstIP:    net.ParseIP(a.cfg.XDP.ServerIP),
		DstPort:  uint16(a.cfg.XDP.ServerPort),
		SrcPort:  12345,
	}

	// 获取本机IP和MAC
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
		log.Printf("⚠️ XDP初始化失败（不影响CMDB功能）: %v", err)
	}
}

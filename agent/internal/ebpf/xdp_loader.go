package ebpf

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type XDPConfig struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	SrcMAC  net.HardwareAddr
	DstMAC  net.HardwareAddr
	Iface   string
}

func LoadXDPReporter(cfg XDPConfig) (link.Link, error) {
	spec, err := ebpf.LoadCollectionSpec("probes/templates/xdp_reporter/xdp_reporter.o")
	if err != nil {
		return nil, fmt.Errorf("加载spec失败: %w", err)
	}

	var objs struct {
		XdpReporter *ebpf.Program `ebpf:"xdp_reporter"`
		ServerMap   *ebpf.Map     `ebpf:"server_map"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("加载程序失败: %w", err)
	}
	log.Printf("   XDP程序已加载到内核 (prog fd=%d)", objs.XdpReporter.FD())

	// 填充配置
	buf := make([]byte, 36)
	binary.BigEndian.PutUint32(buf[0:4], ipToUint32(cfg.SrcIP))
	binary.BigEndian.PutUint32(buf[4:8], ipToUint32(cfg.DstIP))
	binary.BigEndian.PutUint16(buf[8:10], cfg.SrcPort)
	binary.BigEndian.PutUint16(buf[10:12], cfg.DstPort)
	copy(buf[12:18], cfg.SrcMAC)
	copy(buf[18:24], cfg.DstMAC)

	key := uint32(0)
	if err := objs.ServerMap.Put(&key, buf); err != nil {
		objs.XdpReporter.Close()
		return nil, fmt.Errorf("写入配置失败: %w", err)
	}
	log.Printf("   Server配置已写入map")

	iface, err := net.InterfaceByName(cfg.Iface)
	if err != nil {
		objs.XdpReporter.Close()
		return nil, fmt.Errorf("网卡不存在: %w", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpReporter,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // 用generic模式兼容VM
	})
	if err != nil {
		objs.XdpReporter.Close()
		return nil, fmt.Errorf("attach失败: %w", err)
	}

	log.Printf("✅ XDP已attach到 %s (link fd=%d)", cfg.Iface, l)
	return l, nil
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil { return 0 }
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

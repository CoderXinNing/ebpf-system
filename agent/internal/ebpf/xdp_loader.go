package ebpf

import (
	"fmt"
	"log"
	"net"
	"os"

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

type XDPHandle struct {
	Objs *ebpf.Collection
	Link link.Link
}

func (h *XDPHandle) Close() {
	if h.Link != nil {
		h.Link.Close()
	}
	if h.Objs != nil {
		for _, m := range h.Objs.Maps {
			m.Close()
		}
		h.Objs.Close()
	}
	os.Remove("/sys/fs/bpf/ebpf-sentinel/xdp_reporter")
	log.Println("🧹 XDP已卸载")
}

func LoadXDPReporter(cfg XDPConfig) (*XDPHandle, error) {
	spec, err := ebpf.LoadCollectionSpec("probes/templates/xdp_reporter/xdp_reporter.o")
	if err != nil {
		return nil, fmt.Errorf("加载spec失败: %w", err)
	}

	var objs struct {
		XdpReporter *ebpf.Program `ebpf:"xdp_reporter"`
		XdpConfig   *ebpf.Map     `ebpf:"xdp_config"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("加载程序失败: %w", err)
	}

	// 写入配置到 eBPF Map
	cfgKey := uint32(0)
	type xdpConfigData struct {
		SrcIP   [4]byte
		DstIP   [4]byte
		SrcPort uint16
		DstPort uint16
		SrcMAC  [6]byte
		DstMAC  [6]byte
	}
	var cfgData xdpConfigData
	if ip4 := cfg.SrcIP.To4(); ip4 != nil {
		copy(cfgData.SrcIP[:], ip4)
	}
	if ip4 := cfg.DstIP.To4(); ip4 != nil {
		copy(cfgData.DstIP[:], ip4)
	}
	cfgData.SrcPort = cfg.SrcPort
	cfgData.DstPort = cfg.DstPort
	copy(cfgData.SrcMAC[:], cfg.SrcMAC)
	copy(cfgData.DstMAC[:], cfg.DstMAC)

	if err := objs.XdpConfig.Put(&cfgKey, &cfgData); err != nil {
		log.Printf("⚠️ XDP配置写入失败: %v", err)
	}

	iface, err := net.InterfaceByName(cfg.Iface)
	if err != nil {
		objs.XdpReporter.Close()
		return nil, fmt.Errorf("网卡不存在: %w", err)
	}

	pinPath := "/sys/fs/bpf/ebpf-sentinel/xdp_reporter"
	os.MkdirAll("/sys/fs/bpf/ebpf-sentinel", 0755)
	if err := objs.XdpReporter.Pin(pinPath); err != nil {
		log.Printf("⚠️ Pin XDP到bpffs失败: %v", err)
	} else {
		log.Printf("📌 XDP已pin到 %s", pinPath)
	}

	// 先尝试驱动模式，失败则回退到 generic
	var l link.Link
	flagsList := []link.XDPAttachFlags{link.XDPDriverMode, link.XDPGenericMode} // 0=驱动模式, 2=SKB/generic模式
	for _, flags := range flagsList {
		l, err = link.AttachXDP(link.XDPOptions{
			Flags:     link.XDPAttachFlags(flags),
			Program:   objs.XdpReporter,
			Interface: iface.Index,
		})
		if err == nil {
			mode := "驱动模式"
			if flags == 2 {
				mode = "通用模式"
			}
			log.Printf("✅ XDP已加载: %s (%s)", cfg.Iface, mode)
			break
		}
	}
	if err != nil {
		objs.XdpReporter.Close()
		return nil, fmt.Errorf("XDP attach失败: %w", err)
	}

	return &XDPHandle{
		Objs: &ebpf.Collection{
			Programs: map[string]*ebpf.Program{"xdp_reporter": objs.XdpReporter},
			Maps:     map[string]*ebpf.Map{"xdp_config": objs.XdpConfig},
		},
		Link: l,
	}, nil
}

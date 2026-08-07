package ebpf

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
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

type XDPEvent struct {
	Timestamp uint64
	PID       uint32
	EventType uint32
	Comm      [16]byte
	Filename  [64]byte
	Details   [64]byte
}

type EventCallback func(XDPEvent)

func LoadXDPReporter(cfg XDPConfig, callback EventCallback) (*ebpf.Map, link.Link, error) {
	spec, err := ebpf.LoadCollectionSpec("probes/templates/xdp_reporter/xdp_reporter.o")
	if err != nil {
		return nil, nil, fmt.Errorf("加载spec失败: %w", err)
	}

	var objs struct {
		XdpReporter *ebpf.Program `ebpf:"xdp_reporter"`
		Events      *ebpf.Map     `ebpf:"events"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, nil, fmt.Errorf("加载程序失败: %w", err)
	}

	// Attach到网卡
	iface, err := net.InterfaceByName(cfg.Iface)
	if err != nil {
		objs.XdpReporter.Close()
		return nil, nil, fmt.Errorf("网卡不存在: %w", err)
	}

	// Pin程序到bpffs
	pinPath := "/sys/fs/bpf/ebpf-sentinel/xdp_reporter"
	os.MkdirAll("/sys/fs/bpf/ebpf-sentinel", 0755)
	if err := objs.XdpReporter.Pin(pinPath); err != nil {
		log.Printf("⚠️ Pin XDP到bpffs失败: %v", err)
	} else {
		log.Printf("📌 XDP已pin到 %s", pinPath)
	}
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpReporter,
		Interface: iface.Index,
	})
	if err != nil {
		objs.XdpReporter.Close()
		return nil, nil, fmt.Errorf("attach失败: %w", err)
	}

	// 自动attach
	bpftoolCmd := exec.Command("bpftool", "net", "attach", "xdp", "pinned", pinPath, "dev", cfg.Iface)
	if err := bpftoolCmd.Run(); err != nil {
		log.Printf("⚠️ 自动attach失败（已pin到bpffs，可手动attach）: %v", err)
	} else {
		log.Printf("✅ XDP已attach到 %s", cfg.Iface)
	}
	log.Printf("✅ XDP已加载: %s (ring buffer模式)", cfg.Iface)

	// 启动ring buffer读取
	go func() {
		rd, err := ringbuf.NewReader(objs.Events)
		log.Printf("XDP ringbuf reader创建成功")
		if err != nil {
			log.Printf("⚠️ XDP ring buffer读取失败: %v", err)
			return
		}
		defer rd.Close()

		for {
			record, err := rd.Read()
			if err != nil {
				continue
			}

			var evt XDPEvent
			raw := record.RawSample
			evt.Timestamp = binary.LittleEndian.Uint64(raw[0:8])
			evt.PID = binary.LittleEndian.Uint32(raw[8:12])
			evt.EventType = binary.LittleEndian.Uint32(raw[12:16])
			copy(evt.Comm[:], raw[16:32])
			copy(evt.Filename[:], raw[32:96])
			copy(evt.Details[:], raw[96:160])

			log.Printf("📡 XDP事件: type=%d comm=%s file=%s", evt.EventType, string(evt.Comm[:]), string(evt.Filename[:]))
			callback(evt)
		}
	}()

	return objs.Events, l, nil
}

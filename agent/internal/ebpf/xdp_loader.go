package ebpf

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"

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

type XDPHandle struct {
	Objs   *ebpf.Collection
	Link   link.Link
	reader *ringbuf.Reader
}

func (h *XDPHandle) Close() {
	if h.reader != nil {
		h.reader.Close()
	}
	if h.Link != nil {
		h.Link.Close()
	}
	if h.Objs != nil {
		h.Objs.Close()
	}
	os.Remove("/sys/fs/bpf/ebpf-sentinel/xdp_reporter")
	log.Println("🧹 XDP已卸载")
}

func LoadXDPReporter(cfg XDPConfig, callback EventCallback) (*XDPHandle, error) {
	spec, err := ebpf.LoadCollectionSpec("probes/templates/xdp_reporter/xdp_reporter.o")
	if err != nil {
		return nil, fmt.Errorf("加载spec失败: %w", err)
	}

	var objs struct {
		XdpReporter *ebpf.Program `ebpf:"xdp_reporter"`
		Events      *ebpf.Map     `ebpf:"events"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("加载程序失败: %w", err)
	}

	iface, err := net.InterfaceByName(cfg.Iface)
	if err != nil {
		objs.XdpReporter.Close()
		return nil, fmt.Errorf("网卡不存在: %w", err)
	}

	// Pin程序到bpffs
	pinPath := "/sys/fs/bpf/ebpf-sentinel/xdp_reporter"
	os.MkdirAll("/sys/fs/bpf/ebpf-sentinel", 0755)
	if err := objs.XdpReporter.Pin(pinPath); err != nil {
		log.Printf("⚠️ Pin XDP到bpffs失败: %v", err)
	} else {
		log.Printf("📌 XDP已pin到 %s", pinPath)
	}

	// 只用 cilium/ebpf attach，不用 bpftool
	l, err := link.AttachXDP(link.XDPOptions{
		Flags: 2, // XDP_FLAGS_SKB_MODE (generic)
			Program:   objs.XdpReporter,
		Interface: iface.Index,
	})
	if err != nil {
		objs.XdpReporter.Close()
		return nil, fmt.Errorf("XDP attach失败: %w", err)
	}

	log.Printf("✅ XDP已加载: %s (ring buffer模式)", cfg.Iface)

	// 启动ring buffer读取
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		l.Close()
		objs.XdpReporter.Close()
		return nil, fmt.Errorf("ring buffer创建失败: %w", err)
	}
	log.Printf("XDP ringbuf reader创建成功")

	go func() {
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

	return &XDPHandle{
		Objs: &ebpf.Collection{
			Programs: map[string]*ebpf.Program{"xdp_reporter": objs.XdpReporter},
			Maps:     map[string]*ebpf.Map{"events": objs.Events},
		},
		Link:   l,
		reader: rd,
	}, nil
}

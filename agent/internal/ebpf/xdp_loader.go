package ebpf

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type XDPConfig struct {
	Iface string
}

type XDPEvent struct {
	PID       uint32
	EventType uint32
	Timestamp uint64
	Comm      [16]byte
	Details   [96]byte
}

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
		for _, m := range h.Objs.Maps {
			m.Close()
		}
		h.Objs.Close()
	}
	os.Remove("/sys/fs/bpf/ebpf-sentinel/xdp_reporter")
	log.Println("🧹 XDP已卸载")
}

func LoadXDPReporter(cfg XDPConfig, callback func(XDPEvent)) (*XDPHandle, error) {
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

	pinPath := "/sys/fs/bpf/ebpf-sentinel/xdp_reporter"
	os.MkdirAll("/sys/fs/bpf/ebpf-sentinel", 0755)
	if err := objs.XdpReporter.Pin(pinPath); err != nil {
		log.Printf("⚠️ Pin XDP到bpffs失败: %v", err)
	} else {
		log.Printf("📌 XDP已pin到 %s", pinPath)
	}

	// 先尝试驱动模式，失败则回退到 generic
	var l link.Link
	flagsList := []link.XDPAttachFlags{link.XDPDriverMode, link.XDPGenericMode}
	for _, flags := range flagsList {
		l, err = link.AttachXDP(link.XDPOptions{
			Flags:     link.XDPAttachFlags(flags),
			Program:   objs.XdpReporter,
			Interface: iface.Index,
		})
		if err == nil {
			mode := "驱动模式"
			if flags == link.XDPGenericMode {
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

	// ring buffer reader
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
			evt.PID = binaryLittleEndianUint32(raw[0:4])
			evt.EventType = binaryLittleEndianUint32(raw[4:8])
			evt.Timestamp = binaryLittleEndianUint64(raw[8:16])
			copy(evt.Comm[:], raw[16:32])
			copy(evt.Details[:], raw[32:128])
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

func binaryLittleEndianUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func binaryLittleEndianUint64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

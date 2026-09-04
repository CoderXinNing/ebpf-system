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
	Iface string
	// Mode 挂载模式："driver" 或 "generic"，默认 "generic"
	Mode string
}

type XDPEvent struct {
	PID       uint32
	EventType uint32
	Timestamp uint64
	Comm      [16]byte
	Details   [96]byte
}

type XDPHandle struct {
	program *ebpf.Program
	events  *ebpf.Map
	link    link.Link
	reader  *ringbuf.Reader
}

func (h *XDPHandle) Close() {
	if h.reader != nil {
		h.reader.Close()
	}
	if h.link != nil {
		h.link.Close()
	}
	if h.events != nil {
		h.events.Close()
	}
	if h.program != nil {
		h.program.Close()
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
		objs.Events.Close()
		return nil, fmt.Errorf("网卡不存在: %w", err)
	}

	pinPath := "/sys/fs/bpf/ebpf-sentinel/xdp_reporter"
	if err := os.MkdirAll("/sys/fs/bpf/ebpf-sentinel", 0755); err != nil {
		objs.XdpReporter.Close()
		objs.Events.Close()
		return nil, fmt.Errorf("创建 pin 目录失败: %w", err)
	}
	if err := objs.XdpReporter.Pin(pinPath); err != nil {
		log.Printf("⚠️ Pin XDP到bpffs失败: %v", err)
	} else {
		log.Printf("📌 XDP已pin到 %s", pinPath)
	}

	// 确定挂载模式：默认 GenericMode，仅当显式配置 "driver" 时使用 DriverMode
	var flags link.XDPAttachFlags
	modeName := "通用模式"
	if cfg.Mode == "driver" {
		flags = link.XDPDriverMode
		modeName = "驱动模式"
	} else {
		flags = link.XDPGenericMode
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Flags:     flags,
		Program:   objs.XdpReporter,
		Interface: iface.Index,
	})
	if err != nil {
		objs.XdpReporter.Close()
		objs.Events.Close()
		return nil, fmt.Errorf("XDP attach失败 (%s): %w", modeName, err)
	}
	log.Printf("✅ XDP已加载: %s (%s)", cfg.Iface, modeName)

	// ring buffer reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		l.Close()
		objs.XdpReporter.Close()
		objs.Events.Close()
		return nil, fmt.Errorf("ring buffer创建失败: %w", err)
	}
	log.Printf("✅ XDP ring buffer reader 创建成功")

	go func() {
		defer rd.Close()
		for {
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("⚠️ XDP ring buffer 读取错误: %v", err)
				continue
			}
			var evt XDPEvent
			raw := record.RawSample
			if len(raw) < 128 {
				log.Printf("⚠️ XDP ring buffer 数据长度不足: %d", len(raw))
				continue
			}
			evt.PID = binary.LittleEndian.Uint32(raw[0:4])
			evt.EventType = binary.LittleEndian.Uint32(raw[4:8])
			evt.Timestamp = binary.LittleEndian.Uint64(raw[8:16])
			copy(evt.Comm[:], raw[16:32])
			copy(evt.Details[:], raw[32:128])
			callback(evt)
		}
	}()

	return &XDPHandle{
		program: objs.XdpReporter,
		events:  objs.Events,
		link:    l,
		reader:  rd,
	}, nil
}

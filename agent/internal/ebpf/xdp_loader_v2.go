package ebpf

import (
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// XDPEventV2 是统一 header 格式的 XDP 事件
type XDPEventV2 struct {
	Header SentinelEventHeader
}

type XDPCallbackV2 func(XDPEventV2)

type XDPHandleV2 struct {
	program *ebpf.Program
	events  *ebpf.Map
	link    link.Link
	reader  *ringbuf.Reader
}

func (h *XDPHandleV2) Close() {
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
}

// LoadXDPReporterV2 加载新格式 XDP 探针（默认 GenericMode）
func LoadXDPReporterV2(cfg XDPConfig, callback XDPCallbackV2) (*XDPHandleV2, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("解除内存锁失败: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec("probes/new/xdp_reporter/xdp_reporter.o")
	if err != nil {
		return nil, fmt.Errorf("加载 spec 失败: %w", err)
	}

	var objs struct {
		XdpReporter    *ebpf.Program `ebpf:"xdp_reporter"`
		SentinelEvents *ebpf.Map     `ebpf:"sentinel_events"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("加载失败: %w", err)
	}

	iface, err := net.InterfaceByName(cfg.Iface)
	if err != nil {
		objs.XdpReporter.Close()
		return nil, fmt.Errorf("网卡不存在: %w", err)
	}

	// 默认 GenericMode，仅显式指定 driver 才用 DriverMode
	flags := link.XDPGenericMode
	modeName := "通用模式"
	if cfg.Mode == "driver" {
		flags = link.XDPDriverMode
		modeName = "驱动模式"
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Flags:     flags,
		Program:   objs.XdpReporter,
		Interface: iface.Index,
	})
	if err != nil {
		objs.XdpReporter.Close()
		return nil, fmt.Errorf("XDP attach 失败 (%s): %w", modeName, err)
	}

	rd, err := ringbuf.NewReader(objs.SentinelEvents)
	if err != nil {
		l.Close()
		objs.XdpReporter.Close()
		return nil, fmt.Errorf("ring buffer 创建失败: %w", err)
	}

	log.Printf("✅ 新 XDP 探针已启动 (%s)", modeName)

	go func() {
		defer rd.Close()
		for {
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				continue
			}

			header, err := DecodeEvent(record.RawSample)
			if err != nil {
				continue
			}
			callback(XDPEventV2{Header: *header})
		}
	}()

	return &XDPHandleV2{
		program: objs.XdpReporter,
		events:  objs.SentinelEvents,
		link:    l,
		reader:  rd,
	}, nil
}

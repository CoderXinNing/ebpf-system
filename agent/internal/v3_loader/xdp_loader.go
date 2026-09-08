package v3_loader

import (
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// XDPEventCallback XDP 事件回调
type XDPEventCallback func(header *SentinelEventHeader)

// XDPConfig XDP 配置
type XDPConfig struct {
	Iface string
	Mode  string // generic / driver
}

// XDPProbe V3 XDP 探针
type XDPProbe struct {
	callback XDPEventCallback
	link     link.Link
	objs     *xdpObjects
	reader   *ringbuf.Reader
}

type xdpObjects struct {
	XdpReporter *ebpf.Program `ebpf:"xdp_reporter"`
	XdpEvents   *ebpf.Map     `ebpf:"xdp_events"`
}

// NewXDPProbe 创建 XDP 探针
func NewXDPProbe(cfg XDPConfig, callback XDPEventCallback) *XDPProbe {
	return &XDPProbe{
		callback: callback,
	}
}

// Load 加载并 attach XDP 探针
func (p *XDPProbe) Load(objPath string, cfg XDPConfig) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除内存锁失败: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("加载 spec 失败: %w", err)
	}

	p.objs = &xdpObjects{}
	if err := spec.LoadAndAssign(p.objs, nil); err != nil {
		return fmt.Errorf("加载失败: %w", err)
	}

	iface, err := net.InterfaceByName(cfg.Iface)
	if err != nil {
		p.objs.XdpReporter.Close()
		return fmt.Errorf("网卡不存在: %w", err)
	}

	flags := link.XDPGenericMode
	if cfg.Mode == "driver" {
		flags = link.XDPDriverMode
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Flags:     flags,
		Program:   p.objs.XdpReporter,
		Interface: iface.Index,
	})
	if err != nil {
		p.objs.XdpReporter.Close()
		return fmt.Errorf("attach XDP 失败: %w", err)
	}
	p.link = l

	rd, err := ringbuf.NewReader(p.objs.XdpEvents)
	if err != nil {
		p.Close()
		return fmt.Errorf("创建 ring buffer reader 失败: %w", err)
	}
	p.reader = rd

	log.Printf("✅ V3 XDP 探针已启动 (%s)", cfg.Iface)

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
			p.callback(header)
		}
	}()

	return nil
}

// Close 清理资源
func (p *XDPProbe) Close() {
	if p.reader != nil {
		p.reader.Close()
	}
	if p.link != nil {
		p.link.Close()
	}
	if p.objs != nil {
		if p.objs.XdpReporter != nil {
			p.objs.XdpReporter.Close()
		}
	}
}

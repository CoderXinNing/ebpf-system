package v3_loader

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// XDPPacketSummary XDP 包摘要（与 C 层 pkt_summary 对应）
type XDPPacketSummary struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

// XDPEventCallback XDP 事件回调
type XDPEventCallback func(header *SentinelEventHeader, summary *XDPPacketSummary)

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
	closed   atomic.Bool
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
			if p.closed.Load() {
				return
			}
			rd.SetDeadline(time.Now().Add(500 * time.Millisecond))
			record, err := rd.Read()
			if err != nil {
				if isReaderClosed(err) || p.closed.Load() {
					return
				}
				if isReaderTimeout(err) {
					continue
				}
				continue
			}

			header, err := DecodeEvent(record.RawSample)
			if err != nil {
				continue
			}

			// 解析五元组摘要
			summary := parseXDPPacket(header.Data)
			p.callback(header, summary)
		}
	}()

	return nil
}

// parseXDPPacket 解析 XDP 五元组
func parseXDPPacket(data [256]byte) *XDPPacketSummary {
	return &XDPPacketSummary{
		SrcIP:    binary.BigEndian.Uint32(data[0:4]),
		DstIP:    binary.BigEndian.Uint32(data[4:8]),
		SrcPort:  binary.BigEndian.Uint16(data[8:10]),
		DstPort:  binary.BigEndian.Uint16(data[10:12]),
		Protocol: data[12],
	}
}

// Close 清理资源
func (p *XDPProbe) Close() {
	if p.reader != nil {
		p.closed.Store(true)
		// 不直接调 reader.Close() 或 SetDeadline：
		// Read 阻塞时持有 reader 内部锁，这两个方法会死锁。
		// reader goroutine 会在下一轮 500ms deadline 超时后检查 closed 并退出，
		// 退出时通过 defer rd.Close() 释放 fd。
		// 关 objs（含 ringbuf map）会让 epoll 立刻返回错误，加速唤醒。
		p.reader = nil
	}
	if p.link != nil {
		p.link.Close()
		p.link = nil
	}
	if p.objs != nil {
		closeEbpfObjects(p.objs)
		p.objs = nil
	}
}

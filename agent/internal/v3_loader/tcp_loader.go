package v3_loader

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// ConfigKey 配置枚举
const (
	ConfigCollectMode      uint32 = 0
	ConfigWhitelistEnabled uint32 = 1
	ConfigMaxEntries       uint32 = 2
	ConfigAgentHash        uint32 = 3
)

// CollectMode 采集模式
const (
	CollectModeCount   uint64 = 0 // 计数模式
	CollectModeDetail  uint64 = 1 // 明细模式
)

// TCPEventCallback TCP 事件回调
type TCPEventCallback func(header *SentinelEventHeader, detail *TCPConnDetail)

// ManualTracepointLink 手动管理 tracepoint fd
type ManualTracepointLink struct {
	fd int
}

func (l *ManualTracepointLink) Close() error {
	if l.fd >= 0 {
		err := unix.Close(l.fd)
		l.fd = -1
		return err
	}
	return nil
}

// attachTracepointManual 手动读取 tracepoint ID 并 attach
func attachTracepointManual(prog *ebpf.Program, tracepointPath string) (*ManualTracepointLink, error) {
	idBytes, err := os.ReadFile(tracepointPath + "/id")
	if err != nil {
		return nil, fmt.Errorf("读取 tracepoint ID 失败: %w", err)
	}
	tpID, err := strconv.Atoi(strings.TrimSpace(string(idBytes)))
	if err != nil {
		return nil, fmt.Errorf("解析 tracepoint ID 失败: %w", err)
	}

	log.Printf("📍 手动读取 tracepoint ID: %d", tpID)

	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Config:      uint64(tpID),
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
	}

	fd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("perf_event_open 失败: %w", err)
	}

	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, prog.FD()); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("SET_BPF 失败: %w", err)
	}

	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("ENABLE 失败: %w", err)
	}

	log.Printf("✅ tracepoint attach 成功 (fd=%d, config=%d)", fd, tpID)
	return &ManualTracepointLink{fd: fd}, nil
}

// TCPProbe V3 TCP 探针
type TCPProbe struct {
	objPath     string
	callback    TCPEventCallback
	link        *ManualTracepointLink
	objs        *tcpObjects
	agentHash   uint32
}

type tcpObjects struct {
	TraceConnect  *ebpf.Program `ebpf:"trace_connect"`
	ConfigMap     *ebpf.Map     `ebpf:"config_map"`
	SentinelEvents *ebpf.Map    `ebpf:"sentinel_events"`
	SentinelWhitelist *ebpf.Map `ebpf:"sentinel_whitelist"`
	PidConnStats  *ebpf.Map     `ebpf:"pid_conn_stats"`
	ConnDetails   *ebpf.Map     `ebpf:"conn_details"`
}

// NewTCPProbe 创建 TCP 探针
func NewTCPProbe(objPath string, agentHash uint32, callback TCPEventCallback) *TCPProbe {
	return &TCPProbe{
		objPath:   objPath,
		callback:  callback,
		agentHash: agentHash,
	}
}

// Load 加载并 attach TCP 探针
func (p *TCPProbe) Load() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除内存锁失败: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(p.objPath)
	if err != nil {
		return fmt.Errorf("加载 spec 失败: %w", err)
	}

	p.objs = &tcpObjects{}
	if err := spec.LoadAndAssign(p.objs, nil); err != nil {
		return fmt.Errorf("加载失败: %w", err)
	}

	// 在 Attach 之前写入 Config Map
	var key uint32 = ConfigAgentHash
	var value uint64 = uint64(p.agentHash)
	if err := p.objs.ConfigMap.Put(&key, &value); err != nil {
		return fmt.Errorf("写入 agent_hash 失败: %w", err)
	}

	// 默认计数模式
	key = ConfigCollectMode
	value = CollectModeCount
	if err := p.objs.ConfigMap.Put(&key, &value); err != nil {
		return fmt.Errorf("写入 collect_mode 失败: %w", err)
	}

	// 手动 attach
	tp, err := attachTracepointManual(p.objs.TraceConnect, "/sys/kernel/debug/tracing/events/syscalls/sys_enter_connect")
	if err != nil {
		p.objs.TraceConnect.Close()
		return fmt.Errorf("attach tracepoint 失败: %w", err)
	}
	p.link = tp

	// 启动 Ring Buffer 读取
	rd, err := ringbuf.NewReader(p.objs.SentinelEvents)
	if err != nil {
		p.Close()
		return fmt.Errorf("创建 ring buffer reader 失败: %w", err)
	}

	log.Printf("✅ V3 TCP 探针已启动 (计数模式)")

	go func() {
		defer rd.Close()
		for {
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("⚠️ ring buffer 读取错误: %v", err)
				continue
			}

			header, err := DecodeEvent(record.RawSample)
			if err != nil {
				continue // 短包已记录日志
			}

			detail := ParseTCPDetail(header.Data)
			p.callback(header, detail)
		}
	}()

	return nil
}

// SetCollectMode 动态切换采集模式
func (p *TCPProbe) SetCollectMode(mode uint64) error {
	if p.objs == nil || p.objs.ConfigMap == nil {
		return fmt.Errorf("探针未加载")
	}
	var key uint32 = ConfigCollectMode
	return p.objs.ConfigMap.Put(&key, &mode)
}

// Close 清理资源
func (p *TCPProbe) Close() {
	if p.link != nil {
		p.link.Close()
		p.link = nil
	}
	if p.objs != nil {
		if p.objs.TraceConnect != nil {
			p.objs.TraceConnect.Close()
		}
		p.objs = nil
	}
}

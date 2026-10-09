package v3_loader

import (
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ConfigKey 配置枚举
const (
	ConfigCollectMode  uint32 = 0
	ConfigExcludeComms uint32 = 1
	ConfigMaxEntries   uint32 = 2
	ConfigAgentHash    uint32 = 3
)

// CollectMode 采集模式
const (
	CollectModeCount  uint64 = 0 // 计数模式
	CollectModeDetail uint64 = 1 // 明细模式
)

// TCPEventCallback TCP 事件回调
type TCPEventCallback func(header *SentinelEventHeader, detail *TCPConnDetail)

// ManualTracepointLink 包装 cilium/ebpf 的 link.Link
//
// 历史：曾用 perf_event_open 手搓 attach（有 CPU 0 限制 + BPF_LINK 单挂限制），
// 现改用 link.Tracepoint（BPF_LINK_CREATE 新 API，自动处理所有 CPU）。
type ManualTracepointLink struct {
	link link.Link
}

func (l *ManualTracepointLink) Close() error {
	if l.link != nil {
		return l.link.Close()
	}
	return nil
}

// attachTracepointManual 用 cilium/ebpf 的 link.Tracepoint attach
//
// tracepointPath 形如：/sys/kernel/debug/tracing/events/<group>/<name>
// 内部拆出 group + name 传给 link.Tracepoint（BPF_LINK_CREATE 新 API）。
func attachTracepointManual(prog *ebpf.Program, tracepointPath string) (*ManualTracepointLink, error) {
	// 解析 group + name
	parts := strings.Split(strings.TrimRight(tracepointPath, "/"), "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("非法 tracepoint 路径: %s", tracepointPath)
	}
	name := parts[len(parts)-1]
	group := parts[len(parts)-2]

	l, err := link.Tracepoint(group, name, prog, nil)
	if err != nil {
		return nil, fmt.Errorf("link.Tracepoint(%s/%s) 失败: %w", group, name, err)
	}

	log.Printf("✅ tracepoint attach 成功: %s/%s", group, name)
	return &ManualTracepointLink{link: l}, nil
}

// TCPProbe V3 TCP 探针
type TCPProbe struct {
	objPath   string
	callback  TCPEventCallback
	link      *ManualTracepointLink
	objs      *tcpObjects
	agentHash uint32

	// 排除名单同步（记录上次 keys，用于清空重建）
	excludeMu        sync.Mutex
	lastExcludeComms []string
}

type tcpObjects struct {
	TraceConnect         *ebpf.Program `ebpf:"trace_connect"`
	ConfigMap            *ebpf.Map     `ebpf:"config_map"`
	SentinelEvents       *ebpf.Map     `ebpf:"sentinel_events"`
	SentinelExcludeComms *ebpf.Map     `ebpf:"sentinel_exclude_comms"`
	PidConnStats         *ebpf.Map     `ebpf:"pid_conn_stats"`
	ConnDetails          *ebpf.Map     `ebpf:"conn_details"`
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

	// 启用排除列表
	var wlKey uint32 = ConfigExcludeComms
	var wlVal uint64 = 1
	if err := p.objs.ConfigMap.Put(&wlKey, &wlVal); err != nil {
		log.Printf("⚠️ 写 ConfigExcludeComms 失败: %v", err)
	}

	// 默认计数模式
	key = ConfigCollectMode
	value = CollectModeCount
	if err := p.objs.ConfigMap.Put(&key, &value); err != nil {
		return fmt.Errorf("写入 collect_mode 失败: %w", err)
	}

	// 手动 attach
	// 使用 kprobe attach（不是 tracepoint）
	tp, err := link.Kprobe("__sys_connect", p.objs.TraceConnect, nil)
	if err != nil {
		p.objs.TraceConnect.Close()
		return fmt.Errorf("attach kprobe 失败: %w", err)
	}
	log.Printf("✅ kprobe attach 成功")
	p.link = &ManualTracepointLink{link: tp}

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

// GetPidConnStats 返回 PID 连接统计 Map
func (p *TCPProbe) GetPidConnStats() *ebpf.Map {
	if p.objs != nil {
		return p.objs.PidConnStats
	}
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

// SetObservationLevel 设置观察等级
// 0=PASSIVE, 1=REDUCED, 2=FULL
func (p *TCPProbe) SetObservationLevel(level uint64) error {
	if p.objs == nil || p.objs.ConfigMap == nil {
		return fmt.Errorf("探针未加载")
	}
	var key uint32 = 4 // CONFIG_OBSERVATION_LEVEL
	return p.objs.ConfigMap.Put(&key, &level)
}

// UpdateExcludeComms 更新白名单
func (p *TCPProbe) UpdateExcludeComms(processNames []string) error {
	if p.objs == nil || p.objs.SentinelExcludeComms == nil {
		return nil
	}

	p.excludeMu.Lock()
	defer p.excludeMu.Unlock()

	var val uint8 = 1

	// 1. 全清现有条目（LRU_HASH 支持 Iterate）
	//    不用"记录 last keys"模式——进程重启后内存丢失，会漏删
	//    注意：Next 的 value 参数不能传 nil，cilium/ebpf 会解码它
	iter := p.objs.SentinelExcludeComms.Iterate()
	var key [16]byte
	var valOld uint8
	for iter.Next(&key, &valOld) {
		k := key // 拷贝一份，防迭代器复用同一 key 缓冲
		_ = p.objs.SentinelExcludeComms.Delete(&k)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("遍历 exclude_comms 失败: %w", err)
	}

	// 2. 写入新列表
	for _, name := range processNames {
		var k [16]byte
		copy(k[:], name)
		if err := p.objs.SentinelExcludeComms.Put(&k, &val); err != nil {
			return fmt.Errorf("写入 exclude 失败 [%s]: %w", name, err)
		}
	}

	// 保留记录（便于观察/调试，可选）
	p.lastExcludeComms = append([]string(nil), processNames...)
	return nil
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

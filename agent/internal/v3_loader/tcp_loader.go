package v3_loader

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
	excludeMu         sync.Mutex
	lastExcludeComms  []string
	lastExcludeIPs    []string
	lastExcludeCombos []TCPComboEntry

	// ringbuf reader（Close 时用来唤醒 Read 阻塞的 goroutine）
	rd     *ringbuf.Reader
	closed atomic.Bool
}

type tcpObjects struct {
	TraceConnect   *ebpf.Program `ebpf:"trace_connect"`
	ConfigMap      *ebpf.Map     `ebpf:"config_map"`
	SentinelEvents *ebpf.Map     `ebpf:"sentinel_events"`
	SentinelXComm  *ebpf.Map     `ebpf:"sentinel_xcomm"`
	SentinelXCombo *ebpf.Map     `ebpf:"sentinel_xcombo"`
	SentinelXIP    *ebpf.Map     `ebpf:"sentinel_xip"`
	PidConnStats   *ebpf.Map     `ebpf:"pid_conn_stats"`
	ConnDetails    *ebpf.Map     `ebpf:"conn_details"`
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
	p.rd = rd

	log.Printf("✅ V3 TCP 探针已启动 (计数模式)")

	go func() {
		defer rd.Close()
		for {
			if p.closed.Load() {
				return
			}
			// 周期性 deadline，让 Read 最多阻塞 500ms
			// （SetDeadline 无法唤醒已阻塞在 EpollWait 中的 Read，
			//  必须靠周期性超时让 goroutine 有机会检查 closed 标志）
			rd.SetDeadline(time.Now().Add(500 * time.Millisecond))
			record, err := rd.Read()
			if err != nil {
				if isReaderClosed(err) || p.closed.Load() {
					return
				}
				if isReaderTimeout(err) {
					continue
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

// UpdateExcludeComms 更新 TCP comm 排除名单（HASH）
//
// 语义：排除某进程发起的全部外联。
// 与 sentinel_xip / sentinel_xcombo 独立并存，任一命中即排除。
func (p *TCPProbe) UpdateExcludeComms(processNames []string) error {
	if p.objs == nil || p.objs.SentinelXComm == nil {
		return nil
	}

	p.excludeMu.Lock()
	defer p.excludeMu.Unlock()

	var val uint8 = 1

	iter := p.objs.SentinelXComm.Iterate()
	var key [16]byte
	var valOld uint8
	for iter.Next(&key, &valOld) {
		k := key
		_ = p.objs.SentinelXComm.Delete(&k)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("遍历 sentinel_xcomm 失败: %w", err)
	}

	for _, name := range processNames {
		var k [16]byte
		copy(k[:], name)
		if err := p.objs.SentinelXComm.Put(&k, &val); err != nil {
			return fmt.Errorf("写入 xcomm 失败 [%s]: %w", name, err)
		}
	}

	p.lastExcludeComms = append([]string(nil), processNames...)
	return nil
}

// Close 清理资源
func (p *TCPProbe) Close() {
	if p.link != nil {
		p.link.Close()
		p.link = nil
	}
	if p.rd != nil {
		p.closed.Store(true)
		// 不直接调 rd.Close() 或 SetDeadline：
		// Read 阻塞时持有 reader 内部锁，这两个方法会死锁。
		// reader goroutine 会在下一轮 500ms deadline 超时后检查 closed 并退出，
		// 退出时通过 defer rd.Close() 释放 fd。
		// 关 objs（含 ringbuf map）会让 epoll 立刻返回错误，加速唤醒。
		p.rd = nil
	}
	if p.objs != nil {
		closeEbpfObjects(p.objs)
		p.objs = nil
	}
}

// ============================================
// IP 维度排除（LPM_TRIE，支持 CIDR）
// 见 EDR-CORRELATION-v3.1【五】+ PROJECT-STATUS 已知问题 #11/#12
// ============================================

// lpmIPKey 与 C 侧 struct lpm_ip_key 内存布局严格一致：
//
//	struct lpm_ip_key {
//	    __u32 prefixlen;
//	    __u32 ip;
//	} __attribute__((packed));
//
// 说明：IP 字段用 [4]byte 而非 uint32，避免 cilium/ebpf 的 native-endian
// 序列化歧义。C 侧写入的 uint32 是小端存储的"网络字节序数值"，
// 其内存字节序与 [4]byte 完全一致。
type lpmIPKey struct {
	PrefixLen uint32
	IP        [4]byte
}

// xcomboKey 与 C 侧 struct xcombo_key 内存布局严格一致（packed，20 字节）
//
//	comm[16] + u32 ip（网络字节序）
type xcomboKey struct {
	Comm [16]byte
	IP   [4]byte
}

// TCPComboEntry 组合排除条目（Go 侧已解析好的形式）
type TCPComboEntry struct {
	Comm string
	IP   [4]byte
}

// UpdateExcludeCombos 更新 TCP (comm, ip) 组合排除名单
//
// 语义：精确排除"进程 X 访问 IP Y"。
// 与 xcomm / xip 独立并存。
// 注意：不支持 CIDR，IP 必须精确。
func (p *TCPProbe) UpdateExcludeCombos(entries []TCPComboEntry) error {
	if p.objs == nil || p.objs.SentinelXCombo == nil {
		return nil
	}

	p.excludeMu.Lock()
	defer p.excludeMu.Unlock()

	var val uint8 = 1

	iter := p.objs.SentinelXCombo.Iterate()
	var key xcomboKey
	var valOld uint8
	for iter.Next(&key, &valOld) {
		k := key
		_ = p.objs.SentinelXCombo.Delete(&k)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("遍历 sentinel_xcombo 失败: %w", err)
	}

	for _, e := range entries {
		var k xcomboKey
		copy(k.Comm[:], e.Comm)
		copy(k.IP[:], e.IP[:])
		if err := p.objs.SentinelXCombo.Put(&k, &val); err != nil {
			return fmt.Errorf("写入 xcombo 失败 [%s/%v]: %w", e.Comm, e.IP, err)
		}
	}

	p.lastExcludeCombos = append([]TCPComboEntry(nil), entries...)
	return nil
}

// UpdateExcludeIPs 更新 TCP 探针 IP 排除名单（支持单 IP 与 CIDR）
//
// 支持形式：
//
//	"1.2.3.4"        → /32
//	"10.0.0.0/8"     → CIDR 前缀
//
// 非法条目跳过并打日志，不阻断整批更新。
func (p *TCPProbe) UpdateExcludeIPs(ips []string) error {
	if p.objs == nil || p.objs.SentinelXIP == nil {
		return nil
	}

	p.excludeMu.Lock()
	defer p.excludeMu.Unlock()

	var val uint8 = 1

	// 1. 全清现有条目（LPM_TRIE 支持 Iterate）
	iter := p.objs.SentinelXIP.Iterate()
	var key lpmIPKey
	var valOld uint8
	for iter.Next(&key, &valOld) {
		k := key // 拷贝一份，防迭代器复用同一 key 缓冲
		_ = p.objs.SentinelXIP.Delete(&k)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("遍历 sentinel_xip 失败: %w", err)
	}

	// 2. 写入新列表
	for _, raw := range ips {
		k, err := parseCIDRToLPMKey(raw)
		if err != nil {
			log.Printf("⚠️ 跳过非法 IP/CIDR [%s]: %v", raw, err)
			continue
		}
		if err := p.objs.SentinelXIP.Put(k, &val); err != nil {
			return fmt.Errorf("写入 sentinel_xip 失败 [%s]: %w", raw, err)
		}
	}

	p.lastExcludeIPs = append([]string(nil), ips...)
	return nil
}

// parseCIDRToLPMKey 解析 IP 或 CIDR 为 LPM_TRIE key
//
// 只支持 IPv4；IPv6 直接报错（探针目前只处理 IPv4）。
func parseCIDRToLPMKey(s string) (*lpmIPKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("空字符串")
	}

	var (
		ip        net.IP
		prefixLen int
	)

	if strings.Contains(s, "/") {
		parsedIP, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("解析 CIDR 失败: %w", err)
		}
		ip = parsedIP
		ones, _ := ipNet.Mask.Size()
		prefixLen = ones
	} else {
		parsedIP := net.ParseIP(s)
		if parsedIP == nil {
			return nil, fmt.Errorf("解析 IP 失败")
		}
		ip = parsedIP
		prefixLen = 32
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("非 IPv4: %s", s)
	}

	k := &lpmIPKey{PrefixLen: uint32(prefixLen)}
	copy(k.IP[:], ip4)
	return k, nil
}

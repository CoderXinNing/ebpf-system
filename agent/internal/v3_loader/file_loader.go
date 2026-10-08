package v3_loader

import (
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// FileEventCallback file_access 事件回调
type FileEventCallback func(header *SentinelEventHeader, filename string)

// FileProbe V3 file_access 探针
type FileProbe struct {
	objPath   string
	callback  FileEventCallback
	link      *ManualTracepointLink
	linkFork  *ManualTracepointLink
	linkExit  *ManualTracepointLink
	objs      *fileObjects
	agentHash uint32

	// 记录上次写入的 keys（避免用 Iterate 清空 LPM_TRIE）
	// 注：cilium/ebpf 对 LPM_TRIE 的 Iterate 有 key size 问题
	lastMu     sync.Mutex
	lastExact  []string
	lastPrefix []string
}

type fileObjects struct {
	TraceOpenat       *ebpf.Program `ebpf:"trace_openat"`
	TraceExec         *ebpf.Program `ebpf:"trace_exec"`
	TraceExit         *ebpf.Program `ebpf:"trace_exit"`
	ConfigMap         *ebpf.Map     `ebpf:"config_map"`
	FileEvents        *ebpf.Map     `ebpf:"file_events"`
	SentinelWhitelist *ebpf.Map     `ebpf:"sentinel_whitelist"`
	SensitiveExact    *ebpf.Map     `ebpf:"sensitive_exact"`
	SensitivePrefixes *ebpf.Map     `ebpf:"sensitive_prefixes"`
	AgentPids         *ebpf.Map     `ebpf:"agent_pids"`
}

// NewFileProbe 创建 file_access 探针
func NewFileProbe(objPath string, agentHash uint32, callback FileEventCallback) *FileProbe {
	return &FileProbe{
		objPath:   objPath,
		callback:  callback,
		agentHash: agentHash,
	}
}

// Load 加载并 attach file_access 探针
func (p *FileProbe) Load() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除内存锁失败: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(p.objPath)
	if err != nil {
		return fmt.Errorf("加载 spec 失败: %w", err)
	}

	p.objs = &fileObjects{}
	if err := spec.LoadAndAssign(p.objs, nil); err != nil {
		return fmt.Errorf("加载失败: %w", err)
	}

	// 写入 Config Map
	var key uint32 = ConfigAgentHash
	var value uint64 = uint64(p.agentHash)
	if err := p.objs.ConfigMap.Put(&key, &value); err != nil {
		return fmt.Errorf("写入 agent_hash 失败: %w", err)
	}

	// 写入自己 PID 到 agent_pids（P1.9：过滤 Agent 自身噪声）
	agentPid := uint32(os.Getpid())
	var flag uint8 = 1
	if err := p.objs.AgentPids.Put(&agentPid, &flag); err != nil {
		log.Printf("⚠️ 写入 agent_pids 失败: %v（P1.9 过滤不生效）", err)
	} else {
		log.Printf("✅ agent_pids 已标记自己 PID=%d（P1.9）", agentPid)
	}

	// 手动 attach（openat）
	tp, err := attachTracepointManual(p.objs.TraceOpenat, "/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat")
	if err != nil {
		p.objs.TraceOpenat.Close()
		return fmt.Errorf("attach tracepoint 失败: %w", err)
	}
	p.link = tp

	// 手动 attach（exec - Agent 进程树跟随）
	tpExec, err := attachTracepointManual(p.objs.TraceExec, "/sys/kernel/debug/tracing/events/sched/sched_process_exec")
	if err != nil {
		log.Printf("⚠️ attach exec tracepoint 失败: %v（P1.9 子进程过滤不生效）", err)
	} else {
		p.linkFork = tpExec
	}

	// 手动 attach（exit - 清理标记）
	tpExit, err := attachTracepointManual(p.objs.TraceExit, "/sys/kernel/debug/tracing/events/sched/sched_process_exit")
	if err != nil {
		log.Printf("⚠️ attach exit tracepoint 失败: %v", err)
	} else {
		p.linkExit = tpExit
	}

	// Ring Buffer 读取
	rd, err := ringbuf.NewReader(p.objs.FileEvents)
	if err != nil {
		p.Close()
		return fmt.Errorf("创建 ring buffer reader 失败: %w", err)
	}

	log.Printf("✅ V3 file_access 探针已启动")

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
				continue
			}

			filename := CString(header.Data[:])
			p.callback(header, filename)
		}
	}()

	return nil
}

// UpdateWhitelist 更新白名单
func (p *FileProbe) UpdateWhitelist(processNames []string) error {
	if p.objs == nil || p.objs.SentinelWhitelist == nil {
		return nil
	}
	for _, name := range processNames {
		var key [16]byte
		copy(key[:], name)
		var value uint8 = 1
		if err := p.objs.SentinelWhitelist.Put(&key, &value); err != nil {
			return err
		}
	}
	return nil
}

// UpdateSensitivePaths 更新敏感路径规则。
//
//   - exactPaths  → 精确匹配（存 sensitive_exact）
//   - prefixPaths → 前缀匹配（存 sensitive_prefixes，路径须以 / 结尾）
//
// 清空策略：不用 Iterate（cilium/ebpf 对 LPM_TRIE 的 Iterate 有 key size 问题），
// 改为记录"上次写入的 keys"，本次逐条 Delete 后再写新的。
func (p *FileProbe) UpdateSensitivePaths(exactPaths, prefixPaths []string) error {
	if p.objs == nil || p.objs.SensitiveExact == nil || p.objs.SensitivePrefixes == nil {
		return fmt.Errorf("探针未加载")
	}

	p.lastMu.Lock()
	defer p.lastMu.Unlock()

	var val uint8 = 1

	// 1. 删除上次的 exact keys
	for _, path := range p.lastExact {
		var key [256]byte
		copy(key[:], path)
		_ = p.objs.SensitiveExact.Delete(&key)
	}
	// 2. 删除上次的 prefix keys
	for _, path := range p.lastPrefix {
		keyBytes := makeLPMKey(path)
		_ = p.objs.SensitivePrefixes.Delete(keyBytes)
	}

	// 3. 写入新的 exact
	for _, path := range exactPaths {
		if len(path) > 255 {
			return fmt.Errorf("路径超长（>255）: %s", path)
		}
		var key [256]byte
		copy(key[:], path)
		if err := p.objs.SensitiveExact.Put(&key, &val); err != nil {
			return fmt.Errorf("写入 exact 失败 [%s]: %w", path, err)
		}
	}

	// 4. 写入新的 prefix
	for _, path := range prefixPaths {
		if len(path) > 255 {
			return fmt.Errorf("路径超长（>255）: %s", path)
		}
		keyBytes := makeLPMKey(path)
		if err := p.objs.SensitivePrefixes.Put(keyBytes, &val); err != nil {
			return fmt.Errorf("写入 prefix 失败 [%s]: %w", path, err)
		}
	}

	// 5. 记录本次 keys（下次清空用）
	p.lastExact = append([]string(nil), exactPaths...)
	p.lastPrefix = append([]string(nil), prefixPaths...)
	return nil
}

// makeLPMKey 构造 LPM_TRIE 的 key（4 字节 prefixlen 小端 + 256 字节路径）
func makeLPMKey(path string) []byte {
	keyBytes := make([]byte, 4+256)
	prefixLen := uint32(len(path) * 8)
	keyBytes[0] = byte(prefixLen)
	keyBytes[1] = byte(prefixLen >> 8)
	keyBytes[2] = byte(prefixLen >> 16)
	keyBytes[3] = byte(prefixLen >> 24)
	copy(keyBytes[4:], path)
	return keyBytes
}

// Close 清理资源
func (p *FileProbe) Close() {
	if p.link != nil {
		p.link.Close()
		p.link = nil
	}
	if p.linkFork != nil {
		p.linkFork.Close()
		p.linkFork = nil
	}
	if p.linkExit != nil {
		p.linkExit.Close()
		p.linkExit = nil
	}
	if p.objs != nil {
		if p.objs.TraceOpenat != nil {
			p.objs.TraceOpenat.Close()
		}
		p.objs = nil
	}
}

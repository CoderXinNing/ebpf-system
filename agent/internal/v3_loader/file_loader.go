package v3_loader

import (
	"fmt"
	"log"

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
	objs      *fileObjects
	agentHash uint32
}

type fileObjects struct {
	TraceOpenat       *ebpf.Program `ebpf:"trace_openat"`
	ConfigMap         *ebpf.Map     `ebpf:"config_map"`
	FileEvents        *ebpf.Map     `ebpf:"file_events"`
	SentinelWhitelist *ebpf.Map     `ebpf:"sentinel_whitelist"`
	SensitiveExact    *ebpf.Map     `ebpf:"sensitive_exact"`
	SensitivePrefixes *ebpf.Map     `ebpf:"sensitive_prefixes"`
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

	// 手动 attach
	tp, err := attachTracepointManual(p.objs.TraceOpenat, "/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat")
	if err != nil {
		p.objs.TraceOpenat.Close()
		return fmt.Errorf("attach tracepoint 失败: %w", err)
	}
	p.link = tp

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
// 流程：先清空两个 map，再逐条写入（清空窗口极短，可接受）。
func (p *FileProbe) UpdateSensitivePaths(exactPaths, prefixPaths []string) error {
	if p.objs == nil || p.objs.SensitiveExact == nil || p.objs.SensitivePrefixes == nil {
		return fmt.Errorf("探针未加载")
	}

	// 1. 清空 exact
	if err := clearMap(p.objs.SensitiveExact); err != nil {
		return fmt.Errorf("清空 exact 失败: %w", err)
	}
	// 2. 清空 prefixes
	if err := clearMap(p.objs.SensitivePrefixes); err != nil {
		return fmt.Errorf("清空 prefixes 失败: %w", err)
	}

	// 3. 写入 exact
	var val uint8 = 1
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

	// 4. 写入 prefixes（LPM key: 4字节 prefixlen + 256字节 path）
	for _, path := range prefixPaths {
		if len(path) > 255 {
			return fmt.Errorf("路径超长（>255）: %s", path)
		}
		keyBytes := make([]byte, 4+256)
		// prefixlen = len(path) * 8 bit（小端）
		prefixLen := uint32(len(path) * 8)
		keyBytes[0] = byte(prefixLen)
		keyBytes[1] = byte(prefixLen >> 8)
		keyBytes[2] = byte(prefixLen >> 16)
		keyBytes[3] = byte(prefixLen >> 24)
		copy(keyBytes[4:], path)

		if err := p.objs.SensitivePrefixes.Put(keyBytes, &val); err != nil {
			return fmt.Errorf("写入 prefix 失败 [%s]: %w", path, err)
		}
	}

	return nil
}

// clearMap 清空 map（遍历删除所有 key）
func clearMap(m *ebpf.Map) error {
	var key [256]byte
	var value uint8
	iter := m.Iterate()
	var toDelete [][256]byte
	for iter.Next(&key, &value) {
		k := key // 拷贝
		toDelete = append(toDelete, k)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range toDelete {
		if err := m.Delete(&k); err != nil {
			return err
		}
	}
	return nil
}

// Close 清理资源
func (p *FileProbe) Close() {
	if p.link != nil {
		p.link.Close()
		p.link = nil
	}
	if p.objs != nil {
		if p.objs.TraceOpenat != nil {
			p.objs.TraceOpenat.Close()
		}
		p.objs = nil
	}
}

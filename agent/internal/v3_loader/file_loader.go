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
	TraceOpenat      *ebpf.Program `ebpf:"trace_openat"`
	ConfigMap        *ebpf.Map     `ebpf:"config_map"`
	FileEvents       *ebpf.Map     `ebpf:"file_events"`
	SentinelWhitelist *ebpf.Map    `ebpf:"sentinel_whitelist"`
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

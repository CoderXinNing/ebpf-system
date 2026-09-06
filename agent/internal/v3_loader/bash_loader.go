package v3_loader

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// BashEventCallback bash 事件回调
type BashEventCallback func(header *SentinelEventHeader, line string)

// BashProbe V3 bash 探针
type BashProbe struct {
	objPath   string
	callback  BashEventCallback
	link      link.Link
	objs      *bashObjects
	agentHash uint32
	bashPath  string
}

type bashObjects struct {
	TraceReadline    *ebpf.Program `ebpf:"trace_readline"`
	ConfigMap        *ebpf.Map     `ebpf:"config_map"`
	BashEvents       *ebpf.Map     `ebpf:"bash_events"`
	SentinelWhitelist *ebpf.Map    `ebpf:"sentinel_whitelist"`
}

// NewBashProbe 创建 bash 探针
func NewBashProbe(objPath string, bashPath string, agentHash uint32, callback BashEventCallback) *BashProbe {
	return &BashProbe{
		objPath:   objPath,
		callback:  callback,
		agentHash: agentHash,
		bashPath:  bashPath,
	}
}

// Load 加载并 attach bash 探针
func (p *BashProbe) Load() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除内存锁失败: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(p.objPath)
	if err != nil {
		return fmt.Errorf("加载 spec 失败: %w", err)
	}

	p.objs = &bashObjects{}
	if err := spec.LoadAndAssign(p.objs, nil); err != nil {
		return fmt.Errorf("加载失败: %w", err)
	}

	// 写入 Config Map
	var key uint32 = ConfigAgentHash
	var value uint64 = uint64(p.agentHash)
	if err := p.objs.ConfigMap.Put(&key, &value); err != nil {
		return fmt.Errorf("写入 agent_hash 失败: %w", err)
	}

	// uretprobe attach
	ex, err := link.OpenExecutable(p.bashPath)
	if err != nil {
		p.objs.TraceReadline.Close()
		return fmt.Errorf("打开 bash 失败: %w", err)
	}

	tp, err := ex.Uretprobe("readline", p.objs.TraceReadline, nil)
	if err != nil {
		p.objs.TraceReadline.Close()
		return fmt.Errorf("attach uretprobe 失败: %w", err)
	}
	p.link = tp

	// Ring Buffer 读取
	rd, err := ringbuf.NewReader(p.objs.BashEvents)
	if err != nil {
		p.Close()
		return fmt.Errorf("创建 ring buffer reader 失败: %w", err)
	}

	log.Printf("✅ V3 bash 探针已启动")

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

			line := CString(header.Data[:])
			p.callback(header, line)
		}
	}()

	return nil
}

// Close 清理资源
func (p *BashProbe) Close() {
	if p.link != nil {
		p.link.Close()
		p.link = nil
	}
	if p.objs != nil {
		if p.objs.TraceReadline != nil {
			p.objs.TraceReadline.Close()
		}
		p.objs = nil
	}
}

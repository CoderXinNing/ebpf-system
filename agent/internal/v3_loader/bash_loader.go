package v3_loader

import (
	"fmt"
	"log"
	"sync"

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

	// 排除名单同步（记录上次 keys，用于清空重建）
	excludeMu        sync.Mutex
	lastExcludeComms []string
}

type bashObjects struct {
	TraceReadline        *ebpf.Program `ebpf:"trace_readline"`
	ConfigMap            *ebpf.Map     `ebpf:"config_map"`
	BashEvents           *ebpf.Map     `ebpf:"bash_events"`
	SentinelExcludeComms *ebpf.Map     `ebpf:"sentinel_exclude_comms"`
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

	// 启用排除列表（exclude_comms）
	var wlKey uint32 = ConfigExcludeComms
	var wlVal uint64 = 1
	if err := p.objs.ConfigMap.Put(&wlKey, &wlVal); err != nil {
		log.Printf("⚠️ 写 ConfigExcludeComms 失败: %v", err)
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

// UpdateExcludeComms 更新白名单
func (p *BashProbe) UpdateExcludeComms(processNames []string) error {
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

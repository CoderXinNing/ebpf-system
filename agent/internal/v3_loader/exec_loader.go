package v3_loader

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ExecEventCallback exec 事件回调
type ExecEventCallback func(header *SentinelEventHeader, cmdline string)

// ExecProbe V3 exec 探针
type ExecProbe struct {
	objPath   string
	callback  ExecEventCallback
	link      *ManualTracepointLink
	objs      *execObjects
	agentHash uint32
}

type execObjects struct {
	TraceExecve      *ebpf.Program `ebpf:"trace_execve"`
	ConfigMap        *ebpf.Map     `ebpf:"config_map"`
	SentinelEvents   *ebpf.Map     `ebpf:"exec_events"`
	SentinelWhitelist *ebpf.Map    `ebpf:"sentinel_whitelist"`
	PidCorrelations  *ebpf.Map     `ebpf:"pid_correlations"`
	PidPpidMap       *ebpf.Map     `ebpf:"pid_ppid_map"`
}

// NewExecProbe 创建 exec 探针
func NewExecProbe(objPath string, agentHash uint32, callback ExecEventCallback) *ExecProbe {
	return &ExecProbe{
		objPath:   objPath,
		callback:  callback,
		agentHash: agentHash,
	}
}

// Load 加载并 attach exec 探针
func (p *ExecProbe) Load() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除内存锁失败: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(p.objPath)
	if err != nil {
		return fmt.Errorf("加载 spec 失败: %w", err)
	}

	p.objs = &execObjects{}
	if err := spec.LoadAndAssign(p.objs, nil); err != nil {
		return fmt.Errorf("加载失败: %w", err)
	}

	// 在 Attach 之前写入 Config Map
	var key uint32 = ConfigAgentHash
	var value uint64 = uint64(p.agentHash)
	if err := p.objs.ConfigMap.Put(&key, &value); err != nil {
		return fmt.Errorf("写入 agent_hash 失败: %w", err)
	}

	// 手动 attach
	tp, err := attachTracepointManual(p.objs.TraceExecve, "/sys/kernel/debug/tracing/events/syscalls/sys_enter_execve")
	if err != nil {
		p.objs.TraceExecve.Close()
		return fmt.Errorf("attach tracepoint 失败: %w", err)
	}
	p.link = tp

	// 启动 Ring Buffer 读取
	rd, err := ringbuf.NewReader(p.objs.SentinelEvents)
	if err != nil {
		p.Close()
		return fmt.Errorf("创建 ring buffer reader 失败: %w", err)
	}

	log.Printf("✅ V3 exec 探针已启动")

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

			cmdline := CString(header.Data[:])
			p.callback(header, cmdline)
		}
	}()

	return nil
}

// GetPidCorrelations 返回 PID 关联 Map（用于父进程查询）
func (p *ExecProbe) GetPidCorrelations() *ebpf.Map {
	if p.objs != nil {
		return p.objs.PidCorrelations
	}
	return nil
}

// GetPidPpidMap 返回 PPID 关联 Map
func (p *ExecProbe) GetPidPpidMap() *ebpf.Map {
	if p.objs != nil {
		return p.objs.PidPpidMap
	}
	return nil
}

// Close 清理资源
func (p *ExecProbe) Close() {
	if p.link != nil {
		p.link.Close()
		p.link = nil
	}
	if p.objs != nil {
		if p.objs.TraceExecve != nil {
			p.objs.TraceExecve.Close()
		}
		p.objs = nil
	}
}

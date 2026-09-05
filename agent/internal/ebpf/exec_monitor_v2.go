package ebpf

import (
	"fmt"
	"github.com/cilium/ebpf"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ExecEventV2 是统一 header 格式的 exec 事件
type ExecEventV2 struct {
	Header     SentinelEventHeader
	Cmdline    string // data 字段
	ParentComm string // parent_comm 字段
}

type ExecCallbackV2 func(ExecEventV2)

// LoadExecMonitorV2 加载新格式的 exec 探针（统一 header + tracepoint）
func LoadExecMonitorV2(objPath string, callback ExecCallbackV2) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除内存锁失败: %w", err)
	}

	spec, err := loadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("加载 spec 失败: %w", err)
	}

	var objs struct {
		TraceExecve     *ebpf.Program `ebpf:"trace_execve"`
		SentinelEvents  *ebpf.Map     `ebpf:"sentinel_events"`
		SentinelWhitelist *ebpf.Map   `ebpf:"sentinel_whitelist"`
		SentinelHeartbeat *ebpf.Map   `ebpf:"sentinel_heartbeat"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("加载失败: %w", err)
	}

	// 挂载 tracepoint
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		objs.TraceExecve.Close()
		return fmt.Errorf("attach tracepoint 失败: %w", err)
	}

	// 创建 ring buffer reader
	rd, err := ringbuf.NewReader(objs.SentinelEvents)
	if err != nil {
		tp.Close()
		objs.TraceExecve.Close()
		return fmt.Errorf("创建 ring buffer reader 失败: %w", err)
	}

	log.Printf("✅ 新 exec 探针已启动 (统一 header + tracepoint)")

	go func() {
		defer rd.Close()
		defer tp.Close()
		defer objs.TraceExecve.Close()

		for {
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("⚠️ ring buffer 读取错误: %v", err)
				continue
			}

			// 统一解码（带长度校验）
			header, err := DecodeEvent(record.RawSample)
			if err != nil {
				log.Printf("⚠️ 事件解码失败: %v", err)
				continue
			}

			evt := ExecEventV2{
				Header:     *header,
				Cmdline:    header.Data,
				ParentComm: header.ParentComm,
			}
			callback(evt)
		}
	}()

	return nil
}

// loadCollectionSpec 封装 ebpf.LoadCollectionSpec
func loadCollectionSpec(path string) (*ebpf.CollectionSpec, error) {
	return ebpf.LoadCollectionSpec(path)
}

package ebpf

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// TCPEventV2 是统一 header 格式的 TCP 事件
type TCPEventV2 struct {
	Header SentinelEventHeader
}

type TCPCallbackV2 func(TCPEventV2)

// LoadTCPMonitorV2 加载新格式的 TCP 探针
func LoadTCPMonitorV2(objPath string, callback TCPCallbackV2) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除内存锁失败: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("加载 spec 失败: %w", err)
	}

	var objs struct {
		TraceConnect     *ebpf.Program `ebpf:"trace_connect"`
		SentinelEvents   *ebpf.Map     `ebpf:"sentinel_events"`
		SentinelWhitelist *ebpf.Map    `ebpf:"sentinel_whitelist"`
		TcpConnStats     *ebpf.Map     `ebpf:"tcp_conn_stats"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("加载失败: %w", err)
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceConnect, nil)
	if err != nil {
		objs.TraceConnect.Close()
		return fmt.Errorf("attach tracepoint 失败: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.SentinelEvents)
	if err != nil {
		tp.Close()
		objs.TraceConnect.Close()
		return fmt.Errorf("创建 ring buffer reader 失败: %w", err)
	}

	log.Printf("✅ 新 TCP 探针已启动 (统一 header + PERCPU_HASH)")

	go func() {
		defer rd.Close()
		defer tp.Close()
		defer objs.TraceConnect.Close()

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
				log.Printf("⚠️ 事件解码失败: %v", err)
				continue
			}

			evt := TCPEventV2{Header: *header}
			callback(evt)
		}
	}()

	return nil
}

package ebpf

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// TCPEventV2 是统一 header 格式的 TCP 事件
type TCPEventV2 struct {
	Header SentinelEventHeader
}

type TCPCallbackV2 func(TCPEventV2)

// LoadTCPMonitorV2 加载 TCP 探针，返回 map 和 link
func LoadTCPMonitorV2(objPath string, callback TCPCallbackV2) (*ebpf.Map, *ebpf.Map, *ManualTracepointLink, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, nil, fmt.Errorf("解除内存锁失败: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("加载 spec 失败: %w", err)
	}

	var objs struct {
		TraceConnect      *ebpf.Program `ebpf:"trace_connect"`
		SentinelEvents    *ebpf.Map     `ebpf:"sentinel_events"`
		SentinelWhitelist *ebpf.Map     `ebpf:"sentinel_whitelist"`
		PidConnMap        *ebpf.Map     `ebpf:"pid_conn_map"`
		ConnDetails       *ebpf.Map     `ebpf:"conn_details"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, nil, nil, fmt.Errorf("加载失败: %w", err)
	}

	// 手动 attach，绕过 cilium/ebpf 的 tracepoint ID 缓存竞态
	tp, err := attachTracepointManual(objs.TraceConnect, "/sys/kernel/debug/tracing/events/syscalls/sys_enter_connect")
	if err != nil {
		objs.TraceConnect.Close()
		return nil, nil, nil, fmt.Errorf("attach tracepoint 失败: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.SentinelEvents)
	if err != nil {
		tp.Close()
		objs.TraceConnect.Close()
		return nil, nil, nil, fmt.Errorf("创建 ring buffer reader 失败: %w", err)
	}

	log.Printf("✅ 新 TCP 探针已启动 (统一 header + PERCPU_HASH)")

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
				log.Printf("⚠️ 事件解码失败: %v", err)
				continue
			}

			evt := TCPEventV2{Header: *header}
			callback(evt)
		}
	}()

	return objs.PidConnMap, objs.ConnDetails, tp, nil
}

// LoadTCPMonitorV2Silent 加载 TCP 探针但不启动事件回调（只用于计数统计）
func LoadTCPMonitorV2Silent(objPath string) (*ebpf.Map, *ebpf.Map, *ManualTracepointLink, error) {
	pidMap, detailMap, tp, err := LoadTCPMonitorV2(objPath, func(evt TCPEventV2) {
		// 静默模式：默认只计数不上报
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return pidMap, detailMap, tp, nil
}

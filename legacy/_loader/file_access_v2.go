package ebpf

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// FileAccessEventV2 是文件访问事件
type FileAccessEventV2 struct {
	Header   SentinelEventHeader
	Filename string
}

type FileAccessCallbackV2 func(FileAccessEventV2)

// LoadFileAccessMonitorV2 加载文件访问探针，返回 link
func LoadFileAccessMonitorV2(objPath string, callback FileAccessCallbackV2) (*ManualTracepointLink, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("解除内存锁失败: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("加载 spec 失败: %w", err)
	}

	var objs struct {
		TraceOpenat    *ebpf.Program `ebpf:"trace_openat"`
		SentinelEvents *ebpf.Map     `ebpf:"sentinel_events"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("加载失败: %w", err)
	}

	// 手动 attach，绕过 cilium/ebpf 的 tracepoint ID 缓存竞态
	tp, err := attachTracepointManual(objs.TraceOpenat, "/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat")
	if err != nil {
		objs.TraceOpenat.Close()
		return nil, fmt.Errorf("attach tracepoint 失败: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.SentinelEvents)
	if err != nil {
		tp.Close()
		objs.TraceOpenat.Close()
		return nil, fmt.Errorf("创建 ring buffer reader 失败: %w", err)
	}

	log.Printf("✅ 文件访问探针已启动 (tracepoint + 统一 header)")

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

			evt := FileAccessEventV2{
				Header:   *header,
				Filename: header.Data,
			}
			callback(evt)
		}
	}()

	return tp, nil
}

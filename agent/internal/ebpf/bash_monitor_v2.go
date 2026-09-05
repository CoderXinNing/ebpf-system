package ebpf

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// BashEventV2 是统一 header 格式的 bash 事件
type BashEventV2 struct {
	Header SentinelEventHeader
	Line   string // data 字段（完整命令输入）
}

type BashCallbackV2 func(BashEventV2)

// LoadBashMonitorV2 加载新格式的 bash 探针
func LoadBashMonitorV2(objPath string, bashPath string, callback BashCallbackV2) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除内存锁失败: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("加载 spec 失败: %w", err)
	}

	var objs struct {
		TraceReadline    *ebpf.Program `ebpf:"trace_readline"`
		SentinelEvents   *ebpf.Map     `ebpf:"sentinel_events"`
		SentinelWhitelist *ebpf.Map    `ebpf:"sentinel_whitelist"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("加载失败: %w", err)
	}

	// 挂载 uprobe
	ex, err := link.OpenExecutable(bashPath)
	if err != nil {
		objs.TraceReadline.Close()
		return fmt.Errorf("打开 %s 失败: %w", bashPath, err)
	}

	up, err := ex.Uretprobe("readline", objs.TraceReadline, nil)
	if err != nil {
		objs.TraceReadline.Close()
		return fmt.Errorf("attach readline 失败: %w", err)
	}

	// ring buffer reader
	rd, err := ringbuf.NewReader(objs.SentinelEvents)
	if err != nil {
		up.Close()
		objs.TraceReadline.Close()
		return fmt.Errorf("创建 ring buffer reader 失败: %w", err)
	}

	log.Printf("✅ 新 bash 探针已启动 (统一 header + uretprobe)")

	go func() {
		defer rd.Close()
		defer up.Close()
		defer objs.TraceReadline.Close()

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

			evt := BashEventV2{
				Header: *header,
				Line:   header.Data,
			}
			callback(evt)
		}
	}()

	return nil
}

package ebpf

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// DNSEventV2 是 DNS 查询事件
type DNSEventV2 struct {
	Header SentinelEventHeader
	Domain string // data 字段
}

type DNSCallbackV2 func(DNSEventV2)

// LoadDNSMonitorV2 加载 DNS 监控探针
func LoadDNSMonitorV2(objPath string, callback DNSCallbackV2) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除内存锁失败: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("加载 spec 失败: %w", err)
	}

	var objs struct {
		TraceDnsQueryKprobe  *ebpf.Program `ebpf:"trace_dns_query_kprobe"`
		SentinelEvents *ebpf.Map     `ebpf:"sentinel_events"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("加载失败: %w", err)
	}

	// kprobe 挂载
	kp, err := link.Kprobe("dns_query", objs.TraceDnsQueryKprobe, nil)
	if err != nil {
		objs.TraceDnsQueryKprobe.Close()
		return fmt.Errorf("attach kprobe 失败: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.SentinelEvents)
	if err != nil {
		kp.Close()
		objs.TraceDnsQueryKprobe.Close()
		return fmt.Errorf("创建 ring buffer reader 失败: %w", err)
	}

	log.Printf("✅ DNS 监控探针已启动 (kprobe + 统一 header)")

	go func() {
		defer rd.Close()
		defer kp.Close()
		defer objs.TraceDnsQueryKprobe.Close()

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

			evt := DNSEventV2{
				Header: *header,
				Domain: header.Data,
			}
			callback(evt)
		}
	}()

	return nil
}

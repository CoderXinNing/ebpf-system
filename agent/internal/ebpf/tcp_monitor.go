package ebpf

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type ConnStat struct {
	PID   uint32
	Count uint64
}

type TCPCallback func(pid uint32, comm string, count uint64)

var tcpCB TCPCallback

func LoadTCPMonitor(callback TCPCallback) error {
	tcpCB = callback

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除内存锁失败: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec("probes/templates/tcp_monitor/tcp_monitor.o")
	if err != nil { return fmt.Errorf("加载spec失败: %w", err) }

	var objs struct {
		TraceConnect *ebpf.Program `ebpf:"trace_connect"`
		TcpConnStats *ebpf.Map     `ebpf:"tcp_conn_stats"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("加载失败: %w", err)
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceConnect, nil)
	if err != nil {
		objs.TraceConnect.Close()
		return fmt.Errorf("attach失败: %w", err)
	}

	os.MkdirAll("/sys/fs/bpf/ebpf-sentinel", 0755)
	objs.TraceConnect.Pin("/sys/fs/bpf/ebpf-sentinel/tcp_monitor")

	log.Printf("✅ TCP监控已启动 (tracepoint)")

	go func() {
		defer tp.Close()
		defer objs.TraceConnect.Close()

		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			var key [16]byte
			var vals []ConnStat
			iter := objs.TcpConnStats.Iterate()
			for iter.Next(&key, &vals) {
				var total uint64
				var pid uint32
				for _, v := range vals {
					total += v.Count
					if v.PID > 0 { pid = v.PID }
				}
				if total > 0 {
					comm := strings.TrimRight(string(key[:]), "\x00")
					log.Printf("TCP聚合: %s x%d次", comm, total)
					if tcpCB != nil { tcpCB(pid, comm, total) }
					objs.TcpConnStats.Delete(&key)
				}
			}
		}
	}()

	return nil
}

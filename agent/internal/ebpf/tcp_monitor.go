package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)
type TCPCallback func(pid uint32, comm string, count uint64)

var tcpCB TCPCallback

func LoadTCPMonitor(objPath string, callback TCPCallback) error {
	tcpCB = callback

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除内存锁失败: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("加载spec失败: %w", err)
	}

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
	if err := objs.TraceConnect.Pin("/sys/fs/bpf/ebpf-sentinel/tcp_monitor"); err != nil {
		log.Printf("⚠️ Pin tcp失败(已存在则复用): %v", err)
	}

	log.Printf("✅ TCP监控已启动 (tracepoint)")

	go func() {
		defer tp.Close()
		defer objs.TraceConnect.Close()

		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			var key [16]byte
			var rawVal []byte
			iter := objs.TcpConnStats.Iterate()
			for iter.Next(&key, &rawVal) {
				if len(rawVal) >= 16 {
					var pid uint32
					var count uint64
					binary.Read(bytes.NewReader(rawVal[0:4]), binary.LittleEndian, &pid)
					binary.Read(bytes.NewReader(rawVal[8:16]), binary.LittleEndian, &count)
					if count > 0 {
						comm := strings.TrimRight(string(key[:]), "\x00")
						log.Printf("TCP聚合: %s x%d次 (PID=%d)", comm, count, pid)
						if tcpCB != nil {
							tcpCB(pid, comm, count)
						}
						objs.TcpConnStats.Delete(&key)
					}
				}
			}
			if err := iter.Err(); err != nil {
				log.Printf("⚠️ TCP map遍历错误: %v", err)
			}
		}
	}()

	return nil
}

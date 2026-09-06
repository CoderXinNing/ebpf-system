package agent

import (
	"log"

	"github.com/cilium/ebpf"
)

// findParentCorrelationKey 向上查找父进程的 correlation_key
func findParentCorrelationKey(pid uint32, pidPpidMap *ebpf.Map, depth int) uint64 {
	if depth > 5 {
		return 0 // 最多向上查 5 层
	}

	if pidPpidMap == nil {
		log.Printf("⚠️ pidPpidMap 为 nil")
		return 0
	}

	var ppid uint32
	if err := pidPpidMap.Lookup(&pid, &ppid); err != nil {
		return 0
	}

	if ppid == 0 || ppid == pid {
		return 0
	}

	log.Printf("🔗 父进程: PID=%d → PPID=%d", pid, ppid)
	return uint64(ppid)
}

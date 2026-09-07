package agent

import (
	"log"

	"github.com/cilium/ebpf"
)

// findParentCorrelationKey 向上递归查找父进程的 correlation_key
// 找到最近的有 correlation_id 的祖先进程（锚点）
func findParentCorrelationKey(pid uint32, pidPpidMap *ebpf.Map, correlationMgr *CorrelationManager, depth int) uint64 {
	if depth > 5 {
		return 0 // 最多向上查 5 层
	}

	if pidPpidMap == nil || correlationMgr == nil {
		return 0
	}

	// 检查当前 PID 是否有 correlation_id
	if correlationMgr.Has(uint64(pid)) {
		return uint64(pid)
	}

	// 查父 PID
	var ppid uint32
	if err := pidPpidMap.Lookup(&pid, &ppid); err != nil {
		return 0
	}

	if ppid == 0 || ppid == pid {
		return 0
	}

	log.Printf("🔗 向上回溯: PID=%d → PPID=%d (depth=%d)", pid, ppid, depth)

	// 递归查父进程
	return findParentCorrelationKey(ppid, pidPpidMap, correlationMgr, depth+1)
}

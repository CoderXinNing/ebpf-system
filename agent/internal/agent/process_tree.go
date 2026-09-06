package agent

import (
	"log"

	"github.com/cilium/ebpf"
)

// PidContext 进程上下文（与 C 层 pid_context 对应）
type PidContext struct {
	PPID    uint32
	Comm    [16]byte
	Cmdline [256]byte
}

// findParentCorrelationKey 向上查找父进程的 correlation_key
func findParentCorrelationKey(pid uint32, pidMap *ebpf.Map, depth int) uint64 {
	if depth > 5 {
		return 0 // 最多向上查 5 层
	}

	if pidMap == nil {
		return 0
	}

	var ctx PidContext
	if err := pidMap.Lookup(&pid, &ctx); err != nil {
		return 0
	}

	// 父 PID 为 0 或等于自己，停止
	if ctx.PPID == 0 || ctx.PPID == pid {
		return 0
	}

	log.Printf("🔗 父进程: PID=%d → PPID=%d", pid, ctx.PPID)
	return uint64(ctx.PPID)
}

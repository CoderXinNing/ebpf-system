//go:build e2e

// 本测试为端到端调试脚本，需要：
//   - root 权限
//   - 真实内核（BPF verifier / tracepoint / kprobe）
//   - 已编译的 .o 文件
//
// 默认不跑（go test ./... 秒过）。
// 手动跑：go test -tags=e2e -v ./agent/internal/v3_loader/ -run TestXxx
//
// 背景：cilium/ebpf 的 ringbuf.Reader 无法从外部安全打断 Read
// （Close/SetDeadline 与 Read 争锁），所以这类测试不能做常规单测。
package v3_loader

import (
	"log"
	"testing"
	"time"
)

func TestExecProbeLoad(t *testing.T) {
	agentHash := uint32(0x12345678)

	probe := NewExecProbe(
		"../../../v3_engine/probes/exec_monitor.o",
		agentHash,
		func(header *SentinelEventHeader, cmdline string) {
			log.Printf("✅ exec 事件: PID=%d CMD=%s", header.PID, cmdline)
		},
	)

	if err := probe.Load(); err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	defer probe.Close() // 唤醒 reader goroutine，否则测试挂死

	log.Println("exec 探针加载成功，执行测试命令...")
	time.Sleep(3 * time.Second)

	log.Println("测试结束")
}

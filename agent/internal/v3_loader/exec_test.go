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
    
    log.Println("exec 探针加载成功，执行测试命令...")
    time.Sleep(3 * time.Second)
    
    log.Println("测试结束")
}

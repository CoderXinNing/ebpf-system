package v3_loader

import (
    "log"
    "net"
    "testing"
    "time"
)

func TestTCPModeSwitch(t *testing.T) {
    agentHash := uint32(0x12345678)
    eventCount := 0

    probe := NewTCPProbe(
        "../../../v3_engine/probes/tcp_monitor.o",
        agentHash,
        func(header *SentinelEventHeader, detail *TCPConnDetail) {
            eventCount++
            log.Printf("✅ TCP 明细事件: PID=%d DstIP=%d.%d.%d.%d DstPort=%d",
                header.PID,
                (detail.DstIP>>24)&0xFF, (detail.DstIP>>16)&0xFF, (detail.DstIP>>8)&0xFF, detail.DstIP&0xFF,
                detail.DstPort)
        },
    )

    if err := probe.Load(); err != nil {
        t.Fatalf("加载失败: %v", err)
    }
    defer probe.Close()

    log.Println("=== 默认计数模式 ===")
    time.Sleep(2 * time.Second)

    log.Println("=== 切换到明细模式 ===")
    if err := probe.SetCollectMode(CollectModeDetail); err != nil {
        t.Fatalf("切换失败: %v", err)
    }
    log.Println("✅ 已切换到明细模式")

    // 触发 TCP 连接
    log.Println("触发 TCP 连接...")
    for i := 0; i < 3; i++ {
        conn, err := net.Dial("tcp", "127.0.0.1:8080")
        if err == nil {
            conn.Close()
        }
        time.Sleep(100 * time.Millisecond)
    }

    time.Sleep(3 * time.Second)

    if eventCount > 0 {
        log.Printf("✅ 测试通过：收到 %d 个 TCP 明细事件", eventCount)
    } else {
        log.Println("⚠️ 未收到 TCP 明细事件")
    }
}

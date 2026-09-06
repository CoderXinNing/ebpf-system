package v3_loader

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	
)

// 模拟 Agent 哈希生成（与正式 Agent 逻辑一致）
func generateAgentHash(agentID string) uint32 {
	// 取 Agent ID 前 8 字节做哈希
	if len(agentID) > 8 {
		agentID = agentID[:8]
	}
	var hash uint32
	for _, c := range []byte(agentID) {
		hash = hash*31 + uint32(c)
	}
	return hash
}

// 生成 local_correlation_id（与正式 Agent 逻辑一致）
func generateLocalCorrelationID(agentID string, correlationKey uint64, timestamp uint64) string {
	// 随机 4 字节
	randomBytes := make([]byte, 4)
	rand.Read(randomBytes)
	randomHex := hex.EncodeToString(randomBytes)

	// 截取 Agent ID 前 8 位
	agentPrefix := agentID
	if len(agentPrefix) > 8 {
		agentPrefix = agentPrefix[:8]
	}

	// 秒级时间戳
	secTimestamp := timestamp / 1000000000 // ns → s

	return fmt.Sprintf("%s-%d-%s", agentPrefix, secTimestamp, randomHex)
}

func TestTCPProbeLoad(t *testing.T) {
	objPath := "../../../v3_engine/probes/tcp_monitor.o"
	if _, err := os.Stat(objPath); os.IsNotExist(err) {
		t.Skip("tcp_monitor.o 不存在，跳过测试")
	}

	agentID := "test-agent-001"
	agentHash := generateAgentHash(agentID)

	eventCount := 0
	corrIDCache := make(map[uint64]string)
	probe := NewTCPProbe(objPath, agentHash, func(header *SentinelEventHeader, detail *TCPConnDetail) {
		eventCount++
		log.Printf("✅ TCP 事件: PID=%d, DstIP=%d.%d.%d.%d, DstPort=%d",
			header.PID,
			(detail.DstIP>>24)&0xFF, (detail.DstIP>>16)&0xFF, (detail.DstIP>>8)&0xFF, detail.DstIP&0xFF,
			detail.DstPort)
		
		var corrID string
		if cached, ok := corrIDCache[header.CorrelationKey]; ok {
			corrID = cached
		} else {
			corrID = generateLocalCorrelationID(agentID, header.CorrelationKey, header.Timestamp)
			corrIDCache[header.CorrelationKey] = corrID
		}
		log.Printf("   correlation_key=%d → local_correlation_id=%s", header.CorrelationKey, corrID)
	})

	if err := probe.Load(); err != nil {
		t.Fatalf("TCP 探针加载失败: %v", err)
	}
	defer probe.Close()

	log.Println("✅ TCP 探针加载成功，等待 5 秒后切换到明细模式...")
	time.Sleep(5 * time.Second)

	// 切换到明细模式
	if err := probe.SetCollectMode(CollectModeDetail); err != nil {
		t.Fatalf("切换明细模式失败: %v", err)
	}
	log.Println("✅ 已切换到明细模式")

	// 触发 TCP 连接
	log.Println("触发 TCP 连接...")
	triggerTCPConnections()

	// 等待事件
	time.Sleep(5 * time.Second)

	if eventCount > 0 {
		log.Printf("✅ 测试通过：收到 %d 个 TCP 事件", eventCount)
	} else {
		log.Println("⚠️ 测试警告：未收到 TCP 事件")
	}

	// 等待 Ctrl+C 退出
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	log.Println("按 Ctrl+C 退出...")
	<-sig
}

func triggerTCPConnections() {
	// 触发一些本地连接
	go func() {
		for i := 0; i < 3; i++ {
			conn, err := net.Dial("tcp", "127.0.0.1:8080")
			if err == nil {
				conn.Close()
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
}

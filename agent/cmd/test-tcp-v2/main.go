package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/CoderXinNing/ebpf-system/agent/internal/ebpf"
)

func main() {
	fmt.Println("测试 tcp_v2...")

	callback := func(evt ebpf.TCPEventV2) {
		fmt.Printf("📡 tcp: PID=%d UID=%d comm=%s data=%s\n",
			evt.Header.PID, evt.Header.UID, evt.Header.Comm, evt.Header.Data)
	}

	err := ebpf.LoadTCPMonitorV2("probes/new/tcp_monitor/tcp_monitor.o", callback)
	if err != nil {
		log.Fatalf("❌ 加载失败: %v", err)
	}

	fmt.Println("✅ 已加载，在浏览器或另一个终端访问网络...")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
}

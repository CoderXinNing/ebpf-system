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
	fmt.Println("测试 dns_monitor...")

	callback := func(evt ebpf.DNSEventV2) {
		fmt.Printf("📡 dns: PID=%d comm=%s domain=%s\n",
			evt.Header.PID, evt.Header.Comm, evt.Domain)
	}

	err := ebpf.LoadDNSMonitorV2("probes/new/dns_monitor/dns_monitor.o", callback)
	if err != nil {
		log.Fatalf("❌ 加载失败: %v", err)
	}

	fmt.Println("✅ 已加载，在另一个终端做 DNS 查询...")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
}

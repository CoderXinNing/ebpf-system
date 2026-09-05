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
	fmt.Println("测试 bash_v2...")

	callback := func(evt ebpf.BashEventV2) {
		fmt.Printf("📡 bash: PID=%d UID=%d comm=%s line=%s\n",
			evt.Header.PID, evt.Header.UID, evt.Header.Comm, evt.Line)
	}

	err := ebpf.LoadBashMonitorV2("probes/new/bash_monitor/bash_monitor.o", "/bin/bash", callback)
	if err != nil {
		log.Fatalf("❌ 加载失败: %v", err)
	}

	fmt.Println("✅ 已加载，在另一个终端输入命令测试...")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
}

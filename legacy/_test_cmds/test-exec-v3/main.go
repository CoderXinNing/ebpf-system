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
	fmt.Println("测试 exec_v2...")

	callback := func(evt ebpf.ExecEventV2) {
		fmt.Printf("📡 exec: PID=%d PPID=%d UID=%d comm=%s parent=%s cmd=%s\n",
			evt.Header.PID, evt.Header.PPID, evt.Header.UID,
			evt.Header.Comm, evt.ParentComm, evt.Cmdline)
	}

	err := ebpf.LoadExecMonitorV2("probes/new/exec_monitor/exec_monitor.o", callback)
	if err != nil {
		log.Fatalf("❌ 加载失败: %v", err)
	}

	fmt.Println("✅ 已加载，等待事件...")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
}

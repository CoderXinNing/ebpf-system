package main

import (
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/CoderXinNing/ebpf-system/agent/internal/ebpf"
)

func main() {
	cfg := ebpf.XDPConfig{
		SrcIP:   net.ParseIP("172.16.2.141"),
		DstIP:   net.ParseIP("172.16.2.141"),
		SrcPort: 12345,
		DstPort: 9999,
		SrcMAC:  net.HardwareAddr{0x00, 0x0c, 0x29, 0x35, 0xea, 0xfa},
		DstMAC:  net.HardwareAddr{0x00, 0x0c, 0x29, 0x35, 0xea, 0xfa},
		Iface:   "ens33",
	}

	_, _, err := ebpf.LoadXDPReporter(cfg, func(evt ebpf.XDPEvent) {
		log.Printf("📡 XDP: type=%d comm=%s", evt.EventType, string(evt.Comm[:]))
	})
	if err != nil {
		log.Fatalf("❌ %v", err)
	}

	log.Println("✅ XDP ring buffer运行中...")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
}

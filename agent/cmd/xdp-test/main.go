package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/CoderXinNing/ebpf-system/agent/internal/ebpf"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	// 连接Server
	conn, err := grpc.Dial("127.0.0.1:50051",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		log.Fatalf("❌ 连接Server失败: %v", err)
	}
	defer conn.Close()
	client := pb.NewSentinelClient(conn)

	cfg := ebpf.XDPConfig{
		SrcIP:   net.ParseIP("172.16.2.141"),
		DstIP:   net.ParseIP("172.16.2.141"),
		SrcPort: 12345,
		DstPort: 9999,
		SrcMAC:  net.HardwareAddr{0x00, 0x0c, 0x29, 0x35, 0xea, 0xfa},
		DstMAC:  net.HardwareAddr{0x00, 0x0c, 0x29, 0x35, 0xea, 0xfa},
		Iface:   "ens33",
	}

	_, _, err = ebpf.LoadXDPReporter(cfg, func(evt ebpf.XDPEvent) {
		// 上报到Server
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		client.ReportEvents(ctx, &pb.EventReport{
			AgentId:    "xdp-reporter",
			AgentToken: "xdp",
			Events: []*pb.ProbeEvent{{
				ProbeName: "xdp",
				Timestamp: time.Now().Unix(),
				EventType: "xdp_packet",
				Pid:       int32(evt.PID),
				Comm:      string(evt.Comm[:]),
				Filename:  string(evt.Filename[:]),
			}},
		})
		log.Printf("📤 已上报Server")
	})
	if err != nil {
		log.Fatalf("❌ %v", err)
	}

	log.Println("✅ XDP上报链路运行中...")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
}

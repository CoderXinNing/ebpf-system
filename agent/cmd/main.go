package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/CoderXinNing/ebpf-system/agent/internal/agent"
	"github.com/CoderXinNing/ebpf-system/agent/internal/config"
)

var (
	configPath = flag.String("config", "agent/configs/agent.toml", "配置文件路径")
	genConfig  = flag.Bool("gen-config", false, "生成默认配置文件")
)

func main() {
	flag.Parse()
	if *genConfig {
		config.GenerateDefault(*configPath)
		return
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("❌ 配置加载失败: %v", err)
	}

	ag := agent.New(cfg)
	if err := ag.Init(); err != nil {
		log.Fatalf("❌ 环境初始化失败: %v", err)
	}

	// 使用 context 贯穿全生命周期
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 信号处理：收到 SIGINT/SIGTERM 时取消 context
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Printf("🛑 收到信号 %v，准备优雅退出...", sig)
		cancel()
	}()

	// 运行 Agent（阻塞直到 ctx 被取消）
	ag.Run(ctx)

	// 优雅退出
	ag.Shutdown()
	log.Println("✅ Agent 已优雅退出")
}

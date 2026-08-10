package main

import (
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
	if err != nil { log.Fatalf("❌ 配置加载失败: %v", err) }

	ag := agent.New(cfg)
	if err := ag.Init(); err != nil {
		log.Fatalf("❌ %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("\n🛑 退出...")
		ag.Shutdown()
		os.Exit(0)
	}()

	ag.Run()
}

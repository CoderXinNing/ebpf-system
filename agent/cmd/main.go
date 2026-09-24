package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/CoderXinNing/ebpf-system/agent/internal/agent"
	"github.com/CoderXinNing/ebpf-system/agent/internal/config"
	"github.com/CoderXinNing/ebpf-system/agent/internal/enroll"
	"github.com/CoderXinNing/ebpf-system/agent/internal/paths"
)

func main() {
	// 子命令路由
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "enroll":
			runEnroll(os.Args[2:])
			return
		case "version":
			fmt.Println("AsterTrack Agent v1.0.0")
			return
		case "help", "-h", "--help":
			printUsage()
			return
		}
	}

	runAgent()
}

// runEnroll 执行 enrollment
func runEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	serverURL := fs.String("server", "", "Server URL（如 http://172.16.2.145:8080）")
	token := fs.String("token", "", "注册 Token（ATK-xxx）")
	installDir := fs.String("install-dir", "/opt/astertrack", "安装目录")
	hostname := fs.String("hostname", "", "主机名（默认自动获取）")
	fs.Parse(args)

	if *serverURL == "" || *token == "" {
		fmt.Println("❌ 缺少必要参数")
		fmt.Println("用法: agent enroll --server=http://x.x.x.x:8080 --token=ATK-xxx")
		os.Exit(1)
	}

	_, err := enroll.Run(enroll.Config{
		ServerURL:  *serverURL,
		Token:      *token,
		InstallDir: *installDir,
		Hostname:   *hostname,
	})
	if err != nil {
		log.Fatalf("❌ Enrollment 失败: %v", err)
	}
}

// runAgent 正常启动 Agent
func runAgent() {
	configPath := flag.String("config", "", "配置文件路径（默认 ASTERTRACK_ROOT/agent/configs/agent.toml）")
	genConfig := flag.Bool("gen-config", false, "生成默认配置文件")
	flag.Parse()

	// 初始化路径（环境变量 ASTERTRACK_ROOT > cwd）
	// ⚠️ 必须在 flag.Parse() 之后、任何路径求值之前调用
	paths.Init()

	// 未指定 config 时用默认路径（Init 后才能求值）
	if *configPath == "" {
		*configPath = paths.Join("agent", "configs", "agent.toml")
	}

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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Printf("🛑 收到信号 %v，准备优雅退出...", sig)
		cancel()
	}()

	ag.Run(ctx)
	ag.Shutdown()
	log.Println("✅ Agent 已优雅退出")
}

// printUsage 打印帮助
func printUsage() {
	fmt.Println(`AsterTrack Agent v1.0.0

用法:
  agent                                  启动 Agent
  agent --config <path>                  指定配置文件启动
  agent enroll --server=<url> --token=<t> 首次安装（enrollment）
  agent version                          查看版本
  agent help                             查看帮助

示例:
  # 首次安装
  agent enroll --server=http://172.16.2.145:8080 --token=ATK-xxx

  # 正常启动
  agent --config /opt/astertrack/agent.toml`)
}

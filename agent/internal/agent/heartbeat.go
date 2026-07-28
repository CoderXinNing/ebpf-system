package agent

import (
	"context"
	"log"
	"time"

	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
)

func (a *Agent) HeartbeatLoop() {
	for {
		stream, err := a.client.Heartbeat(context.Background())
		if err != nil {
			log.Printf("⚠️ 心跳流建立失败: %v", err)
			time.Sleep(a.cfg.Agent.RetryDelay)
			continue
		}
		log.Println("💓 心跳流已建立")

		done := make(chan struct{})
		go func() {
			ticker := time.NewTicker(a.cfg.Agent.HeartbeatInterval)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					stream.Send(&pb.HeartbeatRequest{
						AgentId:      a.id,
						AgentToken:   a.token,
						Timestamp:    time.Now().Unix(),
						ActiveProbes: int32(len(a.pluginMgr.ListPlugins())),
					})
				}
			}
		}()

		for {
			resp, err := stream.Recv()
			if err != nil {
				close(done)
				break
			}
			if resp.Success && len(resp.Commands) > 0 {
				for _, cmd := range resp.Commands {
					a.handleCommand(cmd)
				}
			}
		}
		time.Sleep(a.cfg.Agent.RetryDelay)
	}
}

func (a *Agent) handleCommand(cmd *pb.ProbeCommand) {
	switch cmd.Type {
	case pb.ProbeCommand_LOAD:
		log.Printf("📥 Server指令: 加载 %s", cmd.ProbeName)
		a.pluginMgr.LoadSingle(cmd.ProbeName)
	case pb.ProbeCommand_UNLOAD:
		log.Printf("📤 Server指令: 卸载 %s", cmd.ProbeName)
		a.pluginMgr.Unload(cmd.ProbeName)
	case pb.ProbeCommand_RELOAD:
		log.Println("🔄 Server指令: 重新扫描")
		a.pluginMgr.ScanAndLoad()
	case pb.ProbeCommand_INSTALL:
		log.Printf("📦 Server指令: 安装 %s", cmd.ProbeName)
		a.pluginMgr.InstallProbe(cmd.ProbeName, cmd.ProbeData, cmd.ProbeConfig)
	}
}

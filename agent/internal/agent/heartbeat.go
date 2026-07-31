package agent

import (
	"context"
	"log"
	"time"

	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
)

func (a *Agent) runHeartbeatLoop() {
	for {
		// 确保已注册
		a.connectAndRegister()
		if a.token == "" {
			log.Printf("❌ 注册失败: %v, 重试...", nil)
			time.Sleep(a.cfg.Agent.RetryDelay)
			continue
		}

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
						ActiveProbes: 0,
					})
				}
			}
		}()

		for {
			resp, err := stream.Recv()
			if err != nil {
				log.Printf("⚠️ 心跳流断开: %v, 将重新注册...", err)
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
	case pb.ProbeCommand_SET_GROUP:
		log.Printf("📋 修改分组: %s", cmd.GroupName)
		// 更新配置文件和localStorage下次启动生效
		// 更新配置文件
	case pb.ProbeCommand_COLLECT:
		log.Println("🔄 手动触发: 全量资产采集")
		a.collectAndReportAssets()
	}
}

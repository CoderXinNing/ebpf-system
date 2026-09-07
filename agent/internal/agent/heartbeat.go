package agent

import (
	"context"
	"log"
	"time"

	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/plugins"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
)

func (a *Agent) runHeartbeatLoop() {
	a.runHeartbeatLoopWithCtx(context.Background())
}

func (a *Agent) runHeartbeatLoopWithCtx(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.Agent.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("💓 心跳循环停止")
			return
		case <-ticker.C:
			// 检查 ctx 是否已取消
			select {
			case <-ctx.Done():
				log.Println("💓 心跳循环停止")
				return
			default:
			}
		// 确保已注册
		if a.token == "" {
			continue
		}

		log.Printf("💓 心跳发送中...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := a.client.Heartbeat(a.getAuthContext(ctx), &pb.HeartbeatRequest{
			AgentId:           a.id,
			Timestamp:         time.Now().Unix(),
			ActiveProbes:      a.getActiveProbeCount(),
			ProbeDetails:      a.getProbeDetailsJSON(),
			BaselineState:     a.baseline.GetState().String(),
			BaselineRemaining: int64(a.baseline.RemainingTime().Seconds()),
		})
		cancel()

		if err != nil {
			log.Printf("⚠️ 心跳失败: %v", err)
			if err := a.connectAndRegister(); err != nil {
				log.Printf("⚠️ 重连失败: %v", err)
			}
			continue
		}

		updateHeartbeatMap()

		if resp.Success && len(resp.Commands) > 0 {
			for _, cmd := range resp.Commands {
				a.handleCommand(cmd)
			}
		}
		}
	}
}

func (a *Agent) handleCommand(cmd *pb.ProbeCommand) {
	switch cmd.Type {
	case pb.ProbeCommand_SET_GROUP:
		log.Printf("📋 修改分组: %s", cmd.GroupName)
	case pb.ProbeCommand_COLLECT:
		log.Println("🔄 手动触发: 全量资产采集")
		a.collectAndReportAssets()
	case pb.ProbeCommand_ACTIVATE_STAR:
		log.Printf("⭐ 收到星轨激活命令: corrID=%s", cmd.ProbeConfig)
		a.starCorrelationID = cmd.ProbeConfig
		if tcpProbe, exists := a.probeManager.Get("tcp_monitor"); exists {
			if tp, ok := tcpProbe.(*plugins.TCPProbe); ok {
				if err := tp.SetCollectMode(1); err != nil {
					log.Printf("⚠️ TCP 切明细失败: %v", err)
				} else {
					log.Println("✅ TCP 已切明细模式")
				}
			}
		}
	}
}

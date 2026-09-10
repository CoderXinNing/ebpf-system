package agent

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/framework"
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

// updateWhitelist 更新所有探针的白名单
func (a *Agent) updateWhitelist(jsonData string) {
	var processNames []string
	if err := json.Unmarshal([]byte(jsonData), &processNames); err != nil {
		log.Printf("⚠️ 白名单解析失败: %v", err)
		return
	}

	// 遍历所有探针，更新白名单
	for _, probeName := range []string{"exec_monitor", "bash_monitor", "tcp_monitor", "file_access"} {
		if probeInst, exists := a.probeManager.Get(probeName); exists {
			// 通过 UpdateRules 接口传递白名单
			_ = probeInst.UpdateRules([]framework.Rule{
				{Key: "whitelist", Value: jsonData, Op: "add"},
			})
		}
	}
	log.Printf("✅ 白名单已更新: %d 个进程", len(processNames))
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
		// 升级观察等级到 FULL
		if a.observationMgr != nil {
			a.observationMgr.Upgrade("星轨激活")
		}
		if tcpProbe, exists := a.probeManager.Get("tcp_monitor"); exists {
			if tp, ok := tcpProbe.(*plugins.TCPProbe); ok {
				if err := tp.SetCollectMode(1); err != nil {
					log.Printf("⚠️ TCP 切明细失败: %v", err)
				} else {
					log.Println("✅ TCP 已切明细模式")
				}
			}
		}
	case pb.ProbeCommand_UNLOAD:
		// 白名单更新命令：ProbeConfig 传 JSON 数组
		log.Printf("📋 收到白名单更新: %s", cmd.ProbeConfig)
		a.updateWhitelist(cmd.ProbeConfig)
	}
}

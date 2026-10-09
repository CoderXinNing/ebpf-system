package agent

import (
	"context"
	"log"
	"time"

	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
)

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
			rpcCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			// 动态规则状态（阶段 3）
			rulesStatus, rulesVersion, rulesLastCheck := a.getRulesStatus()

			// P1.9 A1 收尾：agent_pids 计数
			agentPidCount := 0
			if a.fileProbe != nil {
				agentPidCount = a.fileProbe.CountAgentPids()
			}

			resp, err := a.client.Heartbeat(a.getAuthContext(rpcCtx), &pb.HeartbeatRequest{
				AgentId:             a.id,
				Timestamp:           time.Now().Unix(),
				ActiveProbes:        a.getActiveProbeCount(),
				ProbeDetails:        a.getProbeDetailsJSON(),
				BaselineState:       a.baseline.GetState().String(),
				BaselineRemaining:   int64(a.baseline.RemainingTime().Seconds()),
				RulesVersion:        rulesVersion,
				RulesStatus:         rulesStatus,
				RulesLastCheck:      rulesLastCheck,
				AgentPidCount:       int32(agentPidCount),
				AgentPidCleanedLast: a.agentPidCleanedLast.Load(),
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

			// Server 不认识了（比如 Server 重启），触发重新注册
			if !resp.Success {
				log.Printf("⚠️ 心跳被拒绝（Server 内存中无此 Agent），尝试重新注册...")
				if err := a.connectAndRegister(); err != nil {
					log.Printf("⚠️ 重新注册失败: %v", err)
				}
				continue
			}

			// #1 规则秒级生效：Server 说版本不对 → 投信号
			if resp.RulesStale {
				select {
				case a.rulesSyncTrigger <- struct{}{}:
					log.Printf("⚡ 心跳提示规则版本不一致，触发立即拉取")
				default:
				}
			}

			if len(resp.Commands) > 0 {
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
		log.Printf("⭐ 收到星轨激活命令: %s", cmd.ProbeConfig)
		a.activateStar(cmd.ProbeConfig)
		// 升级观察等级到 FULL
		if a.observationMgr != nil {
			a.observationMgr.Upgrade("星轨激活")
		}
		a.switchTCPCollectMode(1)
	default:
		log.Printf("⚠️ 收到未知命令类型: %v，忽略", cmd.Type)
	}
}

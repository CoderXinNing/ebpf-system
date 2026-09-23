package agent

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/framework"
)

// probeEventTracker 高频事件埋点（sync.Map + atomic，零分配、无锁）
//
// ⚠️ 热路径：仅允许 Store 时间戳，禁止在此路径读判定/写状态。
// 所有状态判定由 ProbeStateActor 完成（状态机唯一写者）。
type probeEventTracker struct {
	m sync.Map // map[string]*atomic.Int64
}

func (t *probeEventTracker) mark(name string) {
	v, ok := t.m.Load(name)
	if !ok {
		v = new(atomic.Int64)
		t.m.Store(name, v)
	}
	v.(*atomic.Int64).Store(time.Now().UnixNano())
}

func (t *probeEventTracker) last(name string) time.Time {
	v, ok := t.m.Load(name)
	if !ok {
		return time.Time{}
	}
	ns := v.(*atomic.Int64).Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// markProbeEvent 事件埋点入口，在 handleXxxEvent 回调里调用
func (a *Agent) markProbeEvent(name string) {
	a.probeEventTracker.mark(name)
}

// getProbeLastEventAt 读取某探针最近一次事件时间
func (a *Agent) getProbeLastEventAt(name string) time.Time {
	return a.probeEventTracker.last(name)
}

// probeSelfTestLoop 定期执行探针自检
func (a *Agent) probeSelfTestLoop(ctx context.Context) {
	if !a.cfg.Selftest.Enabled {
		log.Println("🔬 [SELFTEST] 自检已禁用（配置）")
		return
	}

	// 启动后等 30 秒，让探针先加载完
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}

	a.runProbeSelfTest() // 首轮

	interval := time.Duration(a.cfg.Selftest.IntervalMinutes) * time.Minute
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("🔬 [SELFTEST] 自检循环停止")
			return
		case <-ticker.C:
			a.runProbeSelfTest()
		}
	}
}

// runProbeSelfTest 对每个已加载探针执行一次自检
func (a *Agent) runProbeSelfTest() {
	probes := a.probeManager.List()
	if len(probes) == 0 {
		return
	}

	waitSec := a.cfg.Selftest.WaitSeconds
	if waitSec <= 0 {
		waitSec = 3
	}
	opts := framework.SelfTestOptions{
		TCPTarget:         a.cfg.Selftest.TCPTarget,
		XDPFallbackTarget: a.cfg.Selftest.XDPFallbackTarget,
		FileTarget:        a.cfg.Selftest.FileTarget,
	}

	for _, p := range probes {
		name := p.Name()

		if !a.isProbeLoaded(name) {
			continue
		}

		st, ok := p.(framework.SelfTester)
		if !ok {
			// 不支持自检（如 bash），交给 actor 记录状态
			a.probeStateActor.Send(msgRunSelfTestCheck{
				name:        name,
				unsupported: true,
			})
			continue
		}

		before := a.getProbeLastEventAt(name)

		if err := st.SelfTestAction(opts); err != nil {
			log.Printf("🔬 [SELFTEST] %s 自检动作失败: %v", name, err)
			a.probeStateActor.Send(msgRunSelfTestCheck{
				name:        name,
				lastEventAt: before,
				selfTestOK:  false,
			})
			continue
		}

		time.Sleep(time.Duration(waitSec) * time.Second)

		after := a.getProbeLastEventAt(name)
		ok2 := after.After(before)
		if ok2 {
			log.Printf("🔬 [SELFTEST] %s 通过", name)
		} else {
			log.Printf("🔬 [SELFTEST] %s 未收到事件（wait=%ds）", name, waitSec)
		}

		a.probeStateActor.Send(msgRunSelfTestCheck{
			name:        name,
			lastEventAt: after,
			selfTestOK:  ok2,
		})
	}

	a.reportProbeStatus()
}

// isProbeLoaded 判断探针是否已加载成功（从缓存非阻塞读）
func (a *Agent) isProbeLoaded(name string) bool {
	status := a.probeState.GetProbeStatus(name)
	return status == "loaded" ||
		status == "loaded-silent" ||
		status == "loaded-no-activity"
}

// reportProbeStatus 上报探针状态给 Server
// Day A：仅打日志占位；Day B 接入 ReportProbeStatus RPC
func (a *Agent) reportProbeStatus() {
	result, err := a.probeStateActor.Ask(msgGetProbeDetails{}, 500*time.Millisecond)
	if err != nil {
		log.Printf("🔬 [SELFTEST] 读取探针详情超时: %v", err)
		return
	}
	details, ok := result.(map[string]ProbeDetail)
	if !ok {
		return
	}
	for name, d := range details {
		log.Printf("🔬 [SELFTEST] %s status=%s selftest_ok=%v failures=%d last_event=%s",
			name, d.Status, d.SelfTestOK, d.ConsecutiveFailures,
			d.LastEventAt.Format(time.RFC3339))
	}
	// TODO(Day B): 调用 a.client.ReportProbeStatus(...)
}

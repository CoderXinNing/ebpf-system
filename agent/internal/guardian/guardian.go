package guardian

import (
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall" guardian ../../../probes/templates/guardian/guardian.c

// AlertCallback 告警回调
type AlertCallback func(alert AlertEvent)

// AlertEvent 守护探针告警事件
type AlertEvent struct {
	PID        uint32
	TargetPID  uint32
	Syscall    uint32
	Comm       string
	Details    string
}

// Guardian 守护探针
type Guardian struct {
	objs     *guardianObjects
	links    []link.Link
	stopChan chan struct{}
	callback AlertCallback
}

// NewGuardian 创建守护探针
func NewGuardian(callback AlertCallback) *Guardian {
	return &Guardian{
		stopChan: make(chan struct{}),
		callback: callback,
	}
}

// Start 启动守护探针
func (g *Guardian) Start() error {
	// 允许内存锁定
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除内存锁定限制失败: %w", err)
	}

	// 加载eBPF程序
	g.objs = &guardianObjects{}
	if err := loadGuardianObjects(g.objs, nil); err != nil {
		return fmt.Errorf("加载守护探针失败: %w", err)
	}

	// 设置agent_pid常量
	agentPID := os.Getpid()
	if err := g.objs.guardianPrograms.TraceKill.Update(
		0,
		uint32(agentPID),
		ebpf.UpdateAny,
	); err != nil {
		g.objs.Close()
		return fmt.Errorf("设置agent_pid失败: %w", err)
	}

	// 同样设置给其他两个程序
	if err := g.objs.guardianPrograms.TracePtrace.Update(
		0,
		uint32(agentPID),
		ebpf.UpdateAny,
	); err != nil {
		g.objs.Close()
		return fmt.Errorf("设置agent_pid(ptrace)失败: %w", err)
	}
	if err := g.objs.guardianPrograms.TraceBpfDelete.Update(
		0,
		uint32(agentPID),
		ebpf.UpdateAny,
	); err != nil {
		g.objs.Close()
		return fmt.Errorf("设置agent_pid(bpf)失败: %w", err)
	}

	// Attach到hook点
	killLink, err := link.Tracepoint("syscalls", "sys_enter_kill", g.objs.TraceKill, nil)
	if err != nil {
		g.objs.Close()
		return fmt.Errorf("attach kill tracepoint失败: %w", err)
	}
	g.links = append(g.links, killLink)

	ptraceLink, err := link.Tracepoint("syscalls", "sys_enter_ptrace", g.objs.TracePtrace, nil)
	if err != nil {
		g.Stop()
		return fmt.Errorf("attach ptrace tracepoint失败: %w", err)
	}
	g.links = append(g.links, ptraceLink)

	bpfLink, err := link.Tracepoint("syscalls", "sys_enter_bpf", g.objs.TraceBpfDelete, nil)
	if err != nil {
		g.Stop()
		return fmt.Errorf("attach bpf tracepoint失败: %w", err)
	}
	g.links = append(g.links, bpfLink)

	log.Printf("🛡️  守护探针已启动 (保护 PID: %d)", agentPID)
	log.Println("   监控: kill / ptrace / bpf_delete")

	// 启动事件读取
	go g.readEvents()

	return nil
}

// readEvents 读取ring buffer事件
func (g *Guardian) readEvents() {
	rd, err := ringbuf.NewReader(g.objs.Alerts)
	if err != nil {
		log.Printf("⚠️ 创建ringbuf reader失败: %v", err)
		return
	}
	defer rd.Close()

	for {
		select {
		case <-g.stopChan:
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			continue
		}

		// 解析事件
		var event struct {
			PID        uint32
			TargetPID  uint32
			Syscall    uint32
			Comm       [16]byte
			Details    [64]byte
		}
		if err := record.Unmarshal(&event); err != nil {
			continue
		}

		alert := AlertEvent{
			PID:       event.PID,
			TargetPID: event.TargetPID,
			Syscall:   event.Syscall,
			Comm:      string(event.Comm[:]),
			Details:   string(event.Details[:]),
		}

		log.Printf("🚨 守护告警: PID=%d 尝试 %s (syscall=%d)",
			alert.PID, alert.Details, alert.Syscall)

		if g.callback != nil {
			g.callback(alert)
		}
	}
}

// Stop 停止守护探针
func (g *Guardian) Stop() {
	close(g.stopChan)

	for _, l := range g.links {
		l.Close()
	}
	g.links = nil

	if g.objs != nil {
		g.objs.Close()
		g.objs = nil
	}

	log.Println("🛡️  守护探针已停止")
}

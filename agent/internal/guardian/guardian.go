package guardian

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type AlertCallback func(alert AlertEvent)

type AlertEvent struct {
	PID       uint32
	TargetPID uint32
	SyscallNR uint32
	Comm      string
	Details   string
}

type Guardian struct {
	objs     *guardianObjects
	links    []link.Link
	stopChan chan struct{}
	callback AlertCallback
}

func NewGuardian(callback AlertCallback) *Guardian {
	return &Guardian{
		stopChan: make(chan struct{}),
		callback: callback,
	}
}

func (g *Guardian) Start() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除内存锁定限制失败: %w", err)
	}

	g.objs = &guardianObjects{}
	if err := loadGuardianObjects(g.objs, nil); err != nil {
		return fmt.Errorf("加载守护探针失败: %w", err)
	}

	// 把agent_pid写入map
	agentPID := uint32(os.Getpid())
	key := uint32(0)
	if err := g.objs.AgentConfig.Put(&key, &agentPID); err != nil {
		g.objs.Close()
		return fmt.Errorf("写入agent_pid失败: %w", err)
	}

	log.Printf("🛡️  守护探针已启动 (保护 PID: %d)", agentPID)

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

	log.Println("   监控: kill / ptrace / bpf_delete")

	go g.readEvents()
	return nil
}

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

		raw := record.RawSample
		var event AlertEvent
		event.PID = binary.LittleEndian.Uint32(raw[0:4])
		event.TargetPID = binary.LittleEndian.Uint32(raw[4:8])
		event.SyscallNR = binary.LittleEndian.Uint32(raw[8:12])
		event.Comm = string(raw[12:28])
		event.Details = string(raw[28:92])

		log.Printf("🚨 守护告警: PID=%d 尝试 %s (syscall=%d)",
			event.PID, event.Details, event.SyscallNR)

		if g.callback != nil {
			g.callback(event)
		}
	}
}

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

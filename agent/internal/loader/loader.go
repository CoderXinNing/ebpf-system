package loader

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type ExecEvent struct {
	PID      uint32
	PPID     uint32
	UID      uint32
	Comm     string
	Filename string
}

type EventCallback func(event ExecEvent)

type Probe struct {
	Name     string
	objs     *exec_monitorObjects
	link     link.Link
	stopChan chan struct{}
	callback EventCallback
}

func LoadExecMonitor(name string, callback EventCallback) (*Probe, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("解除内存锁定限制失败: %w", err)
	}

	objs := &exec_monitorObjects{}
	if err := loadExec_monitorObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("加载exec_monitor探针失败: %w", err)
	}

	tpLink, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tracepoint失败: %w", err)
	}

	p := &Probe{
		Name:     name,
		objs:     objs,
		link:     tpLink,
		stopChan: make(chan struct{}),
		callback: callback,
	}

	log.Printf("📥 探针已加载: %s (hook: sys_enter_execve)", name)
	go p.readEvents()
	return p, nil
}

func (p *Probe) readEvents() {
	rd, err := ringbuf.NewReader(p.objs.Events)
	if err != nil {
		log.Printf("⚠️ [%s] 创建ringbuf reader失败: %v", p.Name, err)
		return
	}
	defer rd.Close()

	for {
		select {
		case <-p.stopChan:
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			continue
		}

		raw := record.RawSample
		event := ExecEvent{
			PID:      binary.LittleEndian.Uint32(raw[0:4]),
			PPID:     binary.LittleEndian.Uint32(raw[4:8]),
			UID:      binary.LittleEndian.Uint32(raw[8:12]),
			Comm:     string(raw[12:28]),
			Filename: string(raw[28:92]),
		}

		log.Printf("📝 [%s] PID=%d COMM=%s FILE=%s",
			p.Name, event.PID, event.Comm, event.Filename)

		if p.callback != nil {
			p.callback(event)
		}
	}
}

func (p *Probe) Stop() {
	close(p.stopChan)
	if p.link != nil {
		p.link.Close()
	}
	if p.objs != nil {
		p.objs.Close()
	}
	log.Printf("📤 探针已卸载: %s", p.Name)
}

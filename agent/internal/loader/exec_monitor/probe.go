package exec_monitor

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/CoderXinNing/ebpf-system/agent/internal/loader/registry"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func init() {
	registry.Register(&registry.ProbeMeta{
		Name:        "exec_monitor",
		Description: "监控所有进程启动（execve系统调用）",
		Version:     "1.0.0",
		HookType:    "tracepoint",
		HookPoint:   "syscalls/sys_enter_execve",
		Factory:     NewExecMonitor,
	})
}

func NewExecMonitor(callback func(registry.Event)) (registry.ProbeInstance, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("解除内存锁限制: %w", err)
	}

	objs := &exec_monitorObjects{}
	if err := loadExec_monitorObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("加载失败: %w", err)
	}

	tpLink, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach失败: %w", err)
	}

	go readEvents(objs, callback)

	return &registry.GenericProbe{Name: "exec_monitor", Objs: objs, Link: tpLink}, nil
}

func readEvents(objs *exec_monitorObjects, callback func(registry.Event)) {
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return
	}
	defer rd.Close()

	for {
		record, err := rd.Read()
		if err != nil {
			continue
		}
		raw := record.RawSample
		event := registry.Event{
			PID:      binary.LittleEndian.Uint32(raw[0:4]),
			Comm:     cstring(raw[12:28]),
			Filename: cstring(raw[28:92]),
		}
		log.Printf("📝 [exec_monitor] PID=%d COMM=%s FILE=%s", event.PID, event.Comm, event.Filename)
		callback(event)
	}
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

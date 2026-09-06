package ebpf

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"unsafe"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// ExecEventV2 是统一 header 格式的 exec 事件
type ExecEventV2 struct {
	Header     SentinelEventHeader
	Cmdline    string
	ParentComm string
}

type ExecCallbackV2 func(ExecEventV2)

// ManualTracepointLink 手动管理 tracepoint fd
type ManualTracepointLink struct {
	fd int
}

func (l *ManualTracepointLink) Close() error {
	if l.fd >= 0 {
		log.Printf("🔴 ManualTracepointLink.Close() 被调用: fd=%d", l.fd)
		err := unix.Close(l.fd)
		l.fd = -1
		return err
	}
	return nil
}

func (l *ManualTracepointLink) Detach() error {
	return l.Close()
}

// attachTracepointManual 手动读取 tracepoint ID 并 attach
func attachTracepointManual(prog *ebpf.Program, tracepointPath string) (*ManualTracepointLink, error) {
	idBytes, err := os.ReadFile(tracepointPath + "/id")
	if err != nil {
		return nil, fmt.Errorf("读取 tracepoint ID 失败: %w", err)
	}
	tpID, err := strconv.Atoi(strings.TrimSpace(string(idBytes)))
	if err != nil {
		return nil, fmt.Errorf("解析 tracepoint ID 失败: %w", err)
	}

	log.Printf("📍 手动读取 tracepoint ID: %d", tpID)

	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Size:        uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Config:      uint64(tpID),
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
	}

	fd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("perf_event_open 失败: %w", err)
	}

	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, prog.FD()); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("SET_BPF 失败: %w", err)
	}

	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("ENABLE 失败: %w", err)
	}

	log.Printf("✅ tracepoint attach 成功 (fd=%d, config=%d)", fd, tpID)
	return &ManualTracepointLink{fd: fd}, nil
}

// LoadExecMonitorV2 加载 exec 探针
func LoadExecMonitorV2(objPath string, callback ExecCallbackV2) (*ManualTracepointLink, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("解除内存锁失败: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("加载 spec 失败: %w", err)
	}

	var objs struct {
		TraceExecve    *ebpf.Program `ebpf:"trace_execve"`
		SentinelEvents *ebpf.Map     `ebpf:"sentinel_events"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("加载失败: %w", err)
	}

	tp, err := attachTracepointManual(objs.TraceExecve, "/sys/kernel/debug/tracing/events/syscalls/sys_enter_execve")
	if err != nil {
		objs.TraceExecve.Close()
		return nil, fmt.Errorf("attach tracepoint 失败: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.SentinelEvents)
	if err != nil {
		tp.Close()
		objs.TraceExecve.Close()
		return nil, fmt.Errorf("创建 ring buffer reader 失败: %w", err)
	}

	log.Printf("✅ 新 exec 探针已启动 (统一 header + tracepoint) fd=%d", tp.fd)

	go func() {
		defer rd.Close()
		for {
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("⚠️ ring buffer 读取错误: %v", err)
				continue
			}

			header, err := DecodeEvent(record.RawSample)
			if err != nil {
				log.Printf("⚠️ 事件解码失败: %v", err)
				continue
			}

			evt := ExecEventV2{
				Header:     *header,
				Cmdline:    header.Data,
				ParentComm: header.ParentComm,
			}
			callback(evt)
		}
	}()

	return tp, nil
}

package ebpf

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type ExecEvent struct {
	Timestamp uint64
	PID       uint32
	UID       uint32
	Comm      [16]byte
	Filename  [256]byte
}

type ExecCallback func(ExecEvent, string)

var uidCache = make(map[uint32]string)

func resolveUser(uid uint32) string {
	if name, ok := uidCache[uid]; ok { return name }
	if u, err := user.LookupId(strconv.Itoa(int(uid))); err == nil {
		uidCache[uid] = u.Username
		return u.Username
	}
	return strconv.Itoa(int(uid))
}

// 从 /proc/pid/cmdline 补全命令行
func GetFullCmdline(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	// cmdline用\0分隔，替换为空格
	return strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " ")
}

func LoadExecMonitor(callback ExecCallback) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除内存锁失败: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec("probes/templates/exec_monitor_ebpf/exec_monitor.o")
	if err != nil { return fmt.Errorf("加载spec失败: %w", err) }

	var objs struct {
		TraceExecve *ebpf.Program `ebpf:"trace_execve"`
		Events      *ebpf.Map     `ebpf:"events"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("加载失败: %w", err)
	}

	os.MkdirAll("/sys/fs/bpf/ebpf-sentinel", 0755)
	objs.TraceExecve.Pin("/sys/fs/bpf/ebpf-sentinel/exec_monitor")

	l, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil { return fmt.Errorf("attach失败: %w", err) }

	log.Printf("✅ eBPF进程监控已启动: execve")

	go func() {
		rd, _ := ringbuf.NewReader(objs.Events)
		if rd == nil { return }
		defer rd.Close()
		defer l.Close()

		for {
			record, err := rd.Read()
			if err != nil { continue }

			var evt ExecEvent
			raw := record.RawSample
			evt.Timestamp = binary.LittleEndian.Uint64(raw[0:8])
			evt.PID = binary.LittleEndian.Uint32(raw[8:12])
			evt.UID = binary.LittleEndian.Uint32(raw[12:16])
			copy(evt.Comm[:], raw[16:32])
			copy(evt.Filename[:], raw[32:288])

			// 从/proc补全命令行
			fullCmd := GetFullCmdline(evt.PID)
			if fullCmd == "" {
				fullCmd = strings.TrimRight(string(evt.Filename[:]), "\x00")
			}
			comm := strings.TrimRight(string(evt.Comm[:]), "\x00")
			userName := resolveUser(evt.UID)

			log.Printf("📡 exec: PID=%d UID=%s %s → %s", evt.PID, userName, comm, fullCmd)
			callback(evt, fullCmd)
		}
	}()

	return nil
}

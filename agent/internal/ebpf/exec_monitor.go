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

func ResolveUser(uid uint32) string {
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
	return strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " ")
}

// 默认硬白名单：内核态直接跳过
var defaultExecWhitelist = []string{
	"systemd-resolved",
	"NetworkManager",
	"snapd",
	"polkitd",
	"bpftool",
}

func LoadExecMonitor(callback ExecCallback) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除内存锁失败: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec("probes/templates/exec_monitor_ebpf/exec_monitor.o")
	if err != nil { return fmt.Errorf("加载spec失败: %w", err) }

	var objs struct {
		TraceExecve    *ebpf.Program `ebpf:"trace_execve"`
		Events         *ebpf.Map     `ebpf:"events"`
		ExecWhitelist  *ebpf.Map     `ebpf:"exec_whitelist"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("加载失败: %w", err)
	}

	// 写入内核态白名单
	for _, name := range defaultExecWhitelist {
		var key [16]byte
		copy(key[:], name)
		var val uint8 = 1
		if err := objs.ExecWhitelist.Put(&key, &val); err != nil {
			log.Printf("⚠️ 白名单写入失败 [%s]: %v", name, err)
		}
	}
	log.Printf("📋 exec白名单: %v", defaultExecWhitelist)

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
			// 新结构体只有92bytes，按实际大小解析
		evt.PID = binary.LittleEndian.Uint32(raw[0:4])
			evt.UID = binary.LittleEndian.Uint32(raw[8:12])
			copy(evt.Comm[:], raw[12:28])
			copy(evt.Filename[:], raw[28:92])
		
			// 从/proc补全命令行
			fullCmd := GetFullCmdline(evt.PID)
			if fullCmd == "" {
				fullCmd = strings.TrimRight(string(evt.Filename[:]), "\x00")
			}
			comm := strings.TrimRight(string(evt.Comm[:]), "\x00")
			userName := ResolveUser(evt.UID)

			log.Printf("📡 exec: PID=%d UID=%s %s → %s", evt.PID, userName, comm, fullCmd)
			callback(evt, fullCmd)
		}
	}()

	return nil
}

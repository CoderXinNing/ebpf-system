package ebpf

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
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

func GetFullCmdline(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " ")
}

var defaultExecWhitelist = []string{
	"systemd-resolved",
	"NetworkManager",
	"snapd",
	"polkitd",
	"bpftool",
}

// 保存原始 FD，不关闭
var savedPerfFDs []int

func LoadExecMonitor(objPath string, callback ExecCallback) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除内存锁失败: %w", err)
	}

	// 使用通用 ProbeSpec 管理
	probeSpec := &ProbeSpec{
		Name:    "exec_monitor",
		ObjPath: objPath,
		PinBase: "/sys/fs/bpf/ebpf-sentinel",
		Maps:    []string{"events", "exec_whitelist", "agent_heartbeat"},
	}

	mode := probeSpec.Prepare()
	if mode == "reuse" {
		log.Printf("🔗 检测到已有exec探针pin，尝试接管...")
		if reuseErr := reusePinnedExecMonitor(probeSpec, callback); reuseErr == nil {
			log.Printf("✅ 已接管已有exec探针")
			return nil
		} else {
			log.Printf("⚠️ 接管失败，重新加载: %v", reuseErr)
			probeSpec.CleanPins()
		}
	}

	collSpec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil { return fmt.Errorf("加载spec失败: %w", err) }

	var objs struct {
		TraceExecve   *ebpf.Program `ebpf:"trace_execve"`
		Events        *ebpf.Map     `ebpf:"events"`
		ExecWhitelist  *ebpf.Map     `ebpf:"exec_whitelist"`
		AgentHeartbeat *ebpf.Map     `ebpf:"agent_heartbeat"`
	}

	if err := collSpec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("加载失败: %w", err)
	}

	// Pin 程序到 bpffs（脱离 Agent 进程存活）
	os.MkdirAll("/sys/fs/bpf/ebpf-sentinel", 0755)
	if err := objs.TraceExecve.Pin(probeSpec.PinPaths()["prog"]); err != nil {
		log.Printf("⚠️ Pin exec程序失败: %v", err)
	} else {
		log.Printf("📌 exec程序已pin到 %s", probeSpec.PinPaths()["prog"])
	}

	// Pin Events map
	mapPinPath := probeSpec.PinPaths()["events"]
	if err := objs.Events.Pin(mapPinPath); err != nil {
		log.Printf("⚠️ Pin exec events失败: %v", err)
	}

	// Pin 白名单 map
	whPinPath := probeSpec.PinPaths()["exec_whitelist"]
	if err := objs.ExecWhitelist.Pin(whPinPath); err != nil {
		log.Printf("⚠️ Pin exec白名单失败: %v", err)
	}

	// Pin 心跳 map
	hbPinPath := probeSpec.PinPaths()["agent_heartbeat"]
	if err := objs.AgentHeartbeat.Pin(hbPinPath); err != nil {
		log.Printf("⚠️ Pin 心跳map失败: %v", err)
	}

	// 写入白名单
	for _, name := range defaultExecWhitelist {
		var key [16]byte
		copy(key[:], name)
		var val uint8 = 1
		objs.ExecWhitelist.Put(&key, &val)
	}
	log.Printf("📋 exec白名单: %v", defaultExecWhitelist)

	// 用原始 syscall attach，不使用 link.Tracepoint
	progFD := objs.TraceExecve.FD()
	if err := attachTracepointSyscall(progFD, "syscalls", "sys_enter_execve"); err != nil {
		objs.TraceExecve.Close()
		return fmt.Errorf("attach失败: %w", err)
	}

	log.Printf("✅ eBPF进程监控已启动: execve (持久化模式)")

	// 启动 ring buffer reader
	go func() {
		rd, _ := ringbuf.NewReader(objs.Events)
		if rd == nil { return }
		defer rd.Close()

		for {
			record, err := rd.Read()
			if err != nil { continue }

			var evt ExecEvent
			raw := record.RawSample
			evt.PID = binary.LittleEndian.Uint32(raw[0:4])
			evt.UID = binary.LittleEndian.Uint32(raw[8:12])
			copy(evt.Comm[:], raw[12:28])
			copy(evt.Filename[:], raw[28:156])

			// 直接用 C 代码给的 filename，不从 /proc 读（避免脏数据）
			fullCmd := strings.TrimRight(string(evt.Filename[:]), "\x00")
			if fullCmd == "" {
				fullCmd = GetFullCmdline(evt.PID)
			}
			comm := strings.TrimRight(string(evt.Comm[:]), "\x00")
			userName := ResolveUser(evt.UID)

			log.Printf("📡 exec: PID=%d UID=%s %s → %s", evt.PID, userName, comm, fullCmd)
			callback(evt, fullCmd)
		}
	}()

	return nil
}

// attachTracepointSyscall 用 perf_event_open 做持久化 attach
func attachTracepointSyscall(progFD int, subsystem, event string) error {
	// 获取 tracepoint ID
	tpID, err := getTracepointID(subsystem, event)
	if err != nil {
		return fmt.Errorf("获取tracepoint ID失败: %w", err)
	}

	attr := &unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Size:        uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Config:      uint64(tpID),
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
	}

	// perf_event_open 返回值 -1 表示在所有 CPU 上
	fd, err := unix.PerfEventOpen(attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return fmt.Errorf("perf_event_open失败: %w", err)
	}

	// 绑定 eBPF 程序
	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, progFD); err != nil {
		unix.Close(fd)
		return fmt.Errorf("SET_BPF失败: %w", err)
	}

	// 启用
	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		unix.Close(fd)
		return fmt.Errorf("ENABLE失败: %w", err)
	}

	// 保存 FD，不关闭
	savedPerfFDs = append(savedPerfFDs, fd)
	log.Printf("📌 tracepoint %s/%s 持久化挂载成功 (FD=%d)", subsystem, event, fd)

	return nil
}

func getTracepointID(subsystem, event string) (int, error) {
	path := fmt.Sprintf("/sys/kernel/debug/tracing/events/%s/%s/id", subsystem, event)
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	id, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, err
	}
	return id, nil
}

// CleanupSavedFDs Agent 正常退出时清理
func CleanupSavedFDs() {
	for _, fd := range savedPerfFDs {
		unix.Close(fd)
	}
	savedPerfFDs = nil
	log.Println("🧹 已清理持久化 FD")
}


// reusePinnedExecMonitor 复用已 pin 的 exec 探针
func reusePinnedExecMonitor(spec *ProbeSpec, callback ExecCallback) error {
	coll, err := spec.LoadPinnedCollection()
	if err != nil {
		return fmt.Errorf("加载pin collection失败: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["exec_monitor"]
	if prog == nil {
		return fmt.Errorf("pin collection缺少程序")
	}

	eventsMap := coll.Maps["events"]
	if eventsMap == nil {
		return fmt.Errorf("pin collection缺少events map")
	}

	whMap := coll.Maps["exec_whitelist"]
	if whMap == nil {
		return fmt.Errorf("pin collection缺少白名单map")
	}

	_ = coll.Maps["agent_heartbeat"]  // 心跳 map 可能不在collection里

	// 写白名单（确保还是最新的）
	for _, name := range defaultExecWhitelist {
		var key [16]byte
		copy(key[:], name)
		var val uint8 = 1
		whMap.Put(&key, &val)
	}

	// 用 perf_event_open 重新 attach
	progFD := prog.FD()
	if err := attachTracepointSyscall(progFD, "syscalls", "sys_enter_execve"); err != nil {
		return fmt.Errorf("重新attach失败: %w", err)
	}

	// 启动 ring buffer reader
	go func() {
		rd, _ := ringbuf.NewReader(eventsMap)
		if rd == nil { return }
		defer rd.Close()
		for {
			record, err := rd.Read()
			if err != nil { continue }
			var evt ExecEvent
			raw := record.RawSample
			evt.PID = binary.LittleEndian.Uint32(raw[0:4])
			evt.UID = binary.LittleEndian.Uint32(raw[8:12])
			copy(evt.Comm[:], raw[12:28])
			copy(evt.Filename[:], raw[28:156])
			// 直接用 C 代码给的 filename，不从 /proc 读（避免脏数据）
			fullCmd := strings.TrimRight(string(evt.Filename[:]), "\x00")
			if fullCmd == "" {
				fullCmd = GetFullCmdline(evt.PID)
			}
			comm := strings.TrimRight(string(evt.Comm[:]), "\x00")
			userName := ResolveUser(evt.UID)
			log.Printf("📡 exec: PID=%d UID=%s %s → %s", evt.PID, userName, comm, fullCmd)
			callback(evt, fullCmd)
		}
	}()

	return nil
}

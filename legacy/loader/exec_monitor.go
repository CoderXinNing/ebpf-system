package ebpf

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type ExecEvent struct {
	Timestamp uint64
	PID       uint32
	PPID      uint32
	UID       uint32
	Comm      [16]byte
	Filename  [256]byte
}

type ExecCallback func(ExecEvent, string)

// uidCache 使用 sync.Map 保证并发安全（读多写少场景）
var uidCache sync.Map

func ResolveUser(uid uint32) string {
	if name, ok := uidCache.Load(uid); ok {
		return name.(string)
	}
	if u, err := user.LookupId(strconv.Itoa(int(uid))); err == nil {
		uidCache.Store(uid, u.Username)
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
	"agent",  // Agent 自身采集命令
	"systemd-resolved",
	"NetworkManager",
	"snapd",
	"polkitd",
	"bpftool",
	// Agent 自身采集命令
	"df", "ip", "ethtool", "systemctl", "modinfo",
	"dpkg-query", "rpm", "apk", "pacman",
	"dmidecode", "uname", "basename", "ss", "lsof",
}

func LoadExecMonitor(objPath string, callback ExecCallback) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除内存锁失败: %w", err)
	}

	// 使用通用 ProbeSpec 管理
	probeSpec := &ProbeSpec{
		Name:    "exec_monitor",
		ObjPath: objPath,
		PinBase: "/sys/fs/bpf/ebpf-sentinel",
		Maps:    []string{"events", "exec_whitelist", "agent_heartbeat", "link"},
	}

	// 每次启动强制清理旧 pin，按 Server 名单重新加载
	probeSpec.CleanPins()

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

	// 使用标准 link 库挂载 tracepoint
	tpLink, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		objs.TraceExecve.Close()
		return fmt.Errorf("attach tracepoint 失败: %w", err)
	}

	// Pin link 到 bpffs（持久化，脱离 Agent 进程存活）
	linkPinPath := probeSpec.PinPaths()["link"]
	if err := tpLink.Pin(linkPinPath); err != nil {
		tpLink.Close()
		return fmt.Errorf("Pin link 失败: %w", err)
	}
	log.Printf("📌 tracepoint link 已 pin 到 %s", linkPinPath)

	log.Printf("✅ eBPF进程监控已启动: execve (持久化模式)")

	// 启动 ring buffer reader
	go func() {
		rd, err := ringbuf.NewReader(objs.Events)
		if err != nil {
			log.Printf("❌ 创建 ring buffer reader 失败: %v", err)
			return
		}
		defer rd.Close()

		for {
			record, err := rd.Read()
			if err != nil { continue }

			var evt ExecEvent
			raw := record.RawSample
			evt.PID = binary.LittleEndian.Uint32(raw[0:4])
			evt.PPID = binary.LittleEndian.Uint32(raw[4:8])
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

	// 心跳 map 可能不在collection里，检查但不强制
	if coll.Maps["agent_heartbeat"] == nil {
		log.Printf("⚠️ pin collection缺少心跳map，跳过心跳更新")
	}

	// 写白名单（确保还是最新的）
	for _, name := range defaultExecWhitelist {
		var key [16]byte
		copy(key[:], name)
		var val uint8 = 1
		whMap.Put(&key, &val)
	}

	// 使用标准 link 库重新 attach
	tpLink, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
	if err != nil {
		return fmt.Errorf("重新 attach tracepoint 失败: %w", err)
	}

	// Pin link 到 bpffs
	linkPinPath := spec.PinPaths()["link"]
	if err := tpLink.Pin(linkPinPath); err != nil {
		tpLink.Close()
		return fmt.Errorf("Pin link 失败: %w", err)
	}
	log.Printf("📌 tracepoint link 已 pin 到 %s", linkPinPath)

	// 启动 ring buffer reader
	go func() {
		rd, err := ringbuf.NewReader(eventsMap)
		if err != nil {
			log.Printf("❌ 创建 ring buffer reader 失败: %v", err)
			return
		}
		defer rd.Close()
		for {
			record, err := rd.Read()
			if err != nil { continue }
			var evt ExecEvent
			raw := record.RawSample
			evt.PID = binary.LittleEndian.Uint32(raw[0:4])
			evt.PPID = binary.LittleEndian.Uint32(raw[4:8])
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

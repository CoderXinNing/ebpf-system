package ebpf

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type BashEvent struct {
	Timestamp uint64
	PID       uint32
	UID       uint32
	Comm      [16]byte
	Line      [256]byte
}

type BashCallback func(BashEvent, string, string)

func LoadBashMonitor(objPath string, bashPath string, callback BashCallback) error {
	if callback == nil {
		return fmt.Errorf("callback 不能为 nil")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除内存锁失败: %w", err)
	}

	probeSpec := &ProbeSpec{
		Name:    "bash_monitor",
		ObjPath: objPath,
		PinBase: "/sys/fs/bpf/ebpf-sentinel",
		Maps:    []string{"events"},
	}

	// bash 不需要持久化，每次启动清理旧 pin
	probeSpec.CleanPins()

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("加载spec失败: %w", err)
	}

	var objs struct {
		BashReadline *ebpf.Program `ebpf:"bash_readline"`
		Events       *ebpf.Map     `ebpf:"events"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("加载失败: %w", err)
	}

	// uprobe attach到/bin/bash的readline
	ex, err := link.OpenExecutable(bashPath)
	if err != nil {
		objs.BashReadline.Close()
		objs.Events.Close()
		return fmt.Errorf("打开bash失败: %w", err)
	}

	l, err := ex.Uretprobe("readline", objs.BashReadline, nil)
	if err != nil {
		objs.BashReadline.Close()
		objs.Events.Close()
		return fmt.Errorf("attach readline失败: %w", err)
	}

	if err := os.MkdirAll("/sys/fs/bpf/ebpf-sentinel", 0755); err != nil {
		l.Close()
		objs.BashReadline.Close()
		objs.Events.Close()
		return fmt.Errorf("创建 pin 目录失败: %w", err)
	}
	if err := objs.BashReadline.Pin(probeSpec.PinPaths()["prog"]); err != nil {
		log.Printf("⚠️ Pin bash失败(已存在则复用): %v", err)
	}
	if err := objs.Events.Pin(probeSpec.PinPaths()["events"]); err != nil {
		log.Printf("⚠️ Pin bash events失败(已存在则复用): %v", err)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		l.Close()
		objs.BashReadline.Close()
		objs.Events.Close()
		return fmt.Errorf("创建 ring buffer reader 失败: %w", err)
	}

	log.Printf("✅ Bash监控已启动: readline")

	go func() {
		defer rd.Close()
		defer l.Close()
		defer objs.BashReadline.Close()
		defer objs.Events.Close()

		for {
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("⚠️ bash ring buffer 读取错误: %v", err)
				continue
			}

			var evt BashEvent
			raw := record.RawSample
			if len(raw) < 288 {
				log.Printf("⚠️ bash ring buffer 数据长度不足: %d", len(raw))
				continue
			}
			evt.Timestamp = binary.LittleEndian.Uint64(raw[0:8])
			evt.PID = binary.LittleEndian.Uint32(raw[8:12])
			evt.UID = binary.LittleEndian.Uint32(raw[12:16])
			copy(evt.Comm[:], raw[16:32])
			copy(evt.Line[:], raw[32:288])

			line := strings.TrimRight(string(evt.Line[:]), "\x00")
			userName := ResolveUser(evt.UID)
			comm := strings.TrimRight(string(evt.Comm[:]), "\x00")
			if line != "" {
				log.Printf("📡 bash: PID=%d UID=%d %s → %s", evt.PID, evt.UID, comm, line)
				callback(evt, userName, line)
			}
		}
	}()

	return nil
}

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

func LoadBashMonitor(bashPath string, callback BashCallback) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除内存锁失败: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec("probes/templates/bash_monitor/bash_monitor.o")
	if err != nil { return fmt.Errorf("加载spec失败: %w", err) }

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
		return fmt.Errorf("打开bash失败: %w", err)
	}

	l, err := ex.Uretprobe("readline", objs.BashReadline, nil)
	if err != nil {
		objs.BashReadline.Close()
		return fmt.Errorf("attach readline失败: %w", err)
	}

	os.MkdirAll("/sys/fs/bpf/ebpf-sentinel", 0755)
	objs.BashReadline.Pin("/sys/fs/bpf/ebpf-sentinel/bash_monitor")

	log.Printf("✅ Bash监控已启动: readline")

	go func() {
		rd, _ := ringbuf.NewReader(objs.Events)
		if rd == nil { return }
		defer rd.Close()
		defer l.Close()

		for {
			record, err := rd.Read()
			if err != nil { continue }

			var evt BashEvent
			raw := record.RawSample
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
		log.Printf("bash回调: uid=%d user=%s line=%s", evt.UID, userName, line)
				callback(evt, userName, line)
			}
		}
	}()

	return nil
}

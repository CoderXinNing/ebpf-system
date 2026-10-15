package v3_loader

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// BashEventCallback bash 事件回调
type BashEventCallback func(header *SentinelEventHeader, line string)

// BashProbe V3 bash 探针
type BashProbe struct {
	objPath   string
	callback  BashEventCallback
	link      link.Link
	objs      *bashObjects
	agentHash uint32
	bashPath  string

	// cmdline 排除同步（v3 起 bash 只做命令维度排除）
	cmdMu              sync.Mutex
	lastExactCmdlines  []string
	lastPrefixCmdlines []string

	// ringbuf reader（Close 时用来唤醒 Read 阻塞的 goroutine）
	rd     *ringbuf.Reader
	closed atomic.Bool
}

type bashObjects struct {
	TraceReadline *ebpf.Program `ebpf:"trace_readline"`
	ConfigMap     *ebpf.Map     `ebpf:"config_map"`
	BashEvents    *ebpf.Map     `ebpf:"bash_events"`
	SentinelXCmdE *ebpf.Map     `ebpf:"sentinel_xcmd_e"`
	SentinelXCmdP *ebpf.Map     `ebpf:"sentinel_xcmd_p"`
}

// NewBashProbe 创建 bash 探针
func NewBashProbe(objPath string, bashPath string, agentHash uint32, callback BashEventCallback) *BashProbe {
	return &BashProbe{
		objPath:   objPath,
		callback:  callback,
		agentHash: agentHash,
		bashPath:  bashPath,
	}
}

// Load 加载并 attach bash 探针
func (p *BashProbe) Load() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除内存锁失败: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(p.objPath)
	if err != nil {
		return fmt.Errorf("加载 spec 失败: %w", err)
	}

	p.objs = &bashObjects{}
	if err := spec.LoadAndAssign(p.objs, nil); err != nil {
		return fmt.Errorf("加载失败: %w", err)
	}

	// 写入 Config Map
	var key uint32 = ConfigAgentHash
	var value uint64 = uint64(p.agentHash)
	if err := p.objs.ConfigMap.Put(&key, &value); err != nil {
		return fmt.Errorf("写入 agent_hash 失败: %w", err)
	}

	// uretprobe attach
	ex, err := link.OpenExecutable(p.bashPath)
	if err != nil {
		p.objs.TraceReadline.Close()
		return fmt.Errorf("打开 bash 失败: %w", err)
	}

	tp, err := ex.Uretprobe("readline", p.objs.TraceReadline, nil)
	if err != nil {
		p.objs.TraceReadline.Close()
		return fmt.Errorf("attach uretprobe 失败: %w", err)
	}
	p.link = tp

	// Ring Buffer 读取
	rd, err := ringbuf.NewReader(p.objs.BashEvents)
	if err != nil {
		p.Close()
		return fmt.Errorf("创建 ring buffer reader 失败: %w", err)
	}
	p.rd = rd

	log.Printf("✅ V3 bash 探针已启动")

	go func() {
		defer rd.Close()
		for {
			if p.closed.Load() {
				return
			}
			// 周期性 deadline，让 Read 最多阻塞 500ms
			// （SetDeadline 无法唤醒已阻塞在 EpollWait 中的 Read，
			//  必须靠周期性超时让 goroutine 有机会检查 closed 标志）
			rd.SetDeadline(time.Now().Add(500 * time.Millisecond))
			record, err := rd.Read()
			if err != nil {
				if isReaderClosed(err) || p.closed.Load() {
					return
				}
				if isReaderTimeout(err) {
					continue
				}
				log.Printf("⚠️ ring buffer 读取错误: %v", err)
				continue
			}

			header, err := DecodeEvent(record.RawSample)
			if err != nil {
				continue
			}

			line := CString(header.Data[:])
			p.callback(header, line)
		}
	}()

	return nil
}

// UpdateExcludeCmdlines 更新命令排除名单（exact HASH + prefix LPM_TRIE）
//
// v3 起 bash 只做命令维度排除，comm 恒为 bash 无意义。
func (p *BashProbe) UpdateExcludeCmdlines(exact, prefix []string) error {
	if p.objs == nil || p.objs.SentinelXCmdE == nil || p.objs.SentinelXCmdP == nil {
		return nil
	}

	p.cmdMu.Lock()
	defer p.cmdMu.Unlock()

	var val uint8 = 1

	for _, cmd := range p.lastExactCmdlines {
		var key [256]byte
		copy(key[:], cmd)
		_ = p.objs.SentinelXCmdE.Delete(&key)
	}
	for _, cmd := range p.lastPrefixCmdlines {
		key := makeLPMKey(cmd)
		_ = p.objs.SentinelXCmdP.Delete(key)
	}

	for _, cmd := range exact {
		if len(cmd) > 255 {
			return fmt.Errorf("exact cmdline 超长（>255）: %s", cmd)
		}
		var key [256]byte
		copy(key[:], cmd)
		if err := p.objs.SentinelXCmdE.Put(&key, &val); err != nil {
			return fmt.Errorf("写入 xcmd_e 失败 [%s]: %w", cmd, err)
		}
	}
	for _, cmd := range prefix {
		if len(cmd) > 255 {
			return fmt.Errorf("prefix cmdline 超长（>255）: %s", cmd)
		}
		key := makeLPMKey(cmd)
		if err := p.objs.SentinelXCmdP.Put(key, &val); err != nil {
			return fmt.Errorf("写入 xcmd_p 失败 [%s]: %w", cmd, err)
		}
	}

	p.lastExactCmdlines = append([]string(nil), exact...)
	p.lastPrefixCmdlines = append([]string(nil), prefix...)
	return nil
}

// Close 清理资源
func (p *BashProbe) Close() {
	if p.link != nil {
		p.link.Close()
		p.link = nil
	}
	if p.rd != nil {
		p.closed.Store(true)
		// 不直接调 rd.Close() 或 SetDeadline：
		// Read 阻塞时持有 reader 内部锁，这两个方法会死锁。
		// reader goroutine 会在下一轮 500ms deadline 超时后检查 closed 并退出，
		// 退出时通过 defer rd.Close() 释放 fd。
		// 关 objs（含 ringbuf map）会让 epoll 立刻返回错误，加速唤醒。
		p.rd = nil
	}
	if p.objs != nil {
		closeEbpfObjects(p.objs)
		p.objs = nil
	}
}

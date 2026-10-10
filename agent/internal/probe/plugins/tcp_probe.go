package plugins

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"

	"github.com/cilium/ebpf"

	probe "github.com/CoderXinNing/ebpf-system/agent/internal/probe"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/framework"
	"github.com/CoderXinNing/ebpf-system/agent/internal/v3_loader"

	"github.com/CoderXinNing/ebpf-system/internal/rules"
)

// TCPProbe 是 V3 TCP 探针的适配器
type TCPProbe struct {
	objPath   string
	callback  func(pid uint32, comm string, count uint64, dstIP uint32, dstPort uint16)
	loaded    bool
	probe     *v3_loader.TCPProbe
	agentHash uint32
}

func NewTCPProbe(objPath string, agentHash uint32, callback func(pid uint32, comm string, count uint64, dstIP uint32, dstPort uint16)) *TCPProbe {
	return &TCPProbe{
		objPath:   objPath,
		callback:  callback,
		agentHash: agentHash,
	}
}

func (p *TCPProbe) Name() string { return "tcp_monitor" }

func (p *TCPProbe) Init() error { return nil }

func (p *TCPProbe) Attach() error {
	p.probe = v3_loader.NewTCPProbe(p.objPath, p.agentHash, func(header *v3_loader.SentinelEventHeader, detail *v3_loader.TCPConnDetail) {
		// V3 事件回调：默认计数模式，明细模式下触发
		if p.callback != nil {
			p.callback(header.PID, v3_loader.CString(header.Comm[:]), 1, detail.DstIP, detail.DstPort)
		}
	})

	if err := p.probe.Load(); err != nil {
		return err
	}

	p.loaded = true
	log.Printf("✅ V3 TCP 探针已通过插件框架加载")
	return nil
}

func (p *TCPProbe) Stop() error {
	if p.probe != nil {
		p.probe.Close()
		p.probe = nil
	}
	p.loaded = false
	return nil
}

// GetPidConnStats 返回 PID 连接统计 Map
func (p *TCPProbe) GetPidConnStats() *ebpf.Map {
	if p.probe != nil {
		return p.probe.GetPidConnStats()
	}
	return nil
}

// SetCollectMode 动态切换采集模式
func (p *TCPProbe) SetCollectMode(mode uint64) error {
	if p.probe == nil {
		return fmt.Errorf("探针未加载")
	}
	return p.probe.SetCollectMode(mode)
}

func (p *TCPProbe) SelfTestAction(opts framework.SelfTestOptions) error {
	target := opts.TCPTarget
	if target == "" {
		target = "127.0.0.1:1"
	}
	hostPort := strings.Replace(target, ":", "/", 1)
	script := fmt.Sprintf(
		"exec -a agent-selftest bash -c 'exec 3<>/dev/tcp/%s' 2>/dev/null",
		hostPort)
	cmd := exec.Command("bash", "-c", script)
	err := cmd.Run()
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		log.Printf("🔬 [SELFTEST][EXPECTED] TCP 自检连接被拒 (exit=%d)", exitErr.ExitCode())
		return nil
	}
	return fmt.Errorf("%w: %v", framework.ErrSelfTestActionFailed, err)
}

var _ framework.SelfTester = (*TCPProbe)(nil)

// PreCheck tcp_monitor 环境预检查：依赖 CO-RE（BTF）+ tracepoint。
func (p *TCPProbe) PreCheck(caps *probe.AgentCapabilities) error {
	if err := framework.CommonPreCheck(caps); err != nil {
		return framework.WrapReason("tcp_monitor", err.Error())
	}
	return nil
}

var _ framework.PreChecker = (*TCPProbe)(nil)

// ApplyConfig 实现 framework.ConfigApplier
//
// tcp 三维度排除（任一命中即排除）：
//   - IPs    目标 IP / CIDR
//   - Comms  发起连接的进程名
//   - Combos (comm, ip) 精确组合
//
// 敏感端口不在 C 层，走 Agent 的 tcpAnomaly（Go 层规则引擎）。
func (p *TCPProbe) ApplyConfig(rs *rules.RuleSet) error {
	if rs == nil || rs.TCP == nil || rs.TCP.Exclude == nil {
		return nil
	}
	if p.probe == nil {
		return nil
	}

	ex := rs.TCP.Exclude

	if err := p.probe.UpdateExcludeIPs(ex.IPs); err != nil {
		return err
	}
	if err := p.probe.UpdateExcludeComms(ex.Comms); err != nil {
		return err
	}

	// combos：解析并写入
	if len(ex.Combos) > 0 {
		entries := make([]v3_loader.TCPComboEntry, 0, len(ex.Combos))
		for _, c := range ex.Combos {
			ip := net.ParseIP(c.IP)
			if ip == nil {
				log.Printf("⚠️ 跳过非法 combo IP [%s/%s]", c.Comm, c.IP)
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil {
				log.Printf("⚠️ 跳过非 IPv4 combo [%s/%s]", c.Comm, c.IP)
				continue
			}
			var entry v3_loader.TCPComboEntry
			entry.Comm = c.Comm
			copy(entry.IP[:], ip4)
			entries = append(entries, entry)
		}
		if err := p.probe.UpdateExcludeCombos(entries); err != nil {
			return err
		}
	} else {
		// 清空
		if err := p.probe.UpdateExcludeCombos(nil); err != nil {
			return err
		}
	}

	return nil
}

var _ framework.ConfigApplier = (*TCPProbe)(nil)

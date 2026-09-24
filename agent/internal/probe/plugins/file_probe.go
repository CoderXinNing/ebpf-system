package plugins

import (
	"errors"
	"fmt"
	"log"
	"os/exec"

	probe "github.com/CoderXinNing/ebpf-system/agent/internal/probe"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/framework"
	"github.com/CoderXinNing/ebpf-system/agent/internal/v3_loader"
)

// FileProbe 是 V3 file_access 探针的适配器
type FileProbe struct {
	objPath   string
	callback  func(pid uint32, comm string, filename string, correlationKey uint64)
	loaded    bool
	probe     *v3_loader.FileProbe
	agentHash uint32
}

func NewFileProbe(objPath string, agentHash uint32, callback func(pid uint32, comm string, filename string, correlationKey uint64)) *FileProbe {
	return &FileProbe{
		objPath:   objPath,
		callback:  callback,
		agentHash: agentHash,
	}
}

func (p *FileProbe) Name() string { return "file_access" }

func (p *FileProbe) Init() error { return nil }

func (p *FileProbe) Attach() error {
	p.probe = v3_loader.NewFileProbe(p.objPath, p.agentHash, func(header *v3_loader.SentinelEventHeader, filename string) {
		if p.callback != nil {
			p.callback(header.PID, v3_loader.CString(header.Comm[:]), filename, header.CorrelationKey)
		}
	})

	if err := p.probe.Load(); err != nil {
		return err
	}

	p.loaded = true
	log.Printf("✅ V3 file_access 探针已通过插件框架加载")
	return nil
}

func (p *FileProbe) UpdateRules(rules []framework.Rule) error {
	return nil
}

func (p *FileProbe) Stop() error {
	if p.probe != nil {
		p.probe.Close()
		p.probe = nil
	}
	p.loaded = false
	return nil
}

var _ framework.Probe = (*FileProbe)(nil)

// selfTestPath 自检路径，与 file_access.c 中的 SELFTEST_PATH 必须严格一致。
// 该路径是"薛定谔的文件"：/proc/self/ 是内核伪文件系统，文件不存在但
// openat 照常触发 tracepoint，且攻击者无法在 /proc/self/ 下伪造。
const selfTestPath = "/proc/self/astertrack-selftest"

func (p *FileProbe) SelfTestAction(opts framework.SelfTestOptions) error {
	cmd := exec.Command("bash", "-c", "cat "+selfTestPath+" 2>/dev/null")
	err := cmd.Run()
	if err == nil {
		// 罕见：文件竟然存在（被攻击者放置？）。仍然算动作成功。
		return nil
	}
	// 预期失败：文件不存在，cat 退出码 1
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return nil // 预期失败，不算动作失败
	}
	return fmt.Errorf("%w: %v", framework.ErrSelfTestActionFailed, err)
}

var _ framework.SelfTester = (*FileProbe)(nil)

// PreCheck file_access 环境预检查：依赖 CO-RE（BTF）+ tracepoint 目录。
func (p *FileProbe) PreCheck(caps *probe.AgentCapabilities) error {
	if err := framework.CommonPreCheck(caps); err != nil {
		return framework.WrapReason("file_access", err.Error())
	}
	return nil
}

var _ framework.PreChecker = (*FileProbe)(nil)

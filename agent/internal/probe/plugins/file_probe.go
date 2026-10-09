package plugins

import (
	"fmt"
	"log"

	probe "github.com/CoderXinNing/ebpf-system/agent/internal/probe"
	"github.com/CoderXinNing/ebpf-system/agent/internal/probe/framework"
	"github.com/CoderXinNing/ebpf-system/agent/internal/v3_loader"

	"github.com/CoderXinNing/ebpf-system/internal/rules"
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

// 默认敏感路径（首次启动注入，Server 动态下发会覆盖）
//
// 精确匹配（用户意图 = 监控文件）
var defaultExactPaths = []string{
	"/etc/shadow",
	"/etc/passwd",
	"/etc/sudoers",
}

// 前缀匹配（用户意图 = 监控目录，路径须以 / 结尾）
var defaultPrefixPaths = []string{
	"/root/.ssh/",
	"/home/",
	"/var/log/auth",
}

func (p *FileProbe) Attach() error {
	p.probe = v3_loader.NewFileProbe(p.objPath, p.agentHash, func(header *v3_loader.SentinelEventHeader, filename string) {
		if p.callback != nil {
			p.callback(header.PID, v3_loader.CString(header.Comm[:]), filename, header.CorrelationKey)
		}
	})

	if err := p.probe.Load(); err != nil {
		return err
	}

	// 注入默认规则（避免启动期"无规则"裸奔）
	if err := p.probe.UpdateSensitivePaths(defaultExactPaths, defaultPrefixPaths); err != nil {
		log.Printf("⚠️ 默认敏感路径注入失败: %v（file_access 将无规则）", err)
	} else {
		log.Printf("✅ 默认敏感路径已注入: 精确 %d 条, 前缀 %d 条",
			len(defaultExactPaths), len(defaultPrefixPaths))
	}

	p.loaded = true
	log.Printf("✅ V3 file_access 探针已通过插件框架加载")
	return nil
}

// IsLoaded 探针是否已加载完成（规则应用前需确认）
func (p *FileProbe) IsLoaded() bool {
	return p.loaded && p.probe != nil
}

// CleanupDeadPids 转发（P1.9：清理死 PID）
func (p *FileProbe) CleanupDeadPids() (int, error) {
	if p.probe == nil {
		return 0, nil
	}
	return p.probe.CleanupDeadPids()
}

// MarkAgentPid 转发给底层（P1.9：标记 Agent 子进程）
func (p *FileProbe) MarkAgentPid(pid uint32) error {
	if p.probe == nil {
		return fmt.Errorf("探针未加载")
	}
	return p.probe.MarkAgentPid(pid)
}

// CountAgentPids 转发给底层（P1.9 A1 心跳汇总用）
func (p *FileProbe) CountAgentPids() int {
	if p.probe == nil {
		return 0
	}
	return p.probe.CountAgentPids()
}

// UpdateSensitivePaths 转发给底层 v3_loader.FileProbe（规则热更新用）
func (p *FileProbe) UpdateSensitivePaths(exactPaths, prefixPaths []string) error {
	if p.probe == nil {
		return fmt.Errorf("探针未加载")
	}
	return p.probe.UpdateSensitivePaths(exactPaths, prefixPaths)
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

// 注：FileProbe 不实现 framework.SelfTester。
//
// 原因：file_access 探针只上报【敏感路径】的访问事件。自检动作必须走敏感路径
// 才能产生可观测事件，但这会触发"密码文件读取"等真实告警 —— 自检与告警相互矛盾。
//
// 替代：file_access 天然有持续流量（Agent 资产采集、系统进程读敏感文件），
// 通过"最近有事件"即可判断其存活，无需人工自检。
//
// 状态：自动标记为 loaded-no-activity（与 bash_monitor 一致）。
//
// TODO：未来若引入 Agent 侧 PID 过滤（识别自身进程），可重新实现 SelfTestAction。

// PreCheck file_access 环境预检查：依赖 CO-RE（BTF）+ tracepoint 目录。
func (p *FileProbe) PreCheck(caps *probe.AgentCapabilities) error {
	if err := framework.CommonPreCheck(caps); err != nil {
		return framework.WrapReason("file_access", err.Error())
	}
	return nil
}

var _ framework.PreChecker = (*FileProbe)(nil)

// ApplyConfig 实现 framework.ConfigApplier
//
// file_access 有两类独立配置：
//  1. 敏感路径（rules）—— 走 file_access 探针自身
//  2. comm 排除（exclude）—— 独立于 exec+bash 的 comm 名单，
//     用于过滤噪音源（如 psql 正常读 /etc/shadow）
//
// 见 EDR-CORRELATION-v3.1【五】+ PROJECT-STATUS 已知问题 #11。
func (p *FileProbe) ApplyConfig(rs *rules.RuleSet) error {
	if rs == nil || rs.FileAccess == nil {
		return nil
	}

	// 1. 敏感路径（rules 非空时应用）
	if rs.FileAccess.Rules != nil {
		if err := p.UpdateSensitivePaths(
			rs.FileAccess.Rules.SensitiveExact,
			rs.FileAccess.Rules.SensitivePrefix,
		); err != nil {
			return err
		}
	}

	// 2. comm 排除（exclude 非空时应用）
	if rs.FileAccess.Exclude != nil {
		if err := p.probe.UpdateExcludeComms(rs.FileAccess.Exclude.Comms); err != nil {
			return err
		}
	}

	return nil
}

var _ framework.ConfigApplier = (*FileProbe)(nil)

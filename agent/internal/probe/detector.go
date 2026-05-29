package probe

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// AgentCapabilities Agent完整能力清单
type AgentCapabilities struct {
	// 框架支持
	Framework *FrameworkSupport `json:"framework"`

	// 内核特性（先保持简化，后面再加回来）
	KernelVersion string `json:"kernel_version"`
	Arch          string `json:"arch"`
	BTFEnabled    bool   `json:"btf_enabled"`
}

// Detect 执行两阶段环境探测
func Detect() (*AgentCapabilities, error) {
	caps := &AgentCapabilities{}

	// 第一阶段：框架检测
	fmt.Println("  [1/2] 检测eBPF框架/工具链...")
	caps.Framework = DetectFramework()
	fmt.Print(caps.Framework.FrameworkSummary())

	// 第二阶段：内核特性检测
	fmt.Println("  [2/2] 检测内核eBPF特性...")
	if err := caps.detectBasicInfo(); err != nil {
		return nil, fmt.Errorf("内核检测失败: %w", err)
	}

	return caps, nil
}

func (c *AgentCapabilities) detectBasicInfo() error {
	// 内核版本
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return err
	}
	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		c.KernelVersion = fields[2]
	}

	// 架构
	out, err := exec.Command("uname", "-m").Output()
	if err != nil {
		return err
	}
	c.Arch = strings.TrimSpace(string(out))

	// BTF
	_, err = os.Stat("/sys/kernel/btf/vmlinux")
	c.BTFEnabled = err == nil

	return nil
}

// Summary 打印完整探测报告
func (c *AgentCapabilities) Summary() string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("╔══════════════════════════════════════╗\n")
	sb.WriteString("║     Agent 完整环境报告               ║\n")
	sb.WriteString("╠══════════════════════════════════════╣\n")
	sb.WriteString(fmt.Sprintf("║ 内核: %-30s ║\n", c.KernelVersion))
	sb.WriteString(fmt.Sprintf("║ 架构: %-30s ║\n", c.Arch))
	btfStr := "否"
	if c.BTFEnabled {
		btfStr = "是"
	}
	sb.WriteString(fmt.Sprintf("║ BTF:  %-30s ║\n", btfStr))
	sb.WriteString("╚══════════════════════════════════════╝\n")

	return sb.String()
}

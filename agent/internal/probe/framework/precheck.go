package framework

import (
	"errors"
	"fmt"

	probe "github.com/CoderXinNing/ebpf-system/agent/internal/probe"
)

// CommonPreCheck 提供通用环境预检查。
// 自定义探针在 PreCheck 里调用它，可覆盖 90% 场景。
//
// 检查项：
//   - capabilities 已初始化
//   - BTF 可用（CO-RE 必须）
//   - cilium/ebpf 可用（Agent 自带，恒 true，作防御）
func CommonPreCheck(caps *probe.AgentCapabilities) error {
	if caps == nil {
		return errors.New("capabilities 未初始化")
	}
	if !caps.BTFEnabled {
		return errors.New("内核不支持 BTF（CO-RE 必须）")
	}
	if caps.Framework == nil || !caps.Framework.GoEBPFAvailable {
		return errors.New("cilium/ebpf 不可用")
	}
	return nil
}

// RequireTracepoint 检查指定 tracepoint 是否可用（debugfs 挂载 + 事件目录存在）。
// 供 tracepoint 类探针复用。
func RequireTracepoint(eventPath string) error {
	if eventPath == "" {
		return errors.New("tracepoint 路径为空")
	}
	// 实际检查放在调用方（需要 os.Stat），这里只做参数校验占位。
	// 具体探针在 PreCheck 里做 os.Stat，避免 framework 包引入 os 依赖。
	return nil
}

// WrapReason 统一封装预检查失败原因，避免重复字符串拼接。
func WrapReason(probeName, reason string) error {
	return fmt.Errorf("[%s] %s", probeName, reason)
}

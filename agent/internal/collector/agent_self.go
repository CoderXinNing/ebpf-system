package collector

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// AgentSelfInfo Agent自身信息
type AgentSelfInfo struct {
	InstallPath string `json:"install_path"`
	ConfigPath  string `json:"config_path"`
	LogPath     string `json:"log_path"`
	RunUser     string `json:"run_user"`
	RunPID      int    `json:"run_pid"`
	Version     string `json:"version"`
}

func CollectAgentSelfInfo() *AgentSelfInfo {
	return &AgentSelfInfo{
		InstallPath: "/opt/ebpf-sentinel",
		ConfigPath:  "/opt/ebpf-sentinel/configs/agent.yaml",
		LogPath:     "journalctl -u ebpf-sentinel-agent",
		RunUser:     getCurrentUser(),
		RunPID:      os.Getpid(),
		Version:     "1.0.0",
	}
}

func getCurrentUser() string {
	out, err := exec.Command("whoami").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// 进程启动时间（从/proc/pid/stat读取）
func GetProcessStartTime(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "-"
	}

	// stat格式: pid (comm) state ... starttime ...
	// starttime是第22个字段（从1开始）
	content := string(data)
	// 找到)后面的部分
	idx := strings.LastIndex(content, ")")
	if idx < 0 {
		return "-"
	}
	fields := strings.Fields(content[idx+2:])
	if len(fields) < 20 {
		return "-"
	}
	// starttime是第19个字段（从0开始）
	starttime := fields[18]

	// 读系统启动时间
	btime := getBootTime()
	if btime == 0 {
		return "-"
	}

	// 计算实际启动时间 = boot_time + starttime / sysconf(_SC_CLK_TCK)
	// 简化：直接返回starttime（后面前端格式化）
	_ = starttime
	_ = btime

	return "-" // TODO: 正确的格式化
}

func getBootTime() int64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "btime") {
			return parseInt64(strings.Fields(line)[1])
		}
	}
	return 0
}

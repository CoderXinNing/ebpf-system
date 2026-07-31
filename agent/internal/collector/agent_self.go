package collector

import (
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

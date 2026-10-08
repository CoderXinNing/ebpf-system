package collector

import (
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
)

// PidMarker 标记 Agent 子进程 PID 的接口
// 由 Agent 初始化时注入（避免 collector 直接依赖 plugins 包）
type PidMarker interface {
	MarkAgentPid(pid uint32) error
}

var pidMarkerRef atomic.Value // 存 PidMarker

// SetPidMarker 注入 PidMarker（Agent 初始化时调用）
func SetPidMarker(m PidMarker) {
	pidMarkerRef.Store(m)
}

// markChildProcess 标记子进程 PID 到 agent_pids map
// 前提：该 PID 的 PPID 确实是当前 Agent 进程
func markChildProcess(pid uint32) {
	if !ppidIsMine(pid) {
		return
	}
	v := pidMarkerRef.Load()
	if v == nil {
		return
	}
	m, ok := v.(PidMarker)
	if !ok || m == nil {
		return
	}
	_ = m.MarkAgentPid(pid)
}

// ppidIsMine 检查 pid 的父进程是否是当前进程
func ppidIsMine(pid uint32) bool {
	statusPath := "/proc/" + strconv.FormatUint(uint64(pid), 10) + "/status"
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return false
	}
	mine := os.Getpid()
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ppid, _ := strconv.Atoi(fields[1])
				return ppid == mine
			}
		}
	}
	return false
}

// RunAndMark 等价 exec.Command(name, args...).Output()
// 启动后立即标记子进程 PID（P1.9）
func RunAndMark(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Start(); err != nil {
		return nil, err
	}
	markChildProcess(uint32(cmd.Process.Pid))
	err := cmd.Wait()
	return stdout.Bytes(), err
}

// RunAndMarkCombined 等价 exec.Command(name, args...).CombinedOutput()
func RunAndMarkCombined(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	if err := cmd.Start(); err != nil {
		return nil, err
	}
	markChildProcess(uint32(cmd.Process.Pid))
	err := cmd.Wait()
	return buf.Bytes(), err
}

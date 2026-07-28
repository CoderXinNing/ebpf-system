package collector

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcessInfo 进程信息
type ProcessInfo struct {
	PID     int      `json:"pid"`
	PPID    int      `json:"ppid"`
	Name    string   `json:"name"`
	Cmdline string   `json:"cmdline"`
	ExePath string   `json:"exe_path"`
	User    string   `json:"user"`
	State   string   `json:"state"`
	Ports   []string `json:"listening_ports"`
}

// CollectAllProcesses 采集所有进程信息
func CollectAllProcesses() ([]ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("读取/proc失败: %w", err)
	}

	var processes []ProcessInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		info := collectProcessInfo(pid)
		if info.PID != 0 {
			processes = append(processes, info)
		}
	}

	return processes, nil
}

// collectProcessInfo 采集单个进程信息
func collectProcessInfo(pid int) ProcessInfo {
	info := ProcessInfo{PID: pid}

	// 进程名
	name, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	info.Name = strings.TrimSpace(string(name))

	// 命令行
	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	info.Cmdline = strings.ReplaceAll(strings.TrimSpace(string(cmdline)), "\x00", " ")

	// 可执行文件路径
	exePath, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	info.ExePath = exePath

	// 进程状态
	status, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	info.PPID, info.User, info.State = parseStatus(string(status))

	// 监听端口
	info.Ports = collectProcessPorts(pid)

	return info
}

// parseStatus 解析 /proc/pid/status
func parseStatus(status string) (ppid int, user string, state string) {
	scanner := bufio.NewScanner(strings.NewReader(status))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "PPid:"):
			fmt.Sscanf(line, "PPid:\t%d", &ppid)
		case strings.HasPrefix(line, "Uid:"):
			var uid int
			fmt.Sscanf(line, "Uid:\t%d", &uid)
			user = resolveUID(uid)
		case strings.HasPrefix(line, "State:"):
			fmt.Sscanf(line, "State:\t%s", &state)
		}
	}
	return
}

// resolveUID UID转用户名
func resolveUID(uid int) string {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return strconv.Itoa(uid)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) >= 3 {
			if id, _ := strconv.Atoi(fields[2]); id == uid {
				return fields[0]
			}
		}
	}
	return strconv.Itoa(uid)
}

// collectProcessPorts 采集进程监听的端口（从/proc/net/tcp和/proc/net/tcp6读）
func collectProcessPorts(pid int) []string {
	var ports []string

	// 从进程的fd目录找socket
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return ports
	}

	inodeSet := make(map[string]bool)
	for _, entry := range entries {
		link, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		if strings.HasPrefix(link, "socket:[") {
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			inodeSet[inode] = true
		}
	}

	// 解析 /proc/net/tcp 和 tcp6
	for _, protoFile := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(protoFile)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		scanner.Scan() // 跳过表头
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}

			// 状态必须为 LISTEN（0A）
			if fields[3] != "0A" {
				continue
			}

			// inode是第10个字段
			inode := fields[9]
			if inodeSet[inode] {
				// 解析端口
				localAddr := fields[1]
				parts := strings.Split(localAddr, ":")
				if len(parts) == 2 {
					portHex := parts[1]
					port, _ := strconv.ParseInt(portHex, 16, 64)
					ports = append(ports, fmt.Sprintf("%d", port))
				}
			}
		}
	}

	return ports
}

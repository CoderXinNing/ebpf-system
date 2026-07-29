package collector

import (
	"fmt"
	"os"
	"strings"
)

// ProcessTreeNode 进程树节点
type ProcessTreeNode struct {
	PID      int                `json:"pid"`
	PPID     int                `json:"ppid"`
	Name     string             `json:"name"`
	Cmdline  string             `json:"cmdline"`
	ExePath  string             `json:"exe_path"`
	User     string             `json:"user"`
	Children []*ProcessTreeNode `json:"children,omitempty"`
}

// GetProcessTree 获取指定PID的父进程链（向上追溯）
func GetProcessTree(pid int) []ProcessTreeNode {
	var chain []ProcessTreeNode
	visited := make(map[int]bool)

	current := pid
	for current > 1 && !visited[current] {
		visited[current] = true

		info := collectProcessInfo(current)
		node := ProcessTreeNode{
			PID:     info.PID,
			PPID:    info.PPID,
			Name:    info.Name,
			Cmdline: info.Cmdline,
			ExePath: info.ExePath,
			User:    info.User,
		}
		chain = append([]ProcessTreeNode{node}, chain...)

		if info.PPID == current || info.PPID <= 0 {
			break
		}
		current = info.PPID
	}

	return chain
}

// GetFullProcessTree 获取完整进程树（从init开始向下）
func GetFullProcessTree() []*ProcessTreeNode {
	procs, _ := CollectAllProcesses()

	// 构建PID→节点的映射
	nodeMap := make(map[int]*ProcessTreeNode)
	for _, p := range procs {
		nodeMap[p.PID] = &ProcessTreeNode{
			PID:     p.PID,
			PPID:    p.PPID,
			Name:    p.Name,
			Cmdline: p.Cmdline,
			ExePath: p.ExePath,
			User:    p.User,
		}
	}

	// 构建父子关系
	var roots []*ProcessTreeNode
	for _, node := range nodeMap {
		if parent, ok := nodeMap[node.PPID]; ok {
			parent.Children = append(parent.Children, node)
		} else {
			roots = append(roots, node)
		}
	}

	return roots
}

// GetProcessChildren 获取指定PID的子进程
func GetProcessChildren(pid int) []ProcessTreeNode {
	procs, _ := CollectAllProcesses()

	var children []ProcessTreeNode
	for _, p := range procs {
		if p.PPID == pid {
			children = append(children, ProcessTreeNode{
				PID:     p.PID,
				PPID:    p.PPID,
				Name:    p.Name,
				Cmdline: p.Cmdline,
				ExePath: p.ExePath,
				User:    p.User,
			})
		}
	}

	return children
}

// GetProcessEnv 获取进程的环境变量
func GetProcessEnv(pid int) map[string]string {
	env := make(map[string]string)

	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return env
	}

	for _, item := range strings.Split(string(data), "\x00") {
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, "=", 2)
		if len(parts) == 2 {
			env[parts[0]] = parts[1]
		}
	}

	return env
}

// GetProcessFds 获取进程打开的文件描述符
func GetProcessFds(pid int) []string {
	var fds []string

	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return fds
	}

	for _, entry := range entries {
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()))
		if err != nil {
			continue
		}
		fds = append(fds, fmt.Sprintf("%s → %s", entry.Name(), link))
	}

	return fds
}

// GetProcessMaps 获取进程的内存映射（加载的so/jar等）
func GetProcessMaps(pid int) []string {
	var maps []string

	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return maps
	}

	seen := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 6 {
			path := fields[len(fields)-1]
			if path != "" && !seen[path] && strings.HasPrefix(path, "/") {
				seen[path] = true
				maps = append(maps, path)
			}
		}
	}

	return maps
}

// parseInt 字符串转int

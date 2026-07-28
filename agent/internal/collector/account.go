package collector

import (
	"bufio"
	"os"
	"strings"
)

// UserInfo 账户信息
type UserInfo struct {
	Username string `json:"username"`
	UID      int    `json:"uid"`
	GID      int    `json:"gid"`
	Home     string `json:"home"`
	Shell    string `json:"shell"`
	HasShell bool   `json:"has_shell"` // 是否有登录Shell（可登录）
}

// CollectAllUsers 采集所有用户信息
func CollectAllUsers() ([]UserInfo, error) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}

	var users []UserInfo
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}

		uid := parseIntOr(fields[2], -1)
		gid := parseIntOr(fields[3], -1)
		shell := fields[6]

		// 判断是否有登录Shell
		hasShell := isLoginShell(shell)

		users = append(users, UserInfo{
			Username: fields[0],
			UID:      uid,
			GID:      gid,
			Home:     fields[5],
			Shell:    shell,
			HasShell: hasShell,
		})
	}

	return users, nil
}

// isLoginShell 判断是否为可登录Shell
func isLoginShell(shell string) bool {
	if shell == "" || shell == "/usr/sbin/nologin" || shell == "/sbin/nologin" ||
		shell == "/bin/false" || shell == "/bin/sync" || shell == "/bin/true" ||
		shell == "/usr/bin/false" || shell == "/usr/bin/true" {
		return false
	}
	return true
}

func parseIntOr(s string, defaultVal int) int {
	var val int
	for _, c := range s {
		if c < '0' || c > '9' {
			return defaultVal
		}
		val = val*10 + int(c-'0')
	}
	return val
}

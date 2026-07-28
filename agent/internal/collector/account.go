package collector

import (
	"bufio"
	"os"
	"os/exec"
	"net"
	"strings"
)

// UserInfo 用户详细信息
type UserInfo struct {
	Username      string `json:"username"`
	UID           int    `json:"uid"`
	GID           int    `json:"gid"`
	Home          string `json:"home"`
	Shell         string `json:"shell"`
	HasShell      bool   `json:"has_shell"`
	IsRoot        bool   `json:"is_root"`
	IsDisabled    bool   `json:"is_disabled"`
	HasSudo       bool   `json:"has_sudo"`
	LastLogin     string `json:"last_login"`
	LastLoginIP   string `json:"last_login_ip"`
}

// CollectAllUsers 采集所有用户信息
func CollectAllUsers() ([]UserInfo, error) {
	// 读取 /etc/passwd
	passwdData, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}

	// 读取 /etc/shadow 获取禁用状态
	shadowMap := parseShadow()

	// 获取sudo用户列表
	sudoUsers := getSudoUsers()

	// 获取最后登录信息
	loginMap := getLastLogins()

	var users []UserInfo
	scanner := bufio.NewScanner(strings.NewReader(string(passwdData)))
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
		username := fields[0]
		shell := fields[6]

		user := UserInfo{
			Username:   username,
			UID:        uid,
			GID:        gid,
			Home:       fields[5],
			Shell:      shell,
			HasShell:   isLoginShell(shell),
			IsRoot:     uid == 0,
			IsDisabled: shadowMap[username],
			HasSudo:    sudoUsers[username],
		}

		// 最后登录信息
		if login, ok := loginMap[username]; ok {
			user.LastLogin = login.time
			user.LastLoginIP = login.ip
		}

		users = append(users, user)
	}

	return users, nil
}

// parseShadow 解析 /etc/shadow，返回用户名→是否禁用
func parseShadow() map[string]bool {
	result := make(map[string]bool)
	data, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return result
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		username := fields[0]
		password := fields[1]

		// 密码字段以 ! 或 * 开头 = 禁用
		isDisabled := strings.HasPrefix(password, "!") || strings.HasPrefix(password, "*") || password == ""
		result[username] = isDisabled
	}
	return result
}

// getSudoUsers 获取有sudo权限的用户
func getSudoUsers() map[string]bool {
	result := make(map[string]bool)

	// 检查 /etc/group 中的 sudo 组
	data, err := os.ReadFile("/etc/group")
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "sudo:") || strings.HasPrefix(line, "wheel:") {
				fields := strings.Split(line, ":")
				if len(fields) >= 4 {
					for _, user := range strings.Split(fields[3], ",") {
						if user != "" {
							result[user] = true
						}
					}
				}
			}
		}
	}

	// 检查 /etc/sudoers
	sudoersData, err := os.ReadFile("/etc/sudoers")
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(sudoersData)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// 匹配 "user ALL=(ALL) ALL" 或 "user ALL=(ALL:ALL) ALL"
			for _, username := range getAllUsernames() {
				if strings.HasPrefix(line, username+" ") && strings.Contains(line, "ALL") {
					result[username] = true
				}
			}
		}
	}

	return result
}

// getAllUsernames 从/etc/passwd获取所有用户名
func getAllUsernames() []string {
	data, _ := os.ReadFile("/etc/passwd")
	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) > 0 && fields[0] != "" {
			names = append(names, fields[0])
		}
	}
	return names
}

type loginInfo struct {
	time string
	ip   string
}

// getLastLogins 获取所有用户的最后登录信息
func getLastLogins() map[string]loginInfo {
	result := make(map[string]loginInfo)

	// 使用 last 命令获取登录记录（解析 /var/log/wtmp）
	cmd := exec.Command("last", "-i", "-n", "100")
	output, err := cmd.Output()
	if err != nil {
		return result
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "wtmp") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		username := fields[0]

		// 跳过系统用户和reboot
		if username == "reboot" || username == "shutdown" {
			continue
		}

		// 如果该用户还没有记录，添加
		if _, exists := result[username]; !exists {
			info := loginInfo{}

			// 提取IP地址（last -i输出中IP在某个字段）
			for _, f := range fields {
				if strings.Contains(f, ".") && !strings.Contains(f, ":") {
					// 简单判断：包含点号且不是时间格式
					if net.ParseIP(f) != nil {
						info.ip = f
					}
				}
			}

			// 提取时间（日期在第二、三、四列可能）
			if len(fields) >= 4 {
				info.time = strings.Join(fields[3:6], " ")
			}

			result[username] = info
		}
	}

	return result
}

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

package collector

import (
	"bufio"
	"os"
	"strings"
)

// CronInfo 定时任务信息
type CronInfo struct {
	User     string `json:"user"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
	Source   string `json:"source"` // system_cron / user_cron / anacron
}

// CollectAllCronJobs 采集所有定时任务
func CollectAllCronJobs() []CronInfo {
	var crons []CronInfo

	// 1. 系统级 /etc/crontab
	crons = append(crons, parseCronFile("/etc/crontab", "root", "system_crontab")...)

	// 2. /etc/cron.d/
	crons = append(crons, parseCronDir("/etc/cron.d", "system_crond")...)

	// 3. /var/spool/cron/crontabs/ (Debian/Ubuntu) 和 /var/spool/cron/ (CentOS)
	crons = append(crons, parseUserCronDir("/var/spool/cron/crontabs")...)
	crons = append(crons, parseUserCronDir("/var/spool/cron")...)

	// 4. /etc/cron.hourly / daily / weekly / monthly
	crons = append(crons, parseScriptDir("/etc/cron.hourly", "hourly")...)
	crons = append(crons, parseScriptDir("/etc/cron.daily", "daily")...)
	crons = append(crons, parseScriptDir("/etc/cron.weekly", "weekly")...)
	crons = append(crons, parseScriptDir("/etc/cron.monthly", "monthly")...)

	// 5. anacron
	crons = append(crons, parseCronFile("/etc/anacrontab", "root", "anacron")...)

	return crons
}

func parseCronFile(path, defaultUser, source string) []CronInfo {
	var crons []CronInfo

	data, err := os.ReadFile(path)
	if err != nil {
		return crons
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 跳过环境变量定义
		if strings.Contains(line, "=") && !strings.Contains(line, " ") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		// 如果第一个字段是用户名（/etc/crontab格式）
		user := defaultUser
		scheduleStart := 0
		if !isTimeField(fields[0]) {
			user = fields[0]
			scheduleStart = 1
		}

		if len(fields) < scheduleStart+6 {
			continue
		}

		schedule := strings.Join(fields[scheduleStart:scheduleStart+5], " ")
		command := strings.Join(fields[scheduleStart+5:], " ")

		crons = append(crons, CronInfo{
			User:     user,
			Schedule: schedule,
			Command:  command,
			Source:   source,
		})
	}

	return crons
}

func parseCronDir(dir, source string) []CronInfo {
	var crons []CronInfo

	entries, err := os.ReadDir(dir)
	if err != nil {
		return crons
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := dir + "/" + entry.Name()
		// 这些文件没有用户字段，默认root
		crons = append(crons, parseCronFile(path, "root", source)...)
	}

	return crons
}

func parseUserCronDir(dir string) []CronInfo {
	var crons []CronInfo

	entries, err := os.ReadDir(dir)
	if err != nil {
		return crons
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		username := entry.Name()
		path := dir + "/" + username
		crons = append(crons, parseCronFile(path, username, "user_cron")...)
	}

	return crons
}

func parseScriptDir(dir, source string) []CronInfo {
	var crons []CronInfo

	entries, err := os.ReadDir(dir)
	if err != nil {
		return crons
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// 只采集可执行脚本
		path := dir + "/" + entry.Name()
		info, err := os.Stat(path)
		if err != nil || info.Mode()&0111 == 0 {
			continue
		}

		crons = append(crons, CronInfo{
			User:     "root",
			Schedule: "@" + source,
			Command:  path,
			Source:   source,
		})
	}

	return crons
}

// 判断是否时间字段（分钟/小时/日/月/星期）
func isTimeField(field string) bool {
	// 数字、*、*/N、1-5 都是时间字段
	if field == "*" {
		return true
	}
	if strings.Contains(field, "*/") || strings.Contains(field, "-") || strings.Contains(field, ",") {
		return true
	}
	for _, c := range field {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}

// CollectCronSummary 采集定时任务摘要（只返回可疑的）
func CollectCronSummary() []CronInfo {
	all := CollectAllCronJobs()
	var suspicious []CronInfo

	suspiciousPaths := []string{"/tmp", "/dev/shm", "/var/tmp", "curl", "wget", "nc", "bash -i", "python -c"}

	for _, c := range all {
		cmdLower := strings.ToLower(c.Command)
		for _, sus := range suspiciousPaths {
			if strings.Contains(cmdLower, sus) {
				suspicious = append(suspicious, c)
				break
			}
		}
	}

	return suspicious
}

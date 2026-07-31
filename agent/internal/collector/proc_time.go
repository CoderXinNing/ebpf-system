package collector

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func GetProcessStartTimeFormatted(pid int) string {
	// 方案1: 读 /proc/pid/stat
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "-"
	}

	content := string(data)
	idx := strings.LastIndex(content, ")")
	if idx < 0 {
		return "-"
	}

	fields := strings.Fields(content[idx+2:])
	if len(fields) < 20 {
		return "-"
	}

	starttimeTicks, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil {
		return "-"
	}

	// 读系统启动时间
	btime := getBootTimeFromStat()
	if btime == 0 {
		return "-"
	}

	clkTck := int64(100)
	uptime := btime + starttimeTicks/clkTck
	return time.Unix(uptime, 0).Format("2006-01-02 15:04:05")
}

func getBootTimeFromStat() int64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "btime") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, _ := strconv.ParseInt(fields[1], 10, 64)
				return val
			}
		}
	}
	return 0
}

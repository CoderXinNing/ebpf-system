package collector

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func GetProcessStartTimeFormatted(pid int) string {
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

	starttimeTicks, _ := strconv.ParseInt(fields[18], 10, 64)
	clkTck := int64(100)
	btime := getBootTime()
	if btime == 0 {
		return "-"
	}

	uptime := btime + starttimeTicks/clkTck
	return time.Unix(uptime, 0).Format("2006-01-02 15:04:05")
}

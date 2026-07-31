package collector

import (
	"fmt"
	"os"
	"strconv"
	"os/exec"
	"strings"
)

type PerfData struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemPercent    float64 `json:"mem_percent"`
	MemUsedMB     int     `json:"mem_used_mb"`
	MemTotalMB    int     `json:"mem_total_mb"`
	DiskUsage     []DiskPerf `json:"disk_usage"`
	NetBytesRecv  int64  `json:"net_bytes_recv"`
	NetBytesSent  int64  `json:"net_bytes_sent"`
}

type DiskPerf struct {
	MountPoint string `json:"mount_point"`
	UsedMB     int    `json:"used_mb"`
	TotalMB    int    `json:"total_mb"`
	Percent    string `json:"percent"`
}

func CollectPerfData() *PerfData {
	p := &PerfData{}

	// CPU使用率：读 /proc/stat
	p.CPUPercent = getCPUPercent()

	// 内存：/proc/meminfo
	p.MemPercent, p.MemUsedMB, p.MemTotalMB = getMemInfo()

	// 磁盘
	p.DiskUsage = getDiskPerf()

	return p
}

func getCPUPercent() float64 {
	data, _ := os.ReadFile("/proc/stat")
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 8 {
				return 0
			}
			// user, nice, system, idle, iowait, irq, softirq, steal
			var total, idle float64
			for i, f := range fields[1:] {
				v, _ := strconv.ParseFloat(f, 64)
				total += v
				if i == 3 { // idle是第4个
					idle = v
				}
			}
			if total > 0 {
				return (1 - idle/total) * 100
			}
		}
	}
	return 0
}

func getMemInfo() (percent float64, usedMB int, totalMB int) {
	data, _ := os.ReadFile("/proc/meminfo")
	var total, avail, buffers, cached int
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			fmt.Sscanf(line, "MemTotal: %d kB", &total)
		case strings.HasPrefix(line, "MemAvailable:"):
			fmt.Sscanf(line, "MemAvailable: %d kB", &avail)
		case strings.HasPrefix(line, "Buffers:"):
			fmt.Sscanf(line, "Buffers: %d kB", &buffers)
		case strings.HasPrefix(line, "Cached:"):
			fmt.Sscanf(line, "Cached: %d kB", &cached)
		}
	}
	totalMB = total / 1024
	if total > 0 {
		used := total - avail
		usedMB = used / 1024
		percent = float64(used) / float64(total) * 100
	}
	return
}

func getDiskPerf() []DiskPerf {
	var disks []DiskPerf
	out, err := exec.Command("df", "-BM").Output()
	if err != nil {
		return disks
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || (!strings.HasPrefix(fields[0], "/dev/") && !strings.HasPrefix(fields[0], "overlay")) {
			continue
		}
		total, _ := strconv.Atoi(strings.TrimSuffix(fields[1], "M"))
		used, _ := strconv.Atoi(strings.TrimSuffix(fields[2], "M"))
		disks = append(disks, DiskPerf{
			MountPoint: fields[5],
			UsedMB:     used,
			TotalMB:    total,
			Percent:    fields[4],
		})
	}
	return disks
}

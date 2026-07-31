package collector

import (
	"os"
	"os/exec"
	"strings"
)

// 系统启动时间
func GetSystemBootTime() string {
	out, err := exec.Command("uptime", "-s").Output()
	if err != nil {
		return "-"
	}
	return strings.TrimSpace(string(out))
}

// 磁盘使用率
type DiskUsage struct {
	MountPoint string `json:"mount_point"`
	TotalMB    int    `json:"total_mb"`
	UsedMB     int    `json:"used_mb"`
	UsePercent string `json:"use_percent"`
}

func CollectDiskUsage() []DiskUsage {
	var usages []DiskUsage
	out, err := exec.Command("df", "-BM").Output()
	if err != nil {
		return usages
	}

	lines := strings.Split(string(out), "\n")
	if len(lines) < 2 {
		return usages
	}

	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		fsType := fields[0]
		if !strings.HasPrefix(fsType, "/dev/") && !strings.HasPrefix(fsType, "overlay") {
			continue
		}

		totalStr := strings.TrimSuffix(fields[1], "M")
		usedStr := strings.TrimSuffix(fields[2], "M")
		total, _ := parseInt(totalStr)
		used, _ := parseInt(usedStr)

		usages = append(usages, DiskUsage{
			MountPoint: fields[5],
			TotalMB:    total,
			UsedMB:     used,
			UsePercent: fields[4],
		})
	}
	return usages
}

// 网卡详细信息
type NetworkDetail struct {
	Name   string `json:"name"`
	MAC    string `json:"mac"`
	IPs    []string `json:"ips"`
	Speed  string `json:"speed"`
	Duplex string `json:"duplex"`
	MTU    string `json:"mtu"`
}

func CollectNetworkDetails() []NetworkDetail {
	var nets []NetworkDetail

	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nets
	}

	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" {
			continue
		}

		nd := NetworkDetail{Name: name}

		// MAC
		if data, err := os.ReadFile("/sys/class/net/" + name + "/address"); err == nil {
			nd.MAC = strings.TrimSpace(string(data))
		}

		// MTU
		if data, err := os.ReadFile("/sys/class/net/" + name + "/mtu"); err == nil {
			nd.MTU = strings.TrimSpace(string(data))
		}

		// IP
		out, _ := exec.Command("ip", "-4", "addr", "show", name).Output()
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "inet ") {
				f := strings.Fields(strings.TrimSpace(line))
				if len(f) >= 2 {
					nd.IPs = append(nd.IPs, f[1])
				}
			}
		}

		// Speed / Duplex (需要ethtool)
		if out, err := exec.Command("ethtool", name).Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "Speed:") {
					nd.Speed = strings.TrimSpace(strings.TrimPrefix(line, "Speed:"))
				}
				if strings.HasPrefix(line, "Duplex:") {
					nd.Duplex = strings.TrimSpace(strings.TrimPrefix(line, "Duplex:"))
				}
			}
		}

		nets = append(nets, nd)
	}

	return nets
}

package collector

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// SystemInfo 系统静态信息
type SystemInfo struct {
	OS       OSInfo       `json:"os"`
	CPU      CPUInfo      `json:"cpu"`
	Memory   MemoryInfo   `json:"memory"`
	Disks    []DiskInfo   `json:"disks"`
	Networks []NetworkInfo `json:"networks"`
	Modules  []string     `json:"kernel_modules"`
	Services []ServiceInfo `json:"services"`
	Locale   string       `json:"locale"`
	Timezone string       `json:"timezone"`
}

type OSInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Kernel  string `json:"kernel"`
}

type CPUInfo struct {
	Model string `json:"model"`
	Cores int    `json:"cores"`
}

type MemoryInfo struct {
	TotalMB  int `json:"total_mb"`
	SwapTotalMB int `json:"swap_total_mb"`
}

type DiskInfo struct {
	MountPoint string `json:"mount_point"`
	Filesystem string `json:"filesystem"`
	TotalMB    int    `json:"total_mb"`
}

type NetworkInfo struct {
	Name    string `json:"name"`
	MAC     string `json:"mac"`
	IPs     []string `json:"ips"`
}

type ServiceInfo struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// CollectSystemInfo 采集系统静态信息
func CollectSystemInfo() (*SystemInfo, error) {
	info := &SystemInfo{}

	info.OS = collectOSInfo()
	info.CPU = collectCPUInfo()
	info.Memory = collectMemoryInfo()
	info.Disks = collectDiskInfo()
	info.Networks = collectNetworkInfo()
	info.Modules = collectKernelModules()
	info.Services = collectServices()
	info.Locale = collectLocale()
	info.Timezone = collectTimezone()

	return info, nil
}

func collectOSInfo() OSInfo {
	osInfo := OSInfo{}

	// /etc/os-release
	data, err := os.ReadFile("/etc/os-release")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				osInfo.Name = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
			}
			if strings.HasPrefix(line, "VERSION_ID=") {
				osInfo.Version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
			}
		}
	}

	// 内核版本
	kernel, _ := os.ReadFile("/proc/version")
	osInfo.Kernel = strings.Fields(string(kernel))[2]

	return osInfo
}

func collectCPUInfo() CPUInfo {
	cpu := CPUInfo{Cores: 0}

	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return cpu
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "model name") && cpu.Model == "" {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				cpu.Model = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(line, "processor") {
			cpu.Cores++
		}
	}

	return cpu
}

func collectMemoryInfo() MemoryInfo {
	mem := MemoryInfo{}

	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return mem
	}

	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			fmt.Sscanf(line, "MemTotal: %d kB", &mem.TotalMB)
			mem.TotalMB /= 1024
		case strings.HasPrefix(line, "SwapTotal:"):
			fmt.Sscanf(line, "SwapTotal: %d kB", &mem.SwapTotalMB)
			mem.SwapTotalMB /= 1024
		}
	}

	return mem
}

func collectDiskInfo() []DiskInfo {
	var disks []DiskInfo

	cmd := exec.Command("df", "-B", "M")
	output, err := cmd.Output()
	if err != nil {
		return disks
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	scanner.Scan() // 跳过表头
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}

		// 只采集真实磁盘（排除tmpfs/devtmpfs/squashfs）
		fsType := fields[0]
		if strings.HasPrefix(fsType, "/dev/") || strings.HasPrefix(fsType, "overlay") {
			totalStr := strings.TrimSuffix(fields[1], "M")
			total, _ := parseInt(totalStr)
			disks = append(disks, DiskInfo{
				Filesystem: fields[0],
				MountPoint: fields[5],
				TotalMB:    total,
			})
		}
	}

	return disks
}

func collectNetworkInfo() []NetworkInfo {
	var networks []NetworkInfo

	// 读 /sys/class/net/ 目录
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return networks
	}

	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" {
			continue
		}

		netInfo := NetworkInfo{Name: name}

		// MAC地址
		macData, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/address", name))
		if err == nil {
			netInfo.MAC = strings.TrimSpace(string(macData))
		}

		// IP地址（用ip addr命令）
		cmd := exec.Command("ip", "-4", "addr", "show", name)
		output, err := cmd.Output()
		if err == nil {
			for _, line := range strings.Split(string(output), "\n") {
				if strings.Contains(line, "inet ") {
					fields := strings.Fields(strings.TrimSpace(line))
					if len(fields) >= 2 {
						netInfo.IPs = append(netInfo.IPs, fields[1])
					}
				}
			}
		}

		networks = append(networks, netInfo)
	}

	return networks
}

func collectKernelModules() []string {
	var modules []string

	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return modules
	}

	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			modules = append(modules, fields[0])
		}
	}

	return modules
}

func collectServices() []ServiceInfo {
	var services []ServiceInfo

	// 只采集enabled的service
	cmd := exec.Command("systemctl", "list-unit-files", "--type=service", "--state=enabled")
	output, err := cmd.Output()
	if err != nil {
		return services
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, ".service") && strings.Contains(line, "enabled") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				services = append(services, ServiceInfo{
					Name:    fields[0],
					Enabled: true,
				})
			}
		}
	}

	return services
}

func collectLocale() string {
	data, err := os.ReadFile("/etc/default/locale")
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "LANG=") {
			return strings.TrimPrefix(line, "LANG=")
		}
	}
	return "unknown"
}

func collectTimezone() string {
	// 读 /etc/timezone 或 /etc/localtime 软链接
	data, err := os.ReadFile("/etc/timezone")
	if err == nil {
		return strings.TrimSpace(string(data))
	}

	// 读软链接
	link, err := os.Readlink("/etc/localtime")
	if err == nil {
		parts := strings.Split(link, "/")
		if len(parts) >= 2 {
			return parts[len(parts)-2] + "/" + parts[len(parts)-1]
		}
	}

	return "unknown"
}

func parseInt(s string) (int, error) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return n, fmt.Errorf("not a number: %s", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

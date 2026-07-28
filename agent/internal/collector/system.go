package collector

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type SystemInfo struct {
	OS       OSInfo        `json:"os"`
	CPU      CPUInfo       `json:"cpu"`
	Memory   MemoryInfo    `json:"memory"`
	Disks    []DiskInfo    `json:"disks"`
	Networks []NetworkInfo `json:"networks"`
	Modules  []string      `json:"kernel_modules"`
	Services []ServiceInfo `json:"services"`
	Locale   string        `json:"locale"`
	Timezone string        `json:"timezone"`
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
	TotalMB     int `json:"total_mb"`
	SwapTotalMB int `json:"swap_total_mb"`
}

type DiskInfo struct {
	MountPoint string `json:"mount_point"`
	Filesystem string `json:"filesystem"`
	TotalMB    int    `json:"total_mb"`
}

type NetworkInfo struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	IPs  []string `json:"ips"`
}

type ServiceInfo struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

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

	if osInfo.Name == "" {
		data, err = os.ReadFile("/etc/redhat-release")
		if err == nil {
			osInfo.Name = strings.TrimSpace(string(data))
		}
	}

	if osInfo.Name == "" {
		osInfo.Name = "Linux"
	}

	kernel, _ := os.ReadFile("/proc/version")
	if len(kernel) > 0 {
		osInfo.Kernel = strings.Fields(string(kernel))[2]
	}

	return osInfo
}

func collectCPUInfo() CPUInfo {
	cpu := CPUInfo{}

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
	scanner.Scan()
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}

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

		macData, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/address", name))
		if err == nil {
			netInfo.MAC = strings.TrimSpace(string(macData))
		}

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

	// 尝试systemd
	cmd := exec.Command("systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend")
	output, err := cmd.Output()
	if err != nil {
		// systemd不可用，尝试读取/etc/init.d（SysV）
		return collectSysVServices()
	}

	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, ".service") {
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

// collectSysVServices 兼容SysV init系统
func collectSysVServices() []ServiceInfo {
	var services []ServiceInfo

	// 读 /etc/rc*.d/ 下的启动脚本
	entries, err := os.ReadDir("/etc/init.d")
	if err != nil {
		return services
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// 检查是否在某个runlevel启用
		enabled := false
		for _, rc := range []string{"rc2.d", "rc3.d", "rc4.d", "rc5.d"} {
			rcDir := "/etc/" + rc
			rcEntries, err := os.ReadDir(rcDir)
			if err != nil {
				continue
			}
			for _, rcEntry := range rcEntries {
				if strings.HasPrefix(rcEntry.Name(), "S") && strings.Contains(rcEntry.Name(), name) {
					enabled = true
					break
				}
			}
			if enabled {
				break
			}
		}

		services = append(services, ServiceInfo{
			Name:    name,
			Enabled: enabled,
		})
	}

	return services
}

func collectLocale() string {
	data, err := os.ReadFile("/etc/default/locale")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "LANG=") {
				return strings.TrimPrefix(line, "LANG=")
			}
		}
	}

	data, err = os.ReadFile("/etc/locale.conf")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "LANG=") {
				return strings.TrimPrefix(line, "LANG=")
			}
		}
	}

	return "unknown"
}

func collectTimezone() string {
	data, err := os.ReadFile("/etc/timezone")
	if err == nil {
		return strings.TrimSpace(string(data))
	}

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

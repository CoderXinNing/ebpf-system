package collector

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
)

type HardwareInfo struct {
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	SerialNumber string `json:"serial_number"`
	UUID         string `json:"uuid"`
	BootTime     string `json:"boot_time"`
}

func CollectHardwareInfo() *HardwareInfo {
	hw := &HardwareInfo{}

	// dmidecode 获取硬件信息
	if out, err := exec.Command("dmidecode", "-s", "system-manufacturer").Output(); err == nil {
		hw.Manufacturer = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("dmidecode", "-s", "system-product-name").Output(); err == nil {
		hw.Model = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("dmidecode", "-s", "system-serial-number").Output(); err == nil {
		hw.SerialNumber = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("dmidecode", "-s", "system-uuid").Output(); err == nil {
		hw.UUID = strings.TrimSpace(string(out))
	}

	// 系统启动时间
	if out, err := exec.Command("uptime", "-s").Output(); err == nil {
		hw.BootTime = strings.TrimSpace(string(out))
	}

	return hw
}

// 内核模块详情
type KernelModuleDetail struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Path        string   `json:"path"`
	Version     string   `json:"version"`
	Size        string   `json:"size"`
	UsedBy      int      `json:"used_by"`
	Parameters  []string `json:"parameters"`
}

func CollectKernelModuleDetails() []KernelModuleDetail {
	var modules []KernelModuleDetail

	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return modules
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		name := fields[0]
		size := fields[1]
		usedBy := 0
		if fields[2] != "-" {
			usedBy = len(strings.Split(fields[2], ","))
		}

		detail := KernelModuleDetail{
			Name:   name,
			Size:   size,
			UsedBy: usedBy,
		}

		// modinfo 获取详细信息
		if out, err := exec.Command("modinfo", "-n", name).Output(); err == nil {
			detail.Path = strings.TrimSpace(string(out))
		}
		if out, err := exec.Command("modinfo", "-d", name).Output(); err == nil {
			detail.Description = strings.TrimSpace(string(out))
		}
		if out, err := exec.Command("modinfo", "-F", "version", name).Output(); err == nil {
			detail.Version = strings.TrimSpace(string(out))
		}

		// 参数列表
		paramDir := "/sys/module/" + name + "/parameters/"
		if entries, err := os.ReadDir(paramDir); err == nil {
			for _, e := range entries {
				paramData, _ := os.ReadFile(paramDir + e.Name())
				detail.Parameters = append(detail.Parameters, e.Name()+"="+strings.TrimSpace(string(paramData)))
			}
		}

		modules = append(modules, detail)
	}

	return modules
}

// 环境变量
type EnvVariable struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  string `json:"type"` // system / user
	User  string `json:"user"`
}

func CollectEnvVariables() []EnvVariable {
	var envs []EnvVariable

	// 系统级
	if data, err := os.ReadFile("/etc/environment"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 && parts[0] != "" {
				envs = append(envs, EnvVariable{Name: parts[0], Value: parts[1], Type: "系统"})
			}
		}
	}

	// 用户级 - 读 /etc/passwd 获取所有用户
	passwdData, _ := os.ReadFile("/etc/passwd")
	for _, line := range strings.Split(string(passwdData), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 6 {
			continue
		}
		user := fields[0]
		home := fields[5]
		if home == "" || home == "/" {
			continue
		}

		// 读用户的环境变量文件
		for _, file := range []string{".bashrc", ".profile", ".bash_profile"} {
			path := home + "/" + file
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(strings.NewReader(string(data)))
			for scanner.Scan() {
				line := scanner.Text()
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "export ") {
					line = strings.TrimPrefix(line, "export ")
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 && parts[0] != "" {
						envs = append(envs, EnvVariable{Name: parts[0], Value: parts[1], Type: "用户", User: user})
					}
				}
			}
		}
	}

	return envs
}

// 进程启动时间

func parseInt64(s string) int64 {
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int64(c-'0')
	}
	return n
}

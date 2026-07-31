package collector

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// 进程启动时间（完整版）
func GetProcessStartTime(pid int) string {
	// 读系统启动时间
	btime := getBootTime()
	if btime == 0 {
		return "-"
	}

	// 读进程stat
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

	// starttime是第19个字段（从0开始），单位是clock ticks
	starttimeTicks := parseInt64(fields[18])
	clkTck := int64(100) // Linux默认100

	uptime := btime + starttimeTicks/clkTck

	return fmt.Sprintf("%d", uptime)
}

// 软件包大小（KB）
func GetPackageSize(name string) int64 {
	// dpkg
	out, err := exec.Command("dpkg-query", "-W", "-f=${Installed-Size}", name).Output()
	if err == nil {
		s := strings.TrimSpace(string(out))
		if n, err := parseInt(s); err == nil {
			return int64(n)
		}
	}
	// rpm
	out, err = exec.Command("rpm", "-q", "--queryformat=%{SIZE}", name).Output()
	if err == nil {
		s := strings.TrimSpace(string(out))
		if n, err := parseInt(s); err == nil {
			return int64(n) / 1024
		}
	}
	return 0
}

// 系统服务运行状态
type ServiceStatus struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Active  string `json:"active"` // active/inactive/failed
}

func CollectServiceStatus() []ServiceStatus {
	var services []ServiceStatus

	// systemd
	out, err := exec.Command("systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend").Output()
	if err != nil {
		return services
	}

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 1 || !strings.Contains(fields[0], ".service") {
			continue
		}
		name := fields[0]

		// 查运行状态
		active := "unknown"
		statusOut, err := exec.Command("systemctl", "is-active", name).Output()
		if err == nil {
			active = strings.TrimSpace(string(statusOut))
		}

		services = append(services, ServiceStatus{
			Name:    name,
			Enabled: true,
			Active:  active,
		})
	}

	return services
}

// Jar包采集
type JarPackage struct {
	Name       string `json:"name"`
	Type       string `json:"type"`       // 应用程序 / 依赖包
	Executable bool   `json:"executable"`
	Version    string `json:"version"`
	Path       string `json:"path"`
}

func CollectJarPackages() []JarPackage {
	var jars []JarPackage
	seen := make(map[string]bool)

	// 常见Java应用目录
	searchDirs := []string{"/opt", "/usr/local", "/var/lib", "/home"}
	for _, dir := range searchDirs {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || seen[path] {
				return nil
			}
			if strings.HasSuffix(path, ".jar") {
				seen[path] = true
				name := filepath.Base(path)

				// 解析版本号
				version := "未知"
				parts := strings.Split(strings.TrimSuffix(name, ".jar"), "-")
				for _, p := range parts {
					if looksLikeVersion(p) {
						version = p
						break
					}
				}

				jars = append(jars, JarPackage{
					Name:       name,
					Type:       "依赖包",
					Executable: false,
					Version:    version,
					Path:       path,
				})
			}
			return nil
		})
	}

	return jars
}

// Python包
type PythonPackage struct {
	Name  string `json:"name"`
	Version string `json:"version"`
	Path string `json:"path"`
	Scope string `json:"scope"` // global / user
}

func CollectPythonPackages() []PythonPackage {
	var pkgs []PythonPackage

	// pip list
	out, err := exec.Command("pip3", "list", "--format=columns").Output()
	if err != nil {
		out, err = exec.Command("pip", "list", "--format=columns").Output()
	}
	if err != nil {
		// 降级：从系统包管理器获取
		return collectPythonFromPkg()
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines[2:] { // 跳过表头
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			pkgs = append(pkgs, PythonPackage{
				Name:    fields[0],
				Version: fields[1],
				Scope:   "global",
				Path:    "-",
			})
		}
	}

	return pkgs
}

// Npm包
type NpmPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Path    string `json:"path"`
	Scope   string `json:"scope"`
}

func looksLikeVersion(s string) bool {
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	dotCount := 0
	for _, c := range s {
		if c == '.' {
			dotCount++
		} else if c < '0' || c > '9' {
			return false
		}
	}
	return dotCount >= 1 && len(s) >= 3 && len(s) <= 15
}

func CollectNpmPackages() []NpmPackage {
	var pkgs []NpmPackage

	// npm list -g
	out, err := exec.Command("npm", "list", "-g", "--depth=0").Output()
	if err != nil {
		return pkgs
	}

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "├──") || strings.HasPrefix(line, "└──") {
			line = strings.TrimPrefix(strings.TrimPrefix(line, "├── "), "└── ")
			parts := strings.SplitN(line, "@", 2)
			if len(parts) == 2 {
				pkgs = append(pkgs, NpmPackage{
					Name:    parts[0],
					Version: parts[1],
					Path:    "-",
					Scope:   "global",
				})
			}
		}
	}

	return pkgs
}

func collectPythonFromPkg() []PythonPackage {
	var pkgs []PythonPackage
	// dpkg
	out, err := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\n").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Split(line, "\t")
			if len(fields) >= 2 && strings.HasPrefix(fields[0], "python3-") {
				pkgs = append(pkgs, PythonPackage{
					Name: strings.TrimPrefix(fields[0], "python3-"),
					Version: fields[1],
					Scope: "system",
					Path: "-",
				})
			}
		}
	}
	return pkgs
}

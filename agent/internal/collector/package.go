package collector

import (
	"os"
	"os/exec"
	"strings"
)

type PackageInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Manager string `json:"manager"`
}

func CollectAllPackages() []PackageInfo {
	var packages []PackageInfo

	// 按优先级尝试各种包管理器
	packages = collectDebPackages()
	if len(packages) > 0 {
		return packages
	}

	packages = collectRPMPackages()
	if len(packages) > 0 {
		return packages
	}

	packages = collectAlpinePackages()
	if len(packages) > 0 {
		return packages
	}

	packages = collectPacmanPackages()
	if len(packages) > 0 {
		return packages
	}

	return packages
}

func collectDebPackages() []PackageInfo {
	var packages []PackageInfo

	if _, err := os.Stat("/var/lib/dpkg/status"); os.IsNotExist(err) {
		return packages
	}

	cmd := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\n")
	output, err := cmd.Output()
	if err != nil {
		return packages
	}

	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) >= 2 && fields[0] != "" {
			packages = append(packages, PackageInfo{
				Name:    fields[0],
				Version: fields[1],
				Manager: "dpkg",
			})
		}
	}

	return packages
}

func collectRPMPackages() []PackageInfo {
	var packages []PackageInfo

	if _, err := os.Stat("/var/lib/rpm"); os.IsNotExist(err) {
		return packages
	}

	cmd := exec.Command("rpm", "-qa", "--queryformat=%{NAME}\t%{VERSION}-%{RELEASE}\n")
	output, err := cmd.Output()
	if err != nil {
		return packages
	}

	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) >= 2 && fields[0] != "" {
			packages = append(packages, PackageInfo{
				Name:    fields[0],
				Version: fields[1],
				Manager: "rpm",
			})
		}
	}

	return packages
}

func collectAlpinePackages() []PackageInfo {
	var packages []PackageInfo

	if _, err := os.Stat("/sbin/apk"); os.IsNotExist(err) {
		return packages
	}

	cmd := exec.Command("apk", "info", "-v")
	output, err := cmd.Output()
	if err != nil {
		return packages
	}

	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// apk格式: package-version
		lastDash := strings.LastIndex(line, "-")
		if lastDash > 0 {
			packages = append(packages, PackageInfo{
				Name:    line[:lastDash],
				Version: line[lastDash+1:],
				Manager: "apk",
			})
		}
	}

	return packages
}

func collectPacmanPackages() []PackageInfo {
	var packages []PackageInfo

	if _, err := os.Stat("/usr/bin/pacman"); os.IsNotExist(err) {
		return packages
	}

	cmd := exec.Command("pacman", "-Q")
	output, err := cmd.Output()
	if err != nil {
		return packages
	}

	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			packages = append(packages, PackageInfo{
				Name:    fields[0],
				Version: fields[1],
				Manager: "pacman",
			})
		}
	}

	return packages
}

package collector

import (
	"os/exec"
	"strings"
)

// PackageInfo 软件包信息
type PackageInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Manager string `json:"manager"` // dpkg / rpm
}

// CollectAllPackages 采集所有已安装软件包
func CollectAllPackages() []PackageInfo {
	var packages []PackageInfo

	// 尝试 dpkg (Debian/Ubuntu)
	packages = append(packages, collectDebPackages()...)

	// 尝试 rpm (CentOS/RHEL)
	if len(packages) == 0 {
		packages = append(packages, collectRPMPackages()...)
	}

	return packages
}

func collectDebPackages() []PackageInfo {
	var packages []PackageInfo

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

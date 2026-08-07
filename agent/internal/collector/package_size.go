package collector

import (
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

var pkgSizeCache map[string]int64
var pkgSizeOnce sync.Once

func loadPkgSizes() {
	pkgSizeOnce.Do(func() {
		pkgSizeCache = make(map[string]int64)
		out, err := exec.Command("dpkg-query", "-W", "-f", "${Package}\t${Installed-Size}\n").Output()
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Split(line, "\t")
			if len(fields) >= 2 {
				if size, err := strconv.ParseInt(strings.TrimSpace(fields[1]), 10, 64); err == nil {
					pkgSizeCache[fields[0]] = size
				}
			}
		}
	})
}

func GetPkgSize(name string) int64 {
	loadPkgSizes()
	return pkgSizeCache[name]
}

package plugins

import (
	"bufio"
	"net"
	"os"
	"strconv"
	"strings"
)

// getDefaultGateway 从 /proc/net/route 读取默认网关 IP
// 返回 "" 表示读取失败
func getDefaultGateway() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // 跳过表头
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		gwHex := fields[2]
		if len(gwHex) != 8 {
			continue
		}
		n, err := strconv.ParseUint(gwHex, 16, 32)
		if err != nil {
			continue
		}
		// /proc/net/route 里 IP 是小端序
		return net.IPv4(
			byte(n), byte(n>>8), byte(n>>16), byte(n>>24),
		).String()
	}
	return ""
}

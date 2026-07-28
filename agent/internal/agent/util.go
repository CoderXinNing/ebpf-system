package agent

import (
	"crypto/md5"
	"fmt"
	"net"
	"os"
)

func getHostname() string {
	name, _ := os.Hostname()
	return name
}

func getIPAddress() string {
	conn, _ := net.Dial("udp", "8.8.8.8:80")
	if conn != nil {
		defer conn.Close()
		return conn.LocalAddr().(*net.UDPAddr).IP.String()
	}
	return "unknown"
}

func generateAgentID(hostname string) string {
	hash := md5.Sum([]byte(hostname))
	return fmt.Sprintf("agent-%x", hash[:8])
}

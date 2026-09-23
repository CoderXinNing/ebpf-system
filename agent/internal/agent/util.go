package agent

import (
	"crypto/md5"
	"fmt"
	"net"
	"os"
	"strings"
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

// generateAgentHash 生成 Agent 哈希值（V3 探针 correlation_key 使用）
func generateAgentHash(agentID string) uint32 {
    if len(agentID) > 8 {
        agentID = agentID[:8]
    }
    var hash uint32
    for _, c := range []byte(agentID) {
        hash = hash*31 + uint32(c)
    }
    return hash
}

// loadAgentID 优先从文件读 agent_id，失败则从 hostname 生成
func loadAgentID(idFile, hostname string) string {
	if idFile != "" {
		if data, err := os.ReadFile(idFile); err == nil {
			id := strings.TrimSpace(string(data))
			if id != "" {
				return id
			}
		}
	}
	return generateAgentID(hostname)
}

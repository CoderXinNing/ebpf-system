package agent

import (
	"crypto/md5"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
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

// loadAgentID 优先从文件读 agent_id。
// 文件不存在时生成一个（基于 hostname MD5）并写回文件，下次启动保持稳定。
// ⚠️ 生产环境应先走 enrollment，由 Server 生成 agent.id，此兜底仅用于开发机。
func loadAgentID(idFile, hostname string) string {
	if idFile != "" {
		if data, err := os.ReadFile(idFile); err == nil {
			id := strings.TrimSpace(string(data))
			if id != "" {
				return id
			}
		}
	}

	// 兜底：生成 + 持久化
	id := generateAgentID(hostname)
	if idFile == "" {
		log.Printf("⚠️ agent.id 路径未配置（agent.toml [agent].id_file），使用临时 ID: %s", id)
		return id
	}
	if err := os.MkdirAll(filepath.Dir(idFile), 0755); err != nil {
		log.Printf("⚠️ 创建 agent.id 目录失败: %v（使用临时 ID: %s）", err, id)
		return id
	}
	if err := os.WriteFile(idFile, []byte(id+"\n"), 0600); err != nil {
		log.Printf("⚠️ 写入 agent.id 失败: %v（使用临时 ID: %s）", err, id)
		return id
	}
	log.Printf("⚠️ 未找到 agent.id，已生成并持久化: %s（生产环境应先走 enrollment）", id)
	return id
}

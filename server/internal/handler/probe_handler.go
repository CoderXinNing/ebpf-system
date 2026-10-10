package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"os"

	"github.com/gin-gonic/gin"
)

// ListProbeConfigs 查询探针配置
func (h *Handler) ListProbeConfigs(c *gin.Context) {
	agentID := c.Query("agent_id")
	if agentID == "" {
		c.JSON(400, gin.H{"error": "缺少agent_id"})
		return
	}
	if h.GetProbeConfigsFunc != nil {
		configs, err := h.GetProbeConfigsFunc(agentID)
		if err != nil {
			c.JSON(500, gin.H{"error": "查询失败"})
			return
		}
		c.JSON(200, gin.H{"configs": configs})
		return
	}
	c.JSON(200, gin.H{"configs": []interface{}{}})
}

// DeployProbe 下发/更新探针配置
func (h *Handler) DeployProbe(c *gin.Context) {
	var req struct {
		AgentID   string `json:"agent_id"`
		ProbeName string `json:"probe_name"`
		Enabled   bool   `json:"enabled"`
		Remove    bool   `json:"remove"`
		Path      string `json:"path"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	if req.AgentID == "" || req.ProbeName == "" {
		c.JSON(400, gin.H{"error": "agent_id和probe_name必填"})
		return
	}
	if req.Path == "" {
		paths := map[string]string{
			"exec_monitor": "probes/templates/exec_monitor_ebpf/exec_monitor.o",
			"bash_monitor": "probes/templates/bash_monitor/bash_monitor.o",
			"tcp_monitor":  "probes/templates/tcp_monitor/tcp_monitor.o",
		}
		req.Path = paths[req.ProbeName]
	}

	sha256Hash := ""
	if data, err := os.ReadFile(req.Path); err == nil {
		hash := sha256.Sum256(data)
		sha256Hash = hex.EncodeToString(hash[:])
	}

	// PSQL 模式：probe_configs 表尚未接入（等 probe_templates 设计完成）
	_ = sha256Hash
	c.JSON(501, gin.H{"error": "探针配置下发暂未接入（等 probe_templates 设计）"})
}

// DestroyProbe 删除探针配置
func (h *Handler) DestroyProbe(c *gin.Context) {
	var req struct {
		AgentID   string `json:"agent_id"`
		ProbeName string `json:"probe_name"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	if req.AgentID == "" || req.ProbeName == "" {
		c.JSON(400, gin.H{"error": "agent_id和probe_name必填"})
		return
	}
	// PSQL 模式：probe_configs 表尚未接入（等 probe_templates 设计完成）
	c.JSON(501, gin.H{"error": "探针配置删除暂未接入（等 probe_templates 设计）"})
}

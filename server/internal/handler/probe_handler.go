package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/CoderXinNing/ebpf-system/server/internal/store"
)

// ListProbeConfigs 查询探针配置
func (h *Handler) ListProbeConfigs(c *gin.Context) {
	agentID := c.Query("agent_id")
	if agentID == "" {
		c.JSON(400, gin.H{"error": "缺少agent_id"})
		return
	}
	configs, err := h.Store.GetProbeConfigs(agentID)
	if err != nil {
		c.JSON(500, gin.H{"error": "查询失败"})
		return
	}
	c.JSON(200, gin.H{"configs": configs})
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

	err := h.Store.UpsertProbeConfig(store.ProbeConfigRecord{
		AgentID:   req.AgentID,
		ProbeName: req.ProbeName,
		Enabled:   req.Enabled,
		Remove:    req.Remove,
		Path:      req.Path,
		Sha256:    sha256Hash,
	})
	if err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	log.Printf("📋 探针配置: %s %s (enabled=%v)", req.AgentID, req.ProbeName, req.Enabled)
	c.JSON(200, gin.H{"success": true})
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
	if err := h.Store.DeleteProbeConfig(req.AgentID, req.ProbeName); err != nil {
		c.JSON(500, gin.H{"error": "删除失败"})
		return
	}
	log.Printf("🗑️ 删除探针配置: %s %s", req.AgentID, req.ProbeName)
	c.JSON(200, gin.H{"success": true})
}

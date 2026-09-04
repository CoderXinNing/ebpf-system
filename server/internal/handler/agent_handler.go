package handler

import (
	"log"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
)

// Health 健康检查
func (h *Handler) Health(c *gin.Context) {
	h.Mu.RLock()
	defer h.Mu.RUnlock()
	now := time.Now().Unix()
	online := 0
	for _, a := range h.Agents {
		if now-a.LastSeen < 60 {
			online++
		}
	}
	c.JSON(200, gin.H{"status": "ok", "online": online, "total": len(h.Agents)})
}

// ListAgents 主机列表
func (h *Handler) ListAgents(c *gin.Context) {
	h.Mu.RLock()
	defer h.Mu.RUnlock()
	agents := make([]AgentInfo, 0, len(h.Agents))
	for _, a := range h.Agents {
		agents = append(agents, *a)
	}
	c.JSON(200, gin.H{"total": len(agents), "agents": agents})
}

// ListEvents 事件列表
func (h *Handler) ListEvents(c *gin.Context) {
	agentID := c.Query("agent_id")
	limit := 100
	if l := c.Query("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	dbEvents, dbErr := h.Store.GetEvents(limit, agentID)
	if dbErr == nil && len(dbEvents) > 0 {
		c.JSON(200, gin.H{"total": len(dbEvents), "events": dbEvents, "source": "sqlite"})
		return
	}
	h.EventMu.RLock()
	defer h.EventMu.RUnlock()
	evts := h.Events
	if len(evts) > limit {
		evts = evts[len(evts)-limit:]
	}
	c.JSON(200, gin.H{"total": len(h.Events), "events": evts, "source": "memory"})
}

// Command 下发指令
func (h *Handler) Command(c *gin.Context) {
	var req struct {
		AgentID     string `json:"agent_id"`
		ProbeName   string `json:"probe_name"`
		Action      string `json:"action"`
		ProbeData   string `json:"probe_data"`
		ProbeConfig string `json:"probe_config"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请求格式错误"})
		return
	}

	var cmdType pb.ProbeCommand_CommandType
	switch req.Action {
	case "load":
		cmdType = pb.ProbeCommand_LOAD
	case "unload":
		cmdType = pb.ProbeCommand_UNLOAD
	case "install":
		cmdType = pb.ProbeCommand_INSTALL
	case "collect":
		cmdType = pb.ProbeCommand_COLLECT
	case "reload":
		cmdType = pb.ProbeCommand_RELOAD
	default:
		c.JSON(400, gin.H{"error": "action无效"})
		return
	}

	cmd := &pb.ProbeCommand{
		Type:        cmdType,
		ProbeName:   req.ProbeName,
		ProbeData:   []byte(req.ProbeData),
		ProbeConfig: req.ProbeConfig,
	}
	if err := h.sendCmd(req.AgentID, cmd); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	log.Printf("📋 指令: %s -> %s (%s)", req.AgentID, req.ProbeName, req.Action)
	c.JSON(200, gin.H{"success": true, "message": "指令已排队"})
}

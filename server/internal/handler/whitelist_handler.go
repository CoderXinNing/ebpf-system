package handler

import (
	"encoding/json"
	"log"

	"github.com/gin-gonic/gin"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
)

// WhitelistItem 白名单条目
type WhitelistItem struct {
	ProcessName string `json:"process_name"`
	Reason      string `json:"reason"`
}

// ListWhitelist 查询白名单
func (h *Handler) ListWhitelist(c *gin.Context) {
	c.JSON(200, gin.H{"whitelist": h.Whitelist})
}

// AddWhitelist 添加白名单
func (h *Handler) AddWhitelist(c *gin.Context) {
	var req WhitelistItem
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请求格式错误"})
		return
	}

	// 去重
	for _, name := range h.Whitelist {
		if name == req.ProcessName {
			c.JSON(200, gin.H{"success": true, "message": "已存在"})
			return
		}
	}

	h.Whitelist = append(h.Whitelist, req.ProcessName)

	// 广播白名单更新给所有 Agent（通过心跳命令）
	h.broadcastWhitelist()
	if h.WhitelistUpdateFunc != nil {
		h.WhitelistUpdateFunc(h.Whitelist)
	}

	c.JSON(200, gin.H{"success": true, "message": "白名单已添加并下发"})
}

// RemoveWhitelist 移除白名单
func (h *Handler) RemoveWhitelist(c *gin.Context) {
	processName := c.Param("process_name")
	
	newList := make([]string, 0, len(h.Whitelist))
	for _, name := range h.Whitelist {
		if name != processName {
			newList = append(newList, name)
		}
	}
	h.Whitelist = newList

	h.broadcastWhitelist()
	if h.WhitelistUpdateFunc != nil {
		h.WhitelistUpdateFunc(h.Whitelist)
	}
	c.JSON(200, gin.H{"success": true, "message": "白名单已移除"})
}

// broadcastWhitelist 将白名单塞入所有 Agent 的命令队列
func (h *Handler) broadcastWhitelist() {
	jsonData, _ := json.Marshal(h.Whitelist)
	
	h.Mu.Lock()
	defer h.Mu.Unlock()
	
	for agentID, agent := range h.Agents {
		agent.Commands = append(agent.Commands, &pb.ProbeCommand{
			Type:        pb.ProbeCommand_UNLOAD, // 复用 UNLOAD 类型传白名单
			ProbeName:   "whitelist",
			ProbeConfig: string(jsonData),
		})
		log.Printf("📤 白名单已塞入 Agent %s 队列: %v", agentID, h.Whitelist)
	}
}

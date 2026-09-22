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
	// 优先查 PSQL
	if h.ListWhitelistFunc != nil {
		list, err := h.ListWhitelistFunc()
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		h.Whitelist = list
		c.JSON(200, gin.H{"whitelist": list})
		return
	}
	c.JSON(200, gin.H{"whitelist": h.Whitelist})
}

// AddWhitelist 添加白名单
func (h *Handler) AddWhitelist(c *gin.Context) {
	var req WhitelistItem
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请求格式错误"})
		return
	}
	if req.ProcessName == "" {
		c.JSON(400, gin.H{"error": "进程名不能为空"})
		return
	}

	// 写入 PSQL
	if h.AddWhitelistFunc != nil {
		if err := h.AddWhitelistFunc(req.ProcessName, req.Reason); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
	}

	// 更新内存
	h.Mu.Lock()
	found := false
	for _, name := range h.Whitelist {
		if name == req.ProcessName {
			found = true
			break
		}
	}
	if !found {
		h.Whitelist = append(h.Whitelist, req.ProcessName)
	}
	whitelistCopy := append([]string{}, h.Whitelist...)
	h.Mu.Unlock()

	h.broadcastWhitelist(whitelistCopy)
	if h.WhitelistUpdateFunc != nil {
		h.WhitelistUpdateFunc(whitelistCopy)
	}

	c.JSON(200, gin.H{"success": true, "message": "白名单已添加并下发"})
}

// RemoveWhitelist 移除白名单
func (h *Handler) RemoveWhitelist(c *gin.Context) {
	processName := c.Param("process_name")

	// 删除 PSQL
	if h.RemoveWhitelistFunc != nil {
		if err := h.RemoveWhitelistFunc(processName); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
	}

	// 更新内存
	h.Mu.Lock()
	newList := make([]string, 0, len(h.Whitelist))
	for _, name := range h.Whitelist {
		if name != processName {
			newList = append(newList, name)
		}
	}
	h.Whitelist = newList
	whitelistCopy := append([]string{}, newList...)
	h.Mu.Unlock()

	h.broadcastWhitelist(whitelistCopy)
	if h.WhitelistUpdateFunc != nil {
		h.WhitelistUpdateFunc(whitelistCopy)
	}
	c.JSON(200, gin.H{"success": true, "message": "白名单已移除"})
}

// broadcastWhitelist 将白名单塞入所有 Agent 的命令队列
func (h *Handler) broadcastWhitelist(whitelist []string) {
	jsonData, _ := json.Marshal(whitelist)

	h.Mu.Lock()
	defer h.Mu.Unlock()

	for agentID, agent := range h.Agents {
		agent.Commands = append(agent.Commands, &pb.ProbeCommand{
			Type:        pb.ProbeCommand_UNLOAD,
			ProbeName:   "whitelist",
			ProbeConfig: string(jsonData),
		})
		log.Printf("📤 白名单已塞入 Agent %s 队列: %v", agentID, whitelist)
	}
}

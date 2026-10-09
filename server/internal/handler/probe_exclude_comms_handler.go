package handler

import (
	"log"

	"github.com/gin-gonic/gin"
)

// ProbeExcludeCommsItem 探针排除名单条目
type ProbeExcludeCommsItem struct {
	Comm   string `json:"comm"`
	Reason string `json:"reason"`
}

// ListProbeExcludeComms 查询探针排除名单
func (h *Handler) ListProbeExcludeComms(c *gin.Context) {
	// 优先查 PSQL
	if h.ListProbeExcludeCommsFunc != nil {
		list, err := h.ListProbeExcludeCommsFunc()
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		h.ProbeExcludeComms = list
		c.JSON(200, gin.H{"comms": list})
		return
	}
	c.JSON(200, gin.H{"comms": h.ProbeExcludeComms})
}

// AddProbeExcludeComms 添加探针排除名单
func (h *Handler) AddProbeExcludeComms(c *gin.Context) {
	var req ProbeExcludeCommsItem
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请求格式错误"})
		return
	}
	if req.Comm == "" {
		c.JSON(400, gin.H{"error": "进程 comm 不能为空"})
		return
	}

	// 写入 PSQL
	if h.AddProbeExcludeCommsFunc != nil {
		if err := h.AddProbeExcludeCommsFunc(req.Comm, req.Reason); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
	}

	// 更新内存
	h.Mu.Lock()
	found := false
	for _, name := range h.ProbeExcludeComms {
		if name == req.Comm {
			found = true
			break
		}
	}
	if !found {
		h.ProbeExcludeComms = append(h.ProbeExcludeComms, req.Comm)
	}
	commsCopy := append([]string{}, h.ProbeExcludeComms...)
	h.Mu.Unlock()

	if h.RebuildRulesFunc != nil {
		if err := h.RebuildRulesFunc(); err != nil {
			log.Printf("⚠️ 重建规则失败: %v", err)
			c.JSON(500, gin.H{"error": "规则重建失败: " + err.Error()})
			return
		}
	}
	if h.ProbeExcludeCommsUpdateFunc != nil {
		h.ProbeExcludeCommsUpdateFunc(commsCopy)
	}

	c.JSON(200, gin.H{"success": true, "message": "排除名单已添加并下发"})
}

// RemoveProbeExcludeComms 移除探针排除名单
func (h *Handler) RemoveProbeExcludeComms(c *gin.Context) {
	comm := c.Param("comm")

	// 删除 PSQL
	if h.RemoveProbeExcludeCommsFunc != nil {
		if err := h.RemoveProbeExcludeCommsFunc(comm); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
	}

	// 更新内存
	h.Mu.Lock()
	newList := make([]string, 0, len(h.ProbeExcludeComms))
	for _, name := range h.ProbeExcludeComms {
		if name != comm {
			newList = append(newList, name)
		}
	}
	h.ProbeExcludeComms = newList
	commsCopy := append([]string{}, newList...)
	h.Mu.Unlock()

	if h.RebuildRulesFunc != nil {
		if err := h.RebuildRulesFunc(); err != nil {
			log.Printf("⚠️ 重建规则失败: %v", err)
			c.JSON(500, gin.H{"error": "规则重建失败: " + err.Error()})
			return
		}
	}
	if h.ProbeExcludeCommsUpdateFunc != nil {
		h.ProbeExcludeCommsUpdateFunc(commsCopy)
	}
	c.JSON(200, gin.H{"success": true, "message": "排除名单已移除"})
}

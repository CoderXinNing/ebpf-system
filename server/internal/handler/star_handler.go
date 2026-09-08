package handler

import (
	"github.com/gin-gonic/gin"
)

// GetStarChain 按 correlation_id 查询攻击链
func (h *Handler) GetStarChain(c *gin.Context) {
	corrID := c.Param("correlation_id")
	if corrID == "" {
		c.JSON(400, gin.H{"error": "缺少 correlation_id"})
		return
	}

	// 优先查 PSQL
	if h.ListStarEventsFunc != nil {
		events, err := h.ListStarEventsFunc(corrID)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		if len(events) == 0 {
			c.JSON(404, gin.H{"error": "未找到关联事件"})
			return
		}
		c.JSON(200, gin.H{
			"correlation_id": corrID,
			"global_id":      "",
			"total":          len(events),
			"events":         events,
		})
		return
	}

	// 内存查询（SQLite 模式或 PSQL 未注入）
	h.EventMu.RLock()
	defer h.EventMu.RUnlock()

	events := make([]ProbeEvent, 0)
	for _, evt := range h.Events {
		if evt.CorrelationID == corrID {
			events = append(events, evt)
		}
	}

	if len(events) == 0 {
		c.JSON(404, gin.H{"error": "未找到关联事件"})
		return
	}

	c.JSON(200, gin.H{
		"correlation_id": corrID,
		"total":          len(events),
		"events":         events,
	})
}

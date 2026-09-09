package handler

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/gin-gonic/gin"
)

// ChainNode 攻击链节点（树状结构）
type ChainNode struct {
	ID        string       `json:"id"`
	EventType string       `json:"event_type"`
	PID       int32        `json:"pid"`
	Comm      string       `json:"comm"`
	Filename  string       `json:"filename"`
	Details   string       `json:"details"`
	Timestamp int64        `json:"timestamp"`
	Children  []*ChainNode `json:"children,omitempty"`
	Count     int          `json:"count,omitempty"`
}

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

		tree := buildChainTree(events)
		c.JSON(200, gin.H{
			"correlation_id": corrID,
			"total":          len(events),
			"tree":           tree,
		})
		return
	}

	// 内存查询
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

// buildChainTree 构建攻击链树状结构
func buildChainTree(events []map[string]interface{}) []*ChainNode {
	// 按时间排序
	sort.Slice(events, func(i, j int) bool {
		return getInt64(events[i]["timestamp"]) < getInt64(events[j]["timestamp"])
	})

	// 按 PID 分组
	pidGroups := make(map[int32][]*ChainNode)
	for _, evt := range events {
		pid := int32(getInt64(evt["pid"]))
		if pid == 0 {
			continue
		}
		node := &ChainNode{
			ID:        fmt.Sprintf("%v", evt["id"]),
			EventType: fmt.Sprintf("%v", evt["event_type"]),
			PID:       pid,
			Comm:      fmt.Sprintf("%v", evt["comm"]),
			Filename:  fmt.Sprintf("%v", evt["filename"]),
			Details:   fmt.Sprintf("%v", evt["details"]),
			Timestamp: getInt64(evt["timestamp"]),
			Count:     1,
		}
		pidGroups[pid] = append(pidGroups[pid], node)
	}

	// 聚合重复事件
	result := make([]*ChainNode, 0)
	for _, nodes := range pidGroups {
		typeGroups := make(map[string]*ChainNode)
		for _, node := range nodes {
			key := node.EventType + ":" + node.Filename
			if existing, ok := typeGroups[key]; ok {
				existing.Count++
			} else {
				typeGroups[key] = node
			}
		}

		for _, node := range typeGroups {
			result = append(result, node)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Timestamp < result[j].Timestamp
	})

	return result
}

func getInt64(v interface{}) int64 {
	switch val := v.(type) {
	case int64:
		return val
	case float64:
		return int64(val)
	case int:
		return int64(val)
	case int32:
		return int64(val)
	case uint32:
		return int64(val)
	case json.Number:
		i, _ := val.Int64()
		return i
	}
	return 0
}

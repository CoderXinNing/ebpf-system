package handler

import (
	"log"

	"github.com/gin-gonic/gin"
)

// FileAccessExcludeItem file_access 独立 comm 排除条目
type FileAccessExcludeItem struct {
	Comm   string `json:"comm"`
	Reason string `json:"reason"`
}

// ExcludeIPItem tcp 独立 IP 排除条目（支持单 IP 或 CIDR）
type ExcludeIPItem struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
}

// ============================================
// file_access 独立 comm 排除（三维度 #11）
// 见 EDR-CORRELATION-v3.1【五】+ PROJECT-STATUS #11
// ============================================

// ListFileAccessExcludeComms 查询 file_access 独立 comm 排除
func (h *Handler) ListFileAccessExcludeComms(c *gin.Context) {
	if h.ListFileAccessExcludeCommsFunc == nil {
		c.JSON(500, gin.H{"error": "未配置"})
		return
	}
	list, err := h.ListFileAccessExcludeCommsFunc()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"comms": list})
}

// AddFileAccessExcludeComms 添加 file_access 独立 comm
func (h *Handler) AddFileAccessExcludeComms(c *gin.Context) {
	var req FileAccessExcludeItem
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请求格式错误"})
		return
	}
	if req.Comm == "" {
		c.JSON(400, gin.H{"error": "进程 comm 不能为空"})
		return
	}
	if h.AddFileAccessExcludeCommsFunc != nil {
		if err := h.AddFileAccessExcludeCommsFunc(req.Comm, req.Reason); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
	}
	if h.RebuildRulesFunc != nil {
		if err := h.RebuildRulesFunc(); err != nil {
			log.Printf("⚠️ 重建规则失败: %v", err)
			c.JSON(500, gin.H{"error": "规则重建失败: " + err.Error()})
			return
		}
	}
	c.JSON(200, gin.H{"success": true, "message": "file_access 排除已添加并下发"})
}

// RemoveFileAccessExcludeComms 移除 file_access 独立 comm
func (h *Handler) RemoveFileAccessExcludeComms(c *gin.Context) {
	comm := c.Param("comm")
	if h.RemoveFileAccessExcludeCommsFunc != nil {
		if err := h.RemoveFileAccessExcludeCommsFunc(comm); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
	}
	if h.RebuildRulesFunc != nil {
		if err := h.RebuildRulesFunc(); err != nil {
			log.Printf("⚠️ 重建规则失败: %v", err)
			c.JSON(500, gin.H{"error": "规则重建失败: " + err.Error()})
			return
		}
	}
	c.JSON(200, gin.H{"success": true, "message": "file_access 排除已移除"})
}

// ============================================
// tcp 独立 IP 排除（三维度 #12）
// 见 EDR-CORRELATION-v3.1【五】+ PROJECT-STATUS #11/#12
// ============================================

// ListExcludeIPs 查询 tcp 独立 IP 排除
func (h *Handler) ListExcludeIPs(c *gin.Context) {
	if h.ListExcludeIPsFunc == nil {
		c.JSON(500, gin.H{"error": "未配置"})
		return
	}
	list, err := h.ListExcludeIPsFunc()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ips": list})
}

// AddExcludeIP 添加 tcp 独立 IP（支持 CIDR）
func (h *Handler) AddExcludeIP(c *gin.Context) {
	var req ExcludeIPItem
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请求格式错误"})
		return
	}
	if req.IP == "" {
		c.JSON(400, gin.H{"error": "IP 不能为空"})
		return
	}
	if h.AddExcludeIPFunc != nil {
		if err := h.AddExcludeIPFunc(req.IP, req.Reason); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
	}
	if h.RebuildRulesFunc != nil {
		if err := h.RebuildRulesFunc(); err != nil {
			log.Printf("⚠️ 重建规则失败: %v", err)
			c.JSON(500, gin.H{"error": "规则重建失败: " + err.Error()})
			return
		}
	}
	c.JSON(200, gin.H{"success": true, "message": "tcp IP 排除已添加并下发"})
}

// RemoveExcludeIP 移除 tcp 独立 IP
//
// 用 query 参数 ?ip=10.0.0.0/8，避免 CIDR 里的 "/" 破路由。
func (h *Handler) RemoveExcludeIP(c *gin.Context) {
	ip := c.Query("ip")
	if ip == "" {
		c.JSON(400, gin.H{"error": "缺少 ip 参数"})
		return
	}
	if h.RemoveExcludeIPFunc != nil {
		if err := h.RemoveExcludeIPFunc(ip); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
	}
	if h.RebuildRulesFunc != nil {
		if err := h.RebuildRulesFunc(); err != nil {
			log.Printf("⚠️ 重建规则失败: %v", err)
			c.JSON(500, gin.H{"error": "规则重建失败: " + err.Error()})
			return
		}
	}
	c.JSON(200, gin.H{"success": true, "message": "tcp IP 排除已移除"})
}

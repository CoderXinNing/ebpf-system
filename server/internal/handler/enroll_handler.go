package handler

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// EnrollRequest enrollment 请求参数
type EnrollRequest struct {
	Token        string
	AgentID      string
	Hostname     string
	IPAddr       string
	MachineID    string
	MAC          string
	PublicKeyDER []byte
}

// EnrollResult enrollment 结果
type EnrollResult struct {
	AgentID   string
	GroupID   *int64
	GroupName string
}

// Enroll Agent 注册（免认证）
func (h *Handler) Enroll(c *gin.Context) {
	var req struct {
		Token     string `json:"token"`
		AgentID   string `json:"agent_id"`
		Hostname  string `json:"hostname"`
		IP        string `json:"ip"`
		MachineID string `json:"machine_id"`
		MAC       string `json:"mac"`
		CSR       string `json:"csr"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}

	if req.Token == "" || req.AgentID == "" || req.CSR == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token/agent_id/csr 不能为空"})
		return
	}

	// 1. 解析 CSR 提取公钥 DER
	block, _ := pem.Decode([]byte(req.CSR))
	if block == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "CSR PEM 解析失败"})
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "CSR 解析失败: " + err.Error()})
		return
	}
	if err := csr.CheckSignature(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "CSR 签名验证失败"})
		return
	}
	pubKeyDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "公钥序列化失败"})
		return
	}

	// 2. 校验 agent_id 与公钥一致
	if h.ComputeAgentIDFunc != nil {
		computedID := h.ComputeAgentIDFunc(pubKeyDER)
		if computedID != req.AgentID {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("agent_id 与公钥不匹配（期望 %s，计算得 %s）", req.AgentID, computedID),
			})
			return
		}
	}

	// 3. CA 签证书
	if h.SignCSRFunc == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "CA 未初始化"})
		return
	}
	agentCRT, serial, expiresAt, err := h.SignCSRFunc([]byte(req.CSR), req.AgentID, 8760)
	if err != nil {
		log.Printf("❌ 签发证书失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "签发证书失败: " + err.Error()})
		return
	}

	// 4. 事务化注册
	if h.EnrollAgentFunc == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "enrollment 未初始化"})
		return
	}
	result, err := h.EnrollAgentFunc(EnrollRequest{
		Token:        req.Token,
		AgentID:      req.AgentID,
		Hostname:     req.Hostname,
		IPAddr:       req.IP,
		MachineID:    req.MachineID,
		MAC:          req.MAC,
		PublicKeyDER: pubKeyDER,
	})
	if err != nil {
		log.Printf("⚠️ Enroll 失败: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// 5. 更新证书序列号（可选）
	if h.UpdateAgentCertFunc != nil {
		h.UpdateAgentCertFunc(req.AgentID, serial, expiresAt)
	}

	log.Printf("✅ Agent 注册成功: %s (%s) 分组=%s", result.AgentID, req.Hostname, result.GroupName)

	// 6. 返回
	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"agent_id":     result.AgentID,
		"agent_crt":    string(agentCRT),
		"ca_crt":       string(h.CACertPEM),
		"cert_serial":  serial,
		"cert_expires": expiresAt.Format("2006-01-02T15:04:05Z07:00"),
		"group_name":   result.GroupName,
	})
}

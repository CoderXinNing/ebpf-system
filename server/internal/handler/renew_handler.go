package handler

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"
)

// RenewCertResult 续期结果
type RenewCertResult struct {
	CertPEM   []byte
	Serial    string
	ExpiresAt time.Time
}

// RenewCertHandler 续期逻辑
//
// 关键校验：
//   1. CSR 公钥 hash == DB 中注册的公钥 hash（确保复用旧密钥）
//   2. agent_id 一致
//   3. 用 CA 签新证书
//   4. 更新 DB 的 cert_serial + cert_expires_at
func (h *Handler) RenewCertHandler(agentID string, csrPEM []byte) (*RenewCertResult, error) {
	// 1. 解析 CSR
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("CSR PEM 解析失败")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CSR 解析失败: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR 签名验证失败: %w", err)
	}

	// 2. 计算新 CSR 的公钥 hash
	newPubKeyDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("公钥序列化失败: %w", err)
	}
	newHash := sha256.Sum256(newPubKeyDER)

	// 3. 从 DB 取注册时的公钥 hash
	if h.GetAgentPublicKeyHashFunc == nil {
		return nil, fmt.Errorf("公钥查询未初始化")
	}
	dbHash, err := h.GetAgentPublicKeyHashFunc(agentID)
	if err != nil {
		return nil, fmt.Errorf("查询公钥失败: %w", err)
	}
	if dbHash == nil {
		return nil, fmt.Errorf("Agent 未注册或公钥缺失")
	}

	// 4. 对比（复用旧密钥的约束）
	if len(dbHash) != len(newHash) {
		return nil, fmt.Errorf("公钥 hash 长度不一致")
	}
	for i := range newHash {
		if newHash[i] != dbHash[i] {
			return nil, fmt.Errorf("公钥 hash 不匹配：续期必须复用旧密钥")
		}
	}

	// 5. CA 签新证书
	if h.SignCSRFunc == nil {
		return nil, fmt.Errorf("CA 未初始化")
	}
	newCertPEM, serial, expiresAt, err := h.SignCSRFunc(csrPEM, agentID, 0) // 0 = 用配置默认
	if err != nil {
		return nil, fmt.Errorf("签发证书失败: %w", err)
	}

	// 6. 更新 DB
	if h.UpdateAgentCertFunc != nil {
		if err := h.UpdateAgentCertFunc(agentID, serial, expiresAt); err != nil {
			log.Printf("⚠️ 更新 Agent 证书元信息失败: %v", err)
			// 不阻塞
		}
	}

	log.Printf("🔄 Agent 证书已续期: %s (serial=%s, expires=%s)",
		agentID, serial, expiresAt.Format("2006-01-02"))

	return &RenewCertResult{
		CertPEM:   newCertPEM,
		Serial:    serial,
		ExpiresAt: expiresAt,
	}, nil
}

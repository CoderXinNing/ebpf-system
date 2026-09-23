package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"
	"time"
)

// CA 证书签发机构
type CA struct {
	cert    *x509.Certificate
	key     *rsa.PrivateKey
	certPEM []byte
}

// Load 加载 CA 证书和私钥
func Load(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("读取 CA 证书失败: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("CA 证书 PEM 解析失败")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CA 证书解析失败: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("读取 CA 私钥失败: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("CA 私钥 PEM 解析失败")
	}

	// 尝试 PKCS1 和 PKCS8
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
		key = k
	} else if k, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
		if rsaKey, ok := k.(*rsa.PrivateKey); ok {
			key = rsaKey
		} else {
			return nil, fmt.Errorf("CA 私钥不是 RSA 类型")
		}
	} else {
		return nil, fmt.Errorf("CA 私钥解析失败: %w", err)
	}

	return &CA{
		cert:    cert,
		key:     key,
		certPEM: certPEM,
	}, nil
}

// CertPEM 返回 CA 证书 PEM
func (c *CA) CertPEM() []byte {
	return c.certPEM
}

// ComputeAgentID 从公钥 DER 计算 agent_id
//
// 冻结规则：
//   agent_id = "agent-" + Base32NoPadding(SHA256(public_key_der)[0:16])
func ComputeAgentID(publicKeyDER []byte) string {
	hash := sha256.Sum256(publicKeyDER)
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).
		EncodeToString(hash[:16])
	return "agent-" + strings.ToLower(encoded)
}

// SignCSR 签发 Agent 证书
//
// 输入：
//   csrPEM      - Agent 的 CSR（PEM 格式）
//   agentID     - 从公钥计算的 agent_id
//   ttl         - 证书有效期
//
// 输出：
//   agent.crt 的 PEM
//   证书序列号
//   过期时间
func (c *CA) SignCSR(csrPEM []byte, agentID string, ttl time.Duration) ([]byte, string, time.Time, error) {
	// 1. 解析 CSR
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, "", time.Time{}, fmt.Errorf("CSR PEM 解析失败")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("CSR 解析失败: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, "", time.Time{}, fmt.Errorf("CSR 签名验证失败: %w", err)
	}

	// 2. 从 CSR 中的公钥计算 agent_id，校验与请求体一致
	pubKeyDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("公钥序列化失败: %w", err)
	}
	computedID := ComputeAgentID(pubKeyDER)
	if computedID != agentID {
		return nil, "", time.Time{}, fmt.Errorf("agent_id 与公钥不匹配（期望 %s，计算得 %s）", agentID, computedID)
	}

	// 3. 生成证书序列号
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("生成序列号失败: %w", err)
	}

	// 4. 构造 SAN URI
	sanURI, err := url.Parse("spiffe://astertrack/agent/" + agentID)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("构造 SAN URI 失败: %w", err)
	}

	// 5. 构造证书模板
	notBefore := time.Now().Add(-1 * time.Minute)
	notAfter := time.Now().Add(ttl)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "AsterTrack Agent",
			Organization: []string{"AsterTrack"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:                  []*url.URL{sanURI},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// 6. 用 CA 签发
	derBytes, err := x509.CreateCertificate(rand.Reader, template, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("签发证书失败: %w", err)
	}

	// 7. PEM 编码
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	serialHex := fmt.Sprintf("%x", serialNumber)

	return certPEM, serialHex, notAfter, nil
}

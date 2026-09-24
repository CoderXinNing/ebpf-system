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

// CA 证书签发机构。
//
// 语义（重要，改这个结构体前先读 server/internal/ca/README.md）：
//   - signCert/signKey：当前用于签发 Server/Agent 证书的唯一密钥对。
//     signCert 必须是 trustCerts 的【最后一个】——CA 轮换时，新 CA 追加到
//     ca.crt 末尾，旧 CA 保留在头部用于验证。
//   - trustCerts：所有信任的 CA 证书（用于验证对端），可能 > 1 个。
//     当前只有 1 个证书时，trustCerts[0] == signCert。
//   - certPEM：ca.crt 原始 Bundle PEM（可能是多证书拼接），直接传给下游。
type CA struct {
	signCert   *x509.Certificate
	signKey    *rsa.PrivateKey
	trustCerts []*x509.Certificate
	certPEM    []byte
}

// Load 加载 CA 证书 Bundle 和私钥。
//
// Bundle 语义（详见 README.md）：
//   - ca.crt 允许包含多个 CERTIFICATE block（CA 轮换用）
//   - 最后一个 block 作为 signCert（签名用）
//   - 全部 block 作为 trustCerts（验证用）
//   - 禁止混入 PRIVATE KEY，遇到立即报错
//   - 未知 block 类型跳过并打 WARN
//
// 当前只有 1 个证书时，行为与旧版一致：trustCerts == [signCert]。
func Load(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("读取 CA 证书失败: %w", err)
	}

	trustCerts, err := parseCABundle(certPEM)
	if err != nil {
		return nil, fmt.Errorf("解析 CA Bundle 失败: %w", err)
	}
	if len(trustCerts) == 0 {
		return nil, fmt.Errorf("CA Bundle 中未找到任何 CERTIFICATE")
	}
	signCert := trustCerts[len(trustCerts)-1]

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
		signCert:   signCert,
		signKey:    key,
		trustCerts: trustCerts,
		certPEM:    certPEM,
	}, nil
}

// parseCABundle 解析 CA Bundle PEM，返回所有 CERTIFICATE。
//
// 防御性校验：
//   - 遇到 PRIVATE KEY block → 立即报错（防止运维手抖把 ca.key 混入 ca.crt）
//   - 未知 block 类型 → 跳过 + WARN
//   - 空/非法 block → 跳过
func parseCABundle(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining

		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("解析证书失败: %w", err)
			}
			certs = append(certs, cert)

		case "RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY":
			return nil, fmt.Errorf(
				"CA Bundle 中混入私钥（block type=%q），拒绝加载。"+
					"请检查 ca.crt 是否误拼接了 ca.key", block.Type)

		default:
			fmt.Printf("⚠️ CA Bundle 跳过未知 block 类型: %s\n", block.Type)
		}
	}
	return certs, nil
}

// CertPEM 返回 CA 证书 PEM
func (c *CA) CertPEM() []byte {
	return c.certPEM
}

// ComputeAgentID 从公钥 DER 计算 agent_id
//
// 冻结规则：
//
//	agent_id = "agent-" + Base32NoPadding(SHA256(public_key_der)[0:16])
func ComputeAgentID(publicKeyDER []byte) string {
	hash := sha256.Sum256(publicKeyDER)
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).
		EncodeToString(hash[:16])
	return "agent-" + strings.ToLower(encoded)
}

// SignCSR 签发 Agent 证书
//
// 输入：
//
//	csrPEM      - Agent 的 CSR（PEM 格式）
//	agentID     - 从公钥计算的 agent_id
//	ttl         - 证书有效期
//
// 输出：
//
//	agent.crt 的 PEM
//	证书序列号
//	过期时间
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
	derBytes, err := x509.CreateCertificate(rand.Reader, template, c.signCert, csr.PublicKey, c.signKey)
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

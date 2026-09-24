package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// DefaultCACommonName 新的 CA 品牌名（与旧 ebpf-sentinel-ca 区分）
const DefaultCACommonName = "AsterTrack CA"

// CAOptions CA 生成参数
type CAOptions struct {
	CommonName   string
	Organization string
	ValidityDays int
}

// GenerateCA 生成自签 CA。
//
// 规则：
//   - RSA 4096
//   - KeyUsage: CertSign | CRLSign | DigitalSignature
//   - IsCA = true, BasicConstraintsValid = true
//   - 默认 CN = "AsterTrack CA"，默认 10 年有效期
func GenerateCA(opts CAOptions) (*CA, error) {
	if opts.CommonName == "" {
		opts.CommonName = DefaultCACommonName
	}
	if opts.Organization == "" {
		opts.Organization = "AsterTrack"
	}
	if opts.ValidityDays <= 0 {
		opts.ValidityDays = 3650 // 10 年
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("生成 CA 密钥失败: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("生成 CA 序列号失败: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: []string{opts.Organization},
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.AddDate(0, 0, opts.ValidityDays),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("生成 CA 证书失败: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("解析生成的 CA 证书失败: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	return &CA{
		cert:    cert,
		key:     key,
		certPEM: certPEM,
	}, nil
}

// ServerCertOptions Server 证书生成参数
type ServerCertOptions struct {
	CommonName   string
	Organization string
	DNSNames     []string
	IPAddresses  []string
	ValidityDays int
}

// ServerCertResult 生成结果
type ServerCertResult struct {
	CertPEM []byte
	KeyPEM  []byte
	Serial  string
	Expires time.Time
}

// GenerateServerCert 用 CA 签发 Server 证书。
//
// 规则：
//   - RSA 2048
//   - ExtKeyUsage: ServerAuth | ClientAuth（mTLS 双向）
//   - SAN 含 DNSNames + IPAddresses
//   - 默认 365 天
func (c *CA) GenerateServerCert(opts ServerCertOptions) (*ServerCertResult, error) {
	if opts.CommonName == "" {
		opts.CommonName = "localhost"
	}
	if opts.Organization == "" {
		opts.Organization = "AsterTrack"
	}
	if opts.ValidityDays <= 0 {
		opts.ValidityDays = 365
	}
	if len(opts.DNSNames) == 0 {
		opts.DNSNames = []string{"localhost", "*.localhost"}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("生成 Server 密钥失败: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("生成 Server 序列号失败: %w", err)
	}

	ips := make([]net.IP, 0, len(opts.IPAddresses))
	for _, s := range opts.IPAddresses {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: []string{opts.Organization},
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.AddDate(0, 0, opts.ValidityDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              opts.DNSNames,
		IPAddresses:           ips,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("签发 Server 证书失败: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return &ServerCertResult{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		Serial:  fmt.Sprintf("%x", serial),
		Expires: template.NotAfter,
	}, nil
}

// WritePEM 把 PEM 数据写入文件，自动建目录 + 权限控制。
// 私钥文件权限 600，证书 644。
func WritePEM(path string, data []byte, isPrivate bool) error {
	perm := os.FileMode(0644)
	if isPrivate {
		perm = 0600
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}
	return os.WriteFile(path, data, perm)
}

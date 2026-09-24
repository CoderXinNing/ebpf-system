package ca

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// BootstrapOptions 证书初始化参数
type BootstrapOptions struct {
	Dir                string   // 证书目录，默认 "certs"
	ServerCommonName   string   // Server 证书 CN，默认 "localhost"
	ServerDNSNames     []string // SAN DNS，默认 ["localhost", "*.localhost"]
	ServerIPAddresses  []string // SAN IP，默认 ["127.0.0.1", "::1"]
	CAValidityDays     int      // 默认 3650
	ServerValidityDays int      // 默认 365
}

// BootstrapResult 初始化结果
type BootstrapResult struct {
	Generated   bool // true = 新生成；false = 复用现有
	CADir       string
	CACertPath  string
	CAKeyPath   string
	SrvCertPath string
	SrvKeyPath  string
}

// 四个必需文件
var requiredFiles = []string{"ca.crt", "ca.key", "server.crt", "server.key"}

// Bootstrap 检查证书目录，决定生成或复用。
//
// 策略：
//   - 四文件齐全 → 复用（校验 CA 品牌，旧品牌则报错退出）
//   - 任一缺失   → 全部重生成（避免半套证书）
//
// 返回：
//
//	generated = true  新生成
//	generated = false 复用
//	err != nil        失败（含旧品牌检测失败）
func Bootstrap(opts BootstrapOptions) (*BootstrapResult, error) {
	if opts.Dir == "" {
		opts.Dir = "certs"
	}
	if opts.CAValidityDays <= 0 {
		opts.CAValidityDays = 3650
	}
	if opts.ServerValidityDays <= 0 {
		opts.ServerValidityDays = 365
	}

	result := &BootstrapResult{
		CADir:       opts.Dir,
		CACertPath:  filepath.Join(opts.Dir, "ca.crt"),
		CAKeyPath:   filepath.Join(opts.Dir, "ca.key"),
		SrvCertPath: filepath.Join(opts.Dir, "server.crt"),
		SrvKeyPath:  filepath.Join(opts.Dir, "server.key"),
	}

	// 1. 检查四文件是否齐全
	allExist := true
	missing := []string{}
	for _, f := range requiredFiles {
		p := filepath.Join(opts.Dir, f)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			allExist = false
			missing = append(missing, f)
		}
	}

	// 2. 齐全 → 复用（校验品牌）
	if allExist {
		if err := verifyCABranding(result.CACertPath); err != nil {
			return nil, fmt.Errorf("复用现有 CA 失败: %w", err)
		}
		log.Printf("🔐 复用现有证书: %s", opts.Dir)
		result.Generated = false
		return result, nil
	}

	// 3. 缺失 → 全部重生成
	if len(missing) > 0 {
		log.Printf("🔐 证书不完整（缺 %v），将重新生成全套", missing)
		// 清理旧文件（避免半套残留）
		for _, f := range requiredFiles {
			p := filepath.Join(opts.Dir, f)
			_ = os.Remove(p)
		}
	}

	// 4. 生成 CA
	caObj, err := GenerateCA(CAOptions{
		CommonName:   DefaultCACommonName,
		Organization: "AsterTrack",
		ValidityDays: opts.CAValidityDays,
	})
	if err != nil {
		return nil, fmt.Errorf("生成 CA 失败: %w", err)
	}
	if err := WritePEM(result.CACertPath, caObj.CertPEM(), false); err != nil {
		return nil, fmt.Errorf("写入 CA 证书失败: %w", err)
	}
	caKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caObj.signKey),
	})
	if err := WritePEM(result.CAKeyPath, caKeyPEM, true); err != nil {
		return nil, fmt.Errorf("写入 CA 私钥失败: %w", err)
	}

	// 5. 生成 Server 证书
	serverResult, err := caObj.GenerateServerCert(ServerCertOptions{
		CommonName:   opts.ServerCommonName,
		Organization: "AsterTrack",
		DNSNames:     opts.ServerDNSNames,
		IPAddresses:  opts.ServerIPAddresses,
		ValidityDays: opts.ServerValidityDays,
	})
	if err != nil {
		return nil, fmt.Errorf("生成 Server 证书失败: %w", err)
	}
	if err := WritePEM(result.SrvCertPath, serverResult.CertPEM, false); err != nil {
		return nil, fmt.Errorf("写入 Server 证书失败: %w", err)
	}
	if err := WritePEM(result.SrvKeyPath, serverResult.KeyPEM, true); err != nil {
		return nil, fmt.Errorf("写入 Server 私钥失败: %w", err)
	}

	log.Printf("🔐 新 CA 已生成: CN=%s 有效期=%d天", DefaultCACommonName, opts.CAValidityDays)
	log.Printf("🔐 新 Server 证书已生成: CN=%s SAN_DNS=%v SAN_IP=%v",
		opts.ServerCommonName, opts.ServerDNSNames, opts.ServerIPAddresses)

	result.Generated = true
	return result, nil
}

// verifyCABranding 校验 CA 品牌是否为 AsterTrack。
// 旧品牌（ebpf-sentinel-ca 等）会被拒绝，强制人工处理。
func verifyCABranding(caCertPath string) error {
	data, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("读取 CA 证书失败: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("CA 证书 PEM 解析失败")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("CA 证书解析失败: %w", err)
	}

	// 允许两种 CN：具体名字（AsterTrack CA）
	cn := cert.Subject.CommonName
	if cn == DefaultCACommonName {
		return nil
	}

	return fmt.Errorf(
		"检测到旧品牌 CA（CN=%q），当前要求 CN=%q。\n"+
			"  请执行：rm -rf %s && 重启 Server（将自动生成新 CA + Server 证书）\n"+
			"  注意：重启后所有 Agent 需重新 enrollment",
		cn, DefaultCACommonName,
		filepath.Dir(caCertPath),
	)
}

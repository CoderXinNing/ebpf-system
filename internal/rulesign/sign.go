// Package rulesign 规则签名/验签（Server 签，Agent 验）。
//
// 复用现有 mTLS CA：
//   - Server 用 certs/ca.key 签
//   - Agent  用 certs/ca.crt 验
//
// 算法：RSA + SHA256 (PKCS1v15)
package rulesign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// Sign 用 PEM 格式的 RSA 私钥对 data 签名（RSA-SHA256-PKCS1v15）。
// 返回 base64 编码的签名。
func Sign(privKeyPEM, data []byte) (string, error) {
	block, _ := pem.Decode(privKeyPEM)
	if block == nil {
		return "", fmt.Errorf("私钥 PEM 解析失败")
	}

	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = k
	} else if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("私钥不是 RSA 类型")
		}
		key = rk
	} else {
		return "", fmt.Errorf("私钥解析失败: %w", err)
	}

	hash := sha256.Sum256(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("签名失败: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}

// Verify 用 PEM 格式的证书验签。
func Verify(certPEM, data []byte, sigB64 string) error {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("证书 PEM 解析失败")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("证书解析失败: %w", err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("证书公钥不是 RSA 类型")
	}

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("签名 base64 解码失败: %w", err)
	}

	hash := sha256.Sum256(data)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sig); err != nil {
		return fmt.Errorf("验签失败: %w", err)
	}
	return nil
}

// HashSHA256 返回 data 的 SHA256 十六进制字符串（供版本比对用）
func HashSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:])
}

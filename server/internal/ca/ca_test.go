package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// makeTestCert 生成一个自签测试证书，返回 PEM。
func makeTestCert(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// makeTestKey 生成 RSA 私钥 PEM。
func makeTestKey(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

// writeTemp 写临时文件，返回路径。
func writeTemp(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatalf("写临时文件失败: %v", err)
	}
	return p
}

// TestLoadCA_SingleCert 单证书 Bundle：trustCerts 长度 1，signCert == trustCerts[0]。
func TestLoadCA_SingleCert(t *testing.T) {
	dir := t.TempDir()
	certPEM := makeTestCert(t, "Single CA")
	keyPEM := makeTestKey(t)

	certPath := writeTemp(t, dir, "ca.crt", certPEM)
	keyPath := writeTemp(t, dir, "ca.key", keyPEM)

	ca, err := Load(certPath, keyPath)
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if len(ca.trustCerts) != 1 {
		t.Fatalf("trustCerts 长度 = %d，期望 1", len(ca.trustCerts))
	}
	if ca.signCert != ca.trustCerts[0] {
		t.Fatal("单证书时 signCert 应等于 trustCerts[0]")
	}
	if ca.signCert.Subject.CommonName != "Single CA" {
		t.Fatalf("CN = %q，期望 Single CA", ca.signCert.Subject.CommonName)
	}
}

// TestLoadCA_MultipleCerts 多证书 Bundle：trustCerts 长度 2，signCert == 最后一个。
// 这是 CA 轮换的核心契约，任何重构不得破坏。
func TestLoadCA_MultipleCerts(t *testing.T) {
	dir := t.TempDir()

	oldCA := makeTestCert(t, "Old CA")
	newCA := makeTestCert(t, "New CA")

	// 拼接：旧 CA 在前，新 CA 在后（轮换惯例）
	bundle := append(append([]byte{}, oldCA...), newCA...)

	keyPEM := makeTestKey(t)
	certPath := writeTemp(t, dir, "ca.crt", bundle)
	keyPath := writeTemp(t, dir, "ca.key", keyPEM)

	ca, err := Load(certPath, keyPath)
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if len(ca.trustCerts) != 2 {
		t.Fatalf("trustCerts 长度 = %d，期望 2", len(ca.trustCerts))
	}
	if ca.trustCerts[0].Subject.CommonName != "Old CA" {
		t.Fatalf("trustCerts[0] CN = %q，期望 Old CA", ca.trustCerts[0].Subject.CommonName)
	}
	if ca.signCert.Subject.CommonName != "New CA" {
		t.Fatalf("signCert CN = %q，期望 New CA（最后一个）", ca.signCert.Subject.CommonName)
	}
	if ca.signCert != ca.trustCerts[1] {
		t.Fatal("signCert 应等于 trustCerts 的最后一个")
	}
}

// TestLoadCA_RejectPrivateKey Bundle 混入私钥必须报错。
func TestLoadCA_RejectPrivateKey(t *testing.T) {
	dir := t.TempDir()

	certPEM := makeTestCert(t, "CA")
	keyPEM := makeTestKey(t)

	// 故意把私钥拼进去
	badBundle := append(append([]byte{}, certPEM...), keyPEM...)

	certPath := writeTemp(t, dir, "ca.crt", badBundle)
	keyPath := writeTemp(t, dir, "ca.key", keyPEM)

	_, err := Load(certPath, keyPath)
	if err == nil {
		t.Fatal("混入私钥应报错，实际未报错")
	}
	// 只检查错误信息含关键词，不依赖具体格式
	if !contains(err.Error(), "私钥") {
		t.Fatalf("错误信息应提到私钥，实际: %v", err)
	}
}

// TestLoadCA_SkipUnknownBlock 未知 block 类型跳过，不影响证书解析。
func TestLoadCA_SkipUnknownBlock(t *testing.T) {
	dir := t.TempDir()

	certPEM := makeTestCert(t, "CA")
	unknown := pem.EncodeToMemory(&pem.Block{
		Type:  "SOMETHING ELSE",
		Bytes: []byte("junk"),
	})
	bundle := append(append([]byte{}, certPEM...), unknown...)

	keyPEM := makeTestKey(t)
	certPath := writeTemp(t, dir, "ca.crt", bundle)
	keyPath := writeTemp(t, dir, "ca.key", keyPEM)

	ca, err := Load(certPath, keyPath)
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if len(ca.trustCerts) != 1 {
		t.Fatalf("trustCerts 长度 = %d，期望 1（未知 block 应跳过）", len(ca.trustCerts))
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

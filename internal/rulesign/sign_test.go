package rulesign

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// makeTestKeyPair 生成自签密钥对 + 证书 PEM
func makeTestKeyPair(t *testing.T) (keyPEM, certPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return
}

func TestSignVerify(t *testing.T) {
	keyPEM, certPEM := makeTestKeyPair(t)
	data := []byte(`{"version":1,"paths":["/etc/passwd"]}`)

	sig, err := Sign(keyPEM, data)
	if err != nil {
		t.Fatalf("Sign 失败: %v", err)
	}
	if err := Verify(certPEM, data, sig); err != nil {
		t.Fatalf("Verify 失败: %v", err)
	}
}

func TestVerifyTamperedData(t *testing.T) {
	keyPEM, certPEM := makeTestKeyPair(t)
	data := []byte(`{"version":1}`)
	sig, _ := Sign(keyPEM, data)

	// 篡改数据
	tampered := []byte(`{"version":2}`)
	if err := Verify(certPEM, tampered, sig); err == nil {
		t.Fatal("篡改数据应验签失败，实际通过")
	}
}

func TestVerifyWrongCert(t *testing.T) {
	keyPEM, _ := makeTestKeyPair(t)
	_, otherCertPEM := makeTestKeyPair(t)

	data := []byte("hello")
	sig, _ := Sign(keyPEM, data)

	if err := Verify(otherCertPEM, data, sig); err == nil {
		t.Fatal("用错证书应验签失败，实际通过")
	}
}

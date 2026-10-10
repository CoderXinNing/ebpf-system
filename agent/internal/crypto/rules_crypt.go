// Package crypto 本地规则缓存加解密（Phase 3）。
//
// 设计：
//   - 密钥源：/etc/machine-id + agent.id
//     HKDF-SHA256(machine-id, salt=nil, info="astertrack-rules-v1")
//     再混入 agent.id 保证每个 Agent 独立密钥
//   - 算法：AES-GCM
//   - 文件格式：[nonce(12) | ciphertext | tag(16)]，整体 base64 或裸二进制
//     选用裸二进制，文件名 rules.enc
//   - 降级：读不到 machine-id 或 agent.id 时，加解密返回明确错误，
//     调用方降级为明文缓存（保留 rules.json），打警告日志
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const hkdfInfo = "astertrack-rules-v1"

// ErrNoMachineID machine-id 读不到
var ErrNoMachineID = errors.New("rules_crypt: machine-id 不可读")

// ErrNoAgentID agent.id 读不到
var ErrNoAgentID = errors.New("rules_crypt: agent.id 不可读")

// deriveKey 派生 32 字节 AES-256 密钥。
//
//	machine-id + agent.id 一起作为 IKM
//	HKDF-SHA256(salt=nil, info="astertrack-rules-v1")
func deriveKey(machineID, agentID string) ([]byte, error) {
	if machineID == "" {
		return nil, ErrNoMachineID
	}
	if agentID == "" {
		return nil, ErrNoAgentID
	}

	ikm := []byte(machineID + "\x00" + agentID)
	h := hkdf.New(sha256.New, ikm, nil, []byte(hkdfInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, fmt.Errorf("HKDF 派生失败: %w", err)
	}
	return key, nil
}

// readMachineID 读 /etc/machine-id，去掉换行/空白
func readMachineID() (string, error) {
	data, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrNoMachineID, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// readAgentID 读 agent.id，去掉换行/空白
func readAgentID(agentIDPath string) (string, error) {
	data, err := os.ReadFile(agentIDPath)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrNoAgentID, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// Encrypt 加密明文。返回 [nonce|ct|tag]。
func Encrypt(plaintext []byte, agentIDPath string) ([]byte, error) {
	machineID, err := readMachineID()
	if err != nil {
		return nil, err
	}
	agentID, err := readAgentID(agentIDPath)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(machineID, agentID)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce 读取失败: %w", err)
	}

	// Seal 输出：nonce 之后追加密文+tag
	out := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, out...), nil
}

// Decrypt 解密 [nonce|ct|tag]。
func Decrypt(ciphertext []byte, agentIDPath string) ([]byte, error) {
	machineID, err := readMachineID()
	if err != nil {
		return nil, err
	}
	agentID, err := readAgentID(agentIDPath)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(machineID, agentID)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM: %w", err)
	}

	ns := gcm.NonceSize()
	if len(ciphertext) < ns+1 {
		return nil, errors.New("密文过短")
	}
	nonce, ct := ciphertext[:ns], ciphertext[ns:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("GCM Open: %w", err)
	}
	return plaintext, nil
}

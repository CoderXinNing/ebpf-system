package enroll

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config enroll 配置
type Config struct {
	ServerURL string // 如 http://172.16.2.145:8080
	Token     string // 注册 Token（ATK-xxx）
	InstallDir string // 安装目录，默认 /opt/astertrack
	Hostname  string // 可选，默认自动获取
}

// Result enroll 结果
type Result struct {
	AgentID       string
	CertPath      string
	KeyPath       string
	CApath        string
	ConfigPath    string
	CertExpiresAt time.Time
}

// Run 执行 enrollment 流程
func Run(cfg Config) (*Result, error) {
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("ServerURL 不能为空")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("Token 不能为空")
	}
	if cfg.InstallDir == "" {
		cfg.InstallDir = "/opt/astertrack"
	}
	if cfg.Hostname == "" {
		cfg.Hostname, _ = os.Hostname()
	}

	log.Printf("🔧 开始 Agent enrollment...")
	log.Printf("   Server:   %s", cfg.ServerURL)
	log.Printf("   Hostname: %s", cfg.Hostname)
	log.Printf("   安装目录:  %s", cfg.InstallDir)

	// 1. 生成密钥对
	log.Println("🔑 生成密钥对...")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("生成密钥失败: %w", err)
	}

	// 2. 计算 agent_id
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("公钥序列化失败: %w", err)
	}
	hash := sha256.Sum256(pubKeyDER)
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:16])
	agentID := "agent-" + strings.ToLower(encoded)
	log.Printf("🆔 Agent ID: %s", agentID)

	// 3. 生成 CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "AsterTrack Agent",
			Organization: []string{"AsterTrack"},
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		return nil, fmt.Errorf("生成 CSR 失败: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	// 4. 收集机器信息
	machineID := readMachineID()
	mac := readFirstMAC()

	// 5. 调用 enrollment API
	log.Println("📡 调用 enrollment API...")
	resp, err := callEnroll(cfg, agentID, csrPEM, machineID, mac)
	if err != nil {
		return nil, fmt.Errorf("enrollment 失败: %w", err)
	}

	// 6. 保存证书
	certDir := filepath.Join(cfg.InstallDir, "certs")
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return nil, fmt.Errorf("创建证书目录失败: %w", err)
	}

	// 6.1 私钥（600）
	keyPath := filepath.Join(certDir, "agent.key")
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("保存私钥失败: %w", err)
	}

	// 6.2 证书（644）
	certPath := filepath.Join(certDir, "agent.crt")
	if err := os.WriteFile(certPath, []byte(resp.AgentCRT), 0644); err != nil {
		return nil, fmt.Errorf("保存证书失败: %w", err)
	}

	// 6.3 CA 证书（644）
	caPath := filepath.Join(certDir, "ca.crt")
	if err := os.WriteFile(caPath, []byte(resp.CACRT), 0644); err != nil {
		return nil, fmt.Errorf("保存 CA 失败: %w", err)
	}

	// 7. 生成 agent.toml
	configPath := filepath.Join(cfg.InstallDir, "agent.toml")
	if err := generateAgentConfig(configPath, cfg, resp); err != nil {
		return nil, fmt.Errorf("生成配置失败: %w", err)
	}

	// 8. 保存 agent_id（用于 audit）
	idPath := filepath.Join(cfg.InstallDir, "agent.id")
	os.WriteFile(idPath, []byte(agentID), 0644)

	expiresAt, _ := time.Parse(time.RFC3339, resp.CertExpires)

	log.Println("✅ Enrollment 完成")
	log.Printf("   证书:      %s", certPath)
	log.Printf("   私钥:      %s", keyPath)
	log.Printf("   CA:        %s", caPath)
	log.Printf("   配置:      %s", configPath)
	log.Printf("   过期时间:  %s", resp.CertExpires)

	return &Result{
		AgentID:       agentID,
		CertPath:      certPath,
		KeyPath:       keyPath,
		CApath:        caPath,
		ConfigPath:    configPath,
		CertExpiresAt: expiresAt,
	}, nil
}

// enrollResponse Server 返回
type enrollResponse struct {
	Success      bool   `json:"success"`
	AgentID      string `json:"agent_id"`
	AgentCRT     string `json:"agent_crt"`
	CACRT        string `json:"ca_crt"`
	CertSerial   string `json:"cert_serial"`
	CertExpires  string `json:"cert_expires"`
	GroupName    string `json:"group_name"`
	Error        string `json:"error"`
}

// callEnroll 调用 enrollment API
func callEnroll(cfg Config, agentID string, csrPEM []byte, machineID, mac string) (*enrollResponse, error) {
	reqBody := map[string]string{
		"token":      cfg.Token,
		"agent_id":   agentID,
		"hostname":   cfg.Hostname,
		"ip":         "",
		"machine_id": machineID,
		"mac":        mac,
		"csr":        string(csrPEM),
	}
	jsonData, _ := json.Marshal(reqBody)

	url := strings.TrimRight(cfg.ServerURL, "/") + "/api/agent/enroll"
	client := &http.Client{Timeout: 15 * time.Second}

	httpResp, err := client.Post(url, "application/json", bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("HTTP 请求失败: %w", err)
	}
	defer httpResp.Body.Close()

	body, _ := io.ReadAll(httpResp.Body)

	var resp enrollResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("响应解析失败: %w, body=%s", err, string(body))
	}

	if httpResp.StatusCode != 200 {
		if resp.Error != "" {
			return nil, fmt.Errorf("%s", resp.Error)
		}
		return nil, fmt.Errorf("HTTP %d: %s", httpResp.StatusCode, string(body))
	}
	if !resp.Success {
		return nil, fmt.Errorf("Server 拒绝: %s", resp.Error)
	}

	return &resp, nil
}

// readMachineID 读 /etc/machine-id
func readMachineID() string {
	data, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// readFirstMAC 读第一个物理网卡 MAC
func readFirstMAC() string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" {
			continue
		}
		addr, err := os.ReadFile(filepath.Join("/sys/class/net", name, "address"))
		if err != nil {
			continue
		}
		mac := strings.TrimSpace(string(addr))
		if mac != "" && mac != "00:00:00:00:00:00" {
			return mac
		}
	}
	return ""
}

// generateAgentConfig 生成 agent.toml
func generateAgentConfig(path string, cfg Config, resp *enrollResponse) error {
	// 从 ServerURL 提取 gRPC 地址
	// http://172.16.2.145:8080 → 172.16.2.145:50051
	grpcAddr := strings.TrimPrefix(cfg.ServerURL, "http://")
	grpcAddr = strings.TrimPrefix(grpcAddr, "https://")
	grpcAddr = strings.Split(grpcAddr, ":")[0] + ":50051"

	iface := detectIface()

	content := fmt.Sprintf(`[agent]
name = "%s"
server = "%s"
heartbeat_interval = "10s"
collect_interval = "300s"
id_file = "%s/agent.id"

[certs]
ca = "%s/certs/ca.crt"
cert = "%s/certs/agent.crt"
key = "%s/certs/agent.key"

[xdp]
enabled = false
iface = "%s"
server_ip = ""
server_port = 9999
`, cfg.Hostname, grpcAddr, cfg.InstallDir, cfg.InstallDir, cfg.InstallDir, cfg.InstallDir, iface)

	return os.WriteFile(path, []byte(content), 0644)
}


// detectIface 探测第一个物理网卡
//
// 优先级：
//   1. 有 IP 且 state=UP 的物理网卡（ens*/enp*/eth*）
//   2. 任意有 IP 的非 lo 网卡
//   3. 兜底 eth0
func detectIface() string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return "eth0"
	}

	// 虚拟网卡前缀（跳过）
	virtualPrefixes := []string{"lo", "docker", "veth", "br-", "virbr", "vmnet", "tun", "tap", "wg"}

	candidates := []string{}
	for _, entry := range entries {
		name := entry.Name()
		skip := false
		for _, prefix := range virtualPrefixes {
			if strings.HasPrefix(name, prefix) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		// 检查是否 UP
		stateData, err := os.ReadFile(filepath.Join("/sys/class/net", name, "operstate"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(stateData)) != "up" {
			continue
		}
		candidates = append(candidates, name)
	}

	if len(candidates) == 0 {
		return "eth0"
	}

	// 优先物理网卡命名
	for _, name := range candidates {
		if strings.HasPrefix(name, "ens") || strings.HasPrefix(name, "enp") || strings.HasPrefix(name, "eth") {
			return name
		}
	}

	return candidates[0]
}

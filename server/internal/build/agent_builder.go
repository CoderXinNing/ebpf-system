package build

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	agentSrcDir    = "agent"
	agentOutPath   = "bin/agent"
	agentHashPath  = "bin/agent.src.hash"
	agentStaticAMD = "server/static/agent-linux-amd64"
)

// Config 编译配置
type Config struct {
	GoPath         string // 留空自动探测
	AutoBuildAgent bool
}

// EnsureAgentBinary 检查 Agent 源码是否有变化，有则重新编译
func EnsureAgentBinary(cfg Config) error {
	// 1. 如果禁用自动编译，检查静态二进制是否存在
	if !cfg.AutoBuildAgent {
		if !fileExists(agentStaticAMD) {
			return fmt.Errorf("自动编译已禁用，但 %s 不存在", agentStaticAMD)
		}
		log.Println("✅ 自动编译已禁用，使用预编译 Agent")
		return nil
	}

	// 2. 探测 Go
	goPath := detectGo(cfg.GoPath)
	if goPath == "" {
		if fileExists(agentStaticAMD) {
			log.Println("⚠️ 未找到 Go 编译器，使用现有的预编译 Agent")
			return nil
		}
		return fmt.Errorf("未找到 Go 编译器，且 %s 不存在", agentStaticAMD)
	}

	// 2.5 版本检查
	requiredVer := readGoModVersion()
	if requiredVer != "" {
		ok, actualVer := checkGoVersion(goPath, requiredVer)
		if !ok {
			log.Printf("⚠️ Go 版本不满足：当前 %s，要求 ≥ %s", actualVer, requiredVer)
			if fileExists(agentStaticAMD) {
				log.Println("   使用现有预编译 Agent")
				return nil
			}
			return fmt.Errorf("Go 版本不满足且无预编译 Agent")
		}
	}

	// 3. 计算源码 hash
	newHash, err := computeSourceHash()
	if err != nil {
		return fmt.Errorf("计算源码哈希失败: %w", err)
	}

	oldHash, _ := os.ReadFile(agentHashPath)
	binExists := fileExists(agentOutPath)
	staticExists := fileExists(agentStaticAMD)

	if binExists && staticExists && string(oldHash) == newHash {
		log.Println("✅ Agent 二进制已是最新，跳过编译")
		return nil
	}

	log.Printf("🔨 检测到 Agent 源码变化或二进制缺失，开始编译（go=%s）...", goPath)

	// 4. 编译（CGO_ENABLED=0 → 静态二进制，兼容老 GLIBC）
	cmd := exec.Command(goPath, "build", "-o", agentOutPath, "./agent/cmd/")
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS=linux",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Printf("⚠️ Agent 编译失败: %v（Server 继续启动）", err)
		return nil
	}

	// 5. 拷贝
	if err := copyFile(agentOutPath, agentStaticAMD); err != nil {
		log.Printf("⚠️ 拷贝 Agent 到静态目录失败: %v", err)
	} else {
		log.Printf("✅ Agent 已编译并复制到 %s", agentStaticAMD)
	}

	// 6. 更新 hash
	os.WriteFile(agentHashPath, []byte(newHash), 0644)

	return nil
}

// detectGo 探测 Go 路径
//
// 顺序：
//   1. 配置指定的路径
//   2. PATH 环境变量
//   3. 常见安装路径
func detectGo(configured string) string {
	// 1. 配置优先
	if configured != "" {
		if fileExists(configured) {
			return configured
		}
		log.Printf("⚠️ 配置的 go_path 不存在: %s", configured)
	}

	// 2. PATH
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}

	// 3. 常见路径
	commonPaths := []string{
		"/usr/local/go/bin/go",
		"/usr/bin/go",
		"/snap/bin/go",
		"/opt/go/bin/go",
	}
	for _, p := range commonPaths {
		if fileExists(p) {
			return p
		}
	}

	// 4. 用户目录
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, "go", "bin", "go")
		if fileExists(p) {
			return p
		}
	}

	return ""
}

// 下面函数不变
func computeSourceHash() (string, error) {
	var files []string

	err := filepath.Walk(agentSrcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "node_modules" || base == ".git" || base == "data" {
				return filepath.SkipDir
			}
			return nil
		}
		name := info.Name()
		if strings.HasSuffix(name, ".go") || name == "go.mod" || name == "go.sum" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	for _, extra := range []string{"go.mod", "go.sum"} {
		if fileExists(extra) {
			files = append(files, extra)
		}
	}

	sort.Strings(files)

	h := sha256.New()
	for _, path := range files {
		h.Write([]byte(path))
		h.Write([]byte{0})

		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		io.Copy(h, f)
		f.Close()

		h.Write([]byte{0})
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(src, dst string) error {
	os.MkdirAll(filepath.Dir(dst), 0755)

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err = io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	return os.Chmod(dst, 0755)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}


// readGoModVersion 从 go.mod 读取要求的 Go 版本
func readGoModVersion() string {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "go ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "go "))
		}
	}
	return ""
}

// checkGoVersion 检查 Go 版本是否满足要求
// 返回：(是否满足, 实际版本号)
func checkGoVersion(goPath, required string) (bool, string) {
	out, err := exec.Command(goPath, "version").Output()
	if err != nil {
		return false, "unknown"
	}
	// 解析 "go version go1.25.0 linux/amd64"
	parts := strings.Fields(string(out))
	if len(parts) < 3 {
		return false, "unknown"
	}
	actual := strings.TrimPrefix(parts[2], "go")

	return compareGoVersion(actual, required) >= 0, actual
}

// compareGoVersion 比较两个版本号
// 返回：-1 (a < b) / 0 (a == b) / 1 (a > b)
func compareGoVersion(a, b string) int {
	parse := func(v string) []int {
		// 去掉 rc / beta 后缀
		v = strings.Split(v, "-")[0]
		parts := strings.Split(v, ".")
		nums := make([]int, 3)
		for i := 0; i < 3 && i < len(parts); i++ {
			n, _ := strconv.Atoi(parts[i])
			nums[i] = n
		}
		return nums
	}

	av := parse(a)
	bv := parse(b)
	for i := 0; i < 3; i++ {
		if av[i] < bv[i] {
			return -1
		}
		if av[i] > bv[i] {
			return 1
		}
	}
	return 0
}

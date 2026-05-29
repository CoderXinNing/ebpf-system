package probe

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// FrameworkSupport 框架支持情况
type FrameworkSupport struct {
	// BCC
	BCCAvailable   bool   `json:"bcc_available"`
	BCCVersion     string `json:"bcc_version,omitempty"`
	PythonBCCAvailable bool `json:"python_bcc_available"`

	// libbpf
	LibBPFAvailable bool   `json:"libbpf_available"`
	LibBPFVersion   string `json:"libbpf_version,omitempty"`
	LibBPFCORE      bool   `json:"libbpf_core"` // CO-RE支持

	// bpftrace
	BpftraceAvailable bool   `json:"bpftrace_available"`
	BpftraceVersion   string `json:"bpftrace_version,omitempty"`

	// 编译工具链
	ClangAvailable bool   `json:"clang_available"`
	ClangVersion   string `json:"clang_version,omitempty"`
	LLVMAvailable  bool   `json:"llvm_available"`
	LLVMVersion    string `json:"llvm_version,omitempty"`

	// 内核头文件
	KernelHeadersAvailable bool `json:"kernel_headers_available"`

	// Go eBPF库（Agent自带，总是可用）
	GoEBPFAvailable bool `json:"go_ebpf_available"`
}

// DetectFramework 检测框架支持
func DetectFramework() *FrameworkSupport {
	fw := &FrameworkSupport{
		GoEBPFAvailable: true, // Agent本身就用cilium/ebpf
	}

	// 1. 检测BCC
	fw.detectBCC()

	// 2. 检测libbpf
	fw.detectLibBPF()

	// 3. 检测bpftrace
	fw.detectBpftrace()

	// 4. 检测编译工具链
	fw.detectClang()
	fw.detectLLVM()

	// 5. 检测内核头文件
	fw.detectKernelHeaders()

	return fw
}

func (fw *FrameworkSupport) detectBCC() {
	// 检查bcc动态库
	libPaths := []string{
		"/usr/lib/x86_64-linux-gnu/libbcc.so",
		"/usr/lib/libbcc.so",
		"/usr/local/lib/libbcc.so",
	}

	for _, path := range libPaths {
		if _, err := os.Stat(path); err == nil {
			fw.BCCAvailable = true
			break
		}
	}

	// 检查Python BCC绑定
	if fw.BCCAvailable {
		// 尝试导入bcc
		cmd := exec.Command("python3", "-c", "from bcc import BPF; print('ok')")
		output, err := cmd.Output()
		if err == nil && strings.TrimSpace(string(output)) == "ok" {
			fw.PythonBCCAvailable = true
		}
	}

	// 尝试获取BCC版本
	if fw.BCCAvailable {
		// 通过dpkg获取
		cmd := exec.Command("dpkg", "-l", "bcc-tools")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "bcc-tools") {
					fields := strings.Fields(line)
					if len(fields) >= 3 {
						fw.BCCVersion = fields[2]
					}
				}
			}
		}
	}
}

func (fw *FrameworkSupport) detectLibBPF() {
	// 检查libbpf动态库
	libPaths := []string{
		"/usr/lib/x86_64-linux-gnu/libbpf.so",
		"/usr/lib/x86_64-linux-gnu/libbpf.so.0",
		"/usr/lib/x86_64-linux-gnu/libbpf.so.1",
		"/usr/lib/libbpf.so",
		"/usr/local/lib/libbpf.so",
	}

	for _, path := range libPaths {
		if _, err := os.Stat(path); err == nil {
			fw.LibBPFAvailable = true
			break
		}
	}

	// 检查pkg-config
	cmd := exec.Command("pkg-config", "--modversion", "libbpf")
	output, err := cmd.Output()
	if err == nil {
		fw.LibBPFVersion = strings.TrimSpace(string(output))
	}

	// CO-RE支持依赖于BTF和较新的libbpf
	_, btfErr := os.Stat("/sys/kernel/btf/vmlinux")
	fw.LibBPFCORE = (btfErr == nil) && fw.LibBPFAvailable
}

func (fw *FrameworkSupport) detectBpftrace() {
	// 检查bpftrace二进制
	_, err := exec.LookPath("bpftrace")
	if err == nil {
		fw.BpftraceAvailable = true

		// 获取版本
		cmd := exec.Command("bpftrace", "--version")
		output, err := cmd.Output()
		if err == nil {
			// 输出格式: bpftrace v0.16.0
			versionStr := strings.TrimSpace(string(output))
			if strings.HasPrefix(versionStr, "bpftrace") {
				parts := strings.Split(versionStr, " ")
				if len(parts) >= 2 {
					fw.BpftraceVersion = strings.TrimPrefix(parts[1], "v")
				}
			}
		}
	}
}

func (fw *FrameworkSupport) detectClang() {
	// 检查clang
	_, err := exec.LookPath("clang")
	if err == nil {
		fw.ClangAvailable = true

		// 获取版本
		cmd := exec.Command("clang", "--version")
		output, err := cmd.Output()
		if err == nil {
			// 输出第一行: clang version 14.0.0-1ubuntu1
			lines := strings.Split(string(output), "\n")
			if len(lines) > 0 {
				fields := strings.Fields(lines[0])
				if len(fields) >= 3 {
					fw.ClangVersion = fields[2]
				}
			}
		}
	}
}

func (fw *FrameworkSupport) detectLLVM() {
	// 检查llvm相关工具
	tools := []string{"llc", "llvm-objcopy", "llvm-strip"}
	available := 0

	for _, tool := range tools {
		_, err := exec.LookPath(tool)
		if err == nil {
			available++
		}
	}

	fw.LLVMAvailable = available > 0

	// 获取LLVM版本
	if fw.LLVMAvailable {
		cmd := exec.Command("llc", "--version")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) > 0 {
				fields := strings.Fields(lines[0])
				if len(fields) >= 3 {
					fw.LLVMVersion = fields[2]
				}
			}
		}
	}
}

func (fw *FrameworkSupport) detectKernelHeaders() {
	// 检查内核头文件
	headerPaths := []string{
		"/lib/modules/" + getKernelRelease() + "/build/include/linux/bpf.h",
		"/usr/src/linux-headers-" + getKernelRelease() + "/include/linux/bpf.h",
	}

	for _, path := range headerPaths {
		if _, err := os.Stat(path); err == nil {
			fw.KernelHeadersAvailable = true
			return
		}
	}

	// 尝试安装vmlinux.h（CO-RE方式，不依赖头文件）
	// 如果有BTF，可以用bpftool生成vmlinux.h
	_, btfErr := os.Stat("/sys/kernel/btf/vmlinux")
	if btfErr == nil {
		// 检查bpftool
		_, err := exec.LookPath("bpftool")
		if err == nil {
			fw.KernelHeadersAvailable = true // 可以用bpftool生成
		}
	}
}

// getKernelRelease 获取内核版本号
func getKernelRelease() string {
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// FrameworkSummary 打印框架检测摘要
func (fw *FrameworkSupport) FrameworkSummary() string {
	var sb strings.Builder

	sb.WriteString("╔══════════════════════════════════════╗\n")
	sb.WriteString("║     框架/工具链 检测报告             ║\n")
	sb.WriteString("╠══════════════════════════════════════╣\n")

	// BCC
	bccStatus := "❌ 未安装"
	bccDetail := ""
	if fw.BCCAvailable {
		bccStatus = "✅ 已安装"
		if fw.BCCVersion != "" {
			bccDetail = fmt.Sprintf(" (v%s)", fw.BCCVersion)
		}
		if fw.PythonBCCAvailable {
			bccDetail += " [Python绑定]"
		}
	}
	sb.WriteString(fmt.Sprintf("║ BCC:       %s%-22s ║\n", bccStatus, bccDetail))

	// libbpf
	libbpfStatus := "❌ 未安装"
	libbpfDetail := ""
	if fw.LibBPFAvailable {
		libbpfStatus = "✅ 已安装"
		if fw.LibBPFVersion != "" {
			libbpfDetail = fmt.Sprintf(" (v%s)", fw.LibBPFVersion)
		}
		if fw.LibBPFCORE {
			libbpfDetail += " [CO-RE]"
		}
	}
	sb.WriteString(fmt.Sprintf("║ libbpf:    %s%-22s ║\n", libbpfStatus, libbpfDetail))

	// bpftrace
	bpftraceStatus := "❌ 未安装"
	bpftraceDetail := ""
	if fw.BpftraceAvailable {
		bpftraceStatus = "✅ 已安装"
		if fw.BpftraceVersion != "" {
			bpftraceDetail = fmt.Sprintf(" (v%s)", fw.BpftraceVersion)
		}
	}
	sb.WriteString(fmt.Sprintf("║ bpftrace:  %s%-22s ║\n", bpftraceStatus, bpftraceDetail))

	// clang
	clangStatus := "❌ 未安装"
	clangDetail := ""
	if fw.ClangAvailable {
		clangStatus = "✅ 已安装"
		if fw.ClangVersion != "" {
			clangDetail = fmt.Sprintf(" (v%s)", fw.ClangVersion)
		}
	}
	sb.WriteString(fmt.Sprintf("║ clang:     %s%-22s ║\n", clangStatus, clangDetail))

	// LLVM工具链
	llvmStatus := "❌ 未安装"
	llvmDetail := ""
	if fw.LLVMAvailable {
		llvmStatus = "✅ 已安装"
		if fw.LLVMVersion != "" {
			llvmDetail = fmt.Sprintf(" (v%s)", fw.LLVMVersion)
		}
	}
	sb.WriteString(fmt.Sprintf("║ LLVM:      %s%-22s ║\n", llvmStatus, llvmDetail))

	// 内核头文件
	headersStatus := "❌ 未找到"
	if fw.KernelHeadersAvailable {
		headersStatus = "✅ 可用"
	}
	sb.WriteString(fmt.Sprintf("║ 内核头文件: %s%-22s ║\n", headersStatus, ""))

	// Go eBPF
	sb.WriteString(fmt.Sprintf("║ Go eBPF:   ✅ 已集成 (cilium/ebpf)%s ║\n", ""))

	sb.WriteString("╚══════════════════════════════════════╝\n")

	return sb.String()
}

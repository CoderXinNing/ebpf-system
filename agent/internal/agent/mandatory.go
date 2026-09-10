package agent

import "log"

// MandatoryProbes 强制观测探针（用户不可关闭）
var MandatoryProbes = map[string]bool{
	"exec_monitor": true, // 进程生命周期（核心事实）
}

// MandatoryAssets 强制采集资产类型（用户不可关闭）
var MandatoryAssets = map[string]bool{
	"process": true, // 进程盘点
	"user":    true, // 用户盘点
	"system":  true, // 系统信息
}

// IsMandatoryProbe 判断探针是否强制
func IsMandatoryProbe(name string) bool {
	return MandatoryProbes[name]
}

// CheckMandatoryCompliance 检查强制观测合规性
// 返回被违规关闭的探针列表
func CheckMandatoryCompliance(disabled []string) []string {
	violations := make([]string, 0)
	for _, name := range disabled {
		if MandatoryProbes[name] {
			violations = append(violations, name)
			log.Printf("⚠️ 违反强制观测: 探针 %s 不允许关闭", name)
		}
	}
	return violations
}

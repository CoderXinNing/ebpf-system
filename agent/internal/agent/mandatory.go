package agent

// MandatoryProbes 强制观测探针（用户不可关闭）
//
// 对齐 DESIGN.txt §1.5「强制观测清单」：
//   - 进程生命周期  → exec_monitor
//   - 关键系统文件  → file_access
//   - 公网外联      → tcp_monitor
//   - bash 输入     → bash_monitor（DESIGN §1.4 核心采集面）
//
// 语义：探针「必须保持加载」；具体采什么仍由 rules 决定
//
//	（file_access 默认不采，靠 sensitive_paths 触发）。
//
// TODO（P1.10）：DESIGN §1.5 的「super-admin + 二次确认可临时调整」
//
//	尚未实现；当前是硬拒绝关闭。等规则模型 v2 时统一接入。
var MandatoryProbes = map[string]bool{
	"exec_monitor": true,
	"bash_monitor": true,
	"file_access":  true,
	"tcp_monitor":  true,
}

// MandatoryAssets 强制采集资产类型
//
// 注：当前仅作声明，Agent 侧无「拒绝关闭」机制。
// 资产上报由 collector 按固定周期驱动，Server 端 SaveAsset 接收即存。
// 若未来要支持资产类型开关，需在此处接入校验。
var MandatoryAssets = map[string]bool{
	"process": true,
	"user":    true,
	"system":  true,
}

// IsMandatoryProbe 判断探针是否强制
func IsMandatoryProbe(name string) bool {
	return MandatoryProbes[name]
}

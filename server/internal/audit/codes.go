// Package audit 定义审计日志的公共模型与常量
//
// 设计原则：
//   - 机器码与中文描述分离（action_code vs action）
//   - target_type / event_type / event_rw 全部枚举化，禁止散落字符串
//   - 未来扩展只需改本文件
package audit

// ============================================================
// TargetType：操作对象类型
// ============================================================

const (
	TargetUser         = "user"          // 用户账户
	TargetAgent        = "agent"         // 被监控主机
	TargetRule         = "rule"          // 检测规则
	TargetRuleTemplate = "rule_template" // 规则模板
	TargetProbe        = "probe"         // 探针
	TargetConfig       = "config"        // 系统配置
	TargetToken        = "token"         // 注册令牌
	TargetSession      = "session"       // 登录会话
	TargetAlert        = "alert"         // 告警
	TargetBaseline     = "baseline"      // 基线
	TargetSystem       = "system"        // 系统级操作
	TargetAsset        = "asset"         // 资产
)

// ============================================================
// EventType：事件来源类型（参照阿里云 ActionTrail / AWS CloudTrail）
// ============================================================

const (
	EventAPICall       = "api_call"       // OpenAPI 调用（预留）
	EventConsoleAction = "console_action" // 控制台操作（主要）
	EventConsoleSignin = "console_signin" // 登录事件
	EventServiceEvent  = "service_event"  // 系统自动操作
)

// ============================================================
// EventRW：读写类型（参照阿里云 eventRW）
// ============================================================

const (
	RWRead  = "read"
	RWWrite = "write"
)

// ============================================================
// Result：操作结果
// ============================================================

const (
	ResultSuccess = "success"
	ResultFailure = "failure"
)

// ============================================================
// ActionCode：机器可读的操作码，命名规范 target.action
// ============================================================

const (
	// 登录 / 会话
	ActionLogin       = "session.login"
	ActionLoginFail   = "session.login_fail"
	ActionLoginLocked = "session.login_locked"
	ActionLogout      = "session.logout"

	// 主机
	ActionAgentDelete     = "agent.delete"
	ActionAgentMove       = "agent.move"
	ActionAgentRevokeCert = "agent.revoke_cert"
	ActionAgentRenewCert  = "agent.renew_cert"

	// 规则
	ActionRuleCreate = "rule.create"
	ActionRuleUpdate = "rule.update"
	ActionRuleDelete = "rule.delete"
	ActionRuleApply  = "rule.apply"

	// 规则模板
	ActionRuleTemplateCreate = "rule_template.create"
	ActionRuleTemplateUpdate = "rule_template.update"
	ActionRuleTemplateDelete = "rule_template.delete"
	ActionRuleTemplateApply  = "rule_template.apply"

	// 探针
	ActionProbeConfigUpdate = "probe.config_update"
	ActionProbeModeSwitch   = "probe.mode_switch"

	// 配置
	ActionConfigUpdate = "config.update"

	// Token
	ActionTokenCreate = "token.create"
	ActionTokenRevoke = "token.revoke"
	ActionTokenClean  = "token.clean"

	// 告警
	ActionAlertAck      = "alert.ack"
	ActionAlertResolve  = "alert.resolve"
	ActionAlertFalsePos = "alert.false_positive"

	// 基线
	ActionBaselineReset = "baseline.reset"

	// 系统
	ActionSystemTimeSet   = "system.time_set"
	ActionSystemNTPSync   = "system.ntp_sync"
	ActionSystemPageVisit = "system.page_visit"

	// 用户
	ActionUserCreate = "user.create"
	ActionUserUpdate = "user.update"
	ActionUserDelete = "user.delete"
)

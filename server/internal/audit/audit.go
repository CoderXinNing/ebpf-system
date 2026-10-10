package audit

// Record 审计记录（写入侧模型）
//
// 字段对齐 audit_logs 表：
//
//	username / action / action_code / detail
//	target_type / target_id / target_name
//	event_type / event_rw
//	before_value / after_value / result
//	ip / user_agent / session_id
type Record struct {
	// 谁
	SessionID *int64
	Username  string

	// 做什么
	Action     string // 中文描述（UI 直显）
	ActionCode string // 机器码（如 agent.delete）
	Detail     string // 补充信息

	// 对什么
	TargetType string
	TargetID   string
	TargetName string

	// 怎么发生的
	EventType string // console_action / console_signin / ...
	EventRW   string // read / write

	// 变更前后（可选）
	BeforeValue interface{}
	AfterValue  interface{}

	// 结果
	Result string // success / failure

	// 环境
	IP        string
	UserAgent string
}

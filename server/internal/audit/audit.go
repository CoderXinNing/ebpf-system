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

// Build 辅助：快速构造一个 record
type Builder struct {
	rec Record
}

func New() *Builder {
	return &Builder{rec: Record{EventType: EventConsoleAction, Result: ResultSuccess}}
}

func (b *Builder) User(name string) *Builder  { b.rec.Username = name; return b }
func (b *Builder) IP(ip string) *Builder      { b.rec.IP = ip; return b }
func (b *Builder) UA(ua string) *Builder      { b.rec.UserAgent = ua; return b }
func (b *Builder) Session(id *int64) *Builder { b.rec.SessionID = id; return b }

func (b *Builder) Action(name, code string) *Builder {
	b.rec.Action = name
	b.rec.ActionCode = code
	return b
}

func (b *Builder) Target(typ, id, name string) *Builder {
	b.rec.TargetType = typ
	b.rec.TargetID = id
	b.rec.TargetName = name
	return b
}

func (b *Builder) Detail(s string) *Builder { b.rec.Detail = s; return b }

func (b *Builder) Write() *Builder {
	b.rec.EventRW = RWWrite
	if b.rec.EventType == "" {
		b.rec.EventType = EventConsoleAction
	}
	return b
}

func (b *Builder) Read() *Builder {
	b.rec.EventRW = RWRead
	if b.rec.EventType == "" {
		b.rec.EventType = EventConsoleAction
	}
	return b
}

func (b *Builder) Failed() *Builder {
	b.rec.Result = ResultFailure
	return b
}

func (b *Builder) Before(v interface{}) *Builder { b.rec.BeforeValue = v; return b }
func (b *Builder) After(v interface{}) *Builder  { b.rec.AfterValue = v; return b }

func (b *Builder) Build() Record { return b.rec }

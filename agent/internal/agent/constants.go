package agent

import "time"

// 时间常量集中管理。
//
// 设计原则：
//   - 这些值相对稳定，不需要配置文件化
//   - 集中定义避免散落各处、修改漏改
//   - 如未来需要配置化，从这里迁移到 config 包
const (
	// ========== 星轨 ==========

	// StarTTL 星轨默认存活时长（激活后多久自动结束）
	StarTTL = 10 * time.Minute

	// StarRebuildPeriod 星轨进程树从 /proc 重建的周期
	// 用途：修正 exec 事件遗漏的进程
	StarRebuildPeriod = 60 * time.Second

	// StarMatchMaxDepth Matches 向上追溯的最大深度
	// 超过此深度判定为"不属于追踪集合"
	StarMatchMaxDepth = 10

	// StarAncestorMaxDepth BuildAncestors 向上追溯祖先的最大层数
	StarAncestorMaxDepth = 5

	// MaxActiveStars 同时活跃星轨数上限（保护内存）
	MaxActiveStars = 50

	// ========== 关联 ==========

	// CorrelationTTL local_correlation_id 的 TTL
	CorrelationTTL = 10 * time.Minute

	// MutationEndCheckPeriod mutation_end 检查周期
	MutationEndCheckPeriod = 60 * time.Second

	// ========== 自检 ==========

	// SelfTestInterval 探针自检周期
	SelfTestInterval = 5 * time.Minute

	// SelfTestStartDelay Agent 启动后首次自检的等待时间
	// 用途：等探针全部加载完
	SelfTestStartDelay = 30 * time.Second

	// SelfTestWaitSeconds 自检动作执行后等待事件的时间
	SelfTestWaitSeconds = 3 * time.Second

	// ========== 观察等级 ==========

	// ObservationDowngradePeriod 观察等级降级检查周期
	ObservationDowngradePeriod = 2 * time.Minute

	// ========== 基线 ==========

	// BaselineFlushPeriod 基线窗口汇总周期
	BaselineFlushPeriod = 1 * time.Minute

	// BaselinePersistPeriod 基线持久化周期
	BaselinePersistPeriod = 5 * time.Minute

	// ========== 事件上报 ==========

	// EventFlushInterval 事件队列 flush 周期
	EventFlushInterval = 3 * time.Second

	// AssetCollectStartDelay Agent 启动后首次资产上报的等待时间
	AssetCollectStartDelay = 3 * time.Second

	// ========== TCP 异常检测 ==========

	// TCPAnomalyPeriod TCP 异常检测周期
	TCPAnomalyPeriod = 10 * time.Second
)

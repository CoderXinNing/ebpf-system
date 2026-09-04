package actor

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// SendResult 表示非阻塞 Send 的结果
type SendResult int

const (
	// Sent 消息成功放入 inbox
	Sent SendResult = iota
	// Full inbox 已满，消息被丢弃（背压）
	Full
	// Stopped Actor 已停止，消息被拒绝
	Stopped
)

func (s SendResult) String() string {
	switch s {
	case Sent:
		return "Sent"
	case Full:
		return "Full"
	case Stopped:
		return "Stopped"
	default:
		return "Unknown"
	}
}

// Message 是 Actor 间传递的消息，所有消息类型必须实现此接口
type Message interface{}

// Handler 是状态处理函数。在 Actor 的 goroutine 内串行执行。
// 入参 state 是当前状态，msg 是收到的消息。
// 返回值是新的状态（可以是原 state 的指针或值）。
// 注意：Handler 内不应执行重活（网络 IO、数据库查询等），
// 如需异步处理，应在 Handler 内启动新的 goroutine 或发送给其他 Actor。
type Handler func(state interface{}, msg Message) interface{}

// ActorConfig 配置 Actor 行为
type ActorConfig struct {
	// InboxSize 是 inbox channel 的容量。默认为 1000。
	// 不同类型 Actor 可根据背压容忍度调整。
	InboxSize int
}

// Actor 是轻量级 Actor 实现。
// 所有状态通过 Handler 串行处理，无并发写。
// 外部通过 Send（非阻塞）或 Ask（阻塞等待响应）与 Actor 交互。
type Actor struct {
	inbox   chan Message
	state   interface{}
	handler Handler
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	mu      sync.RWMutex
	stopped bool

	// Ask 支持
	askMu    sync.Mutex
	askID    uint64
	askTable map[uint64]chan interface{}
}

// askRequest 是 Ask 的内部消息包装
type askRequest struct {
	id      uint64
	replyCh chan interface{}
	msg     Message
}

// askResponse 是 Ask 的响应消息
type askResponse struct {
	id     uint64
	result interface{}
}

// New 创建 Actor。必须调用 Start 才会开始处理消息。
func New(handler Handler, initialState interface{}, cfg ActorConfig) *Actor {
	if cfg.InboxSize <= 0 {
		cfg.InboxSize = 1000
	}
	if handler == nil {
		panic("actor: handler cannot be nil")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Actor{
		inbox:    make(chan Message, cfg.InboxSize),
		state:    initialState,
		handler:  handler,
		ctx:      ctx,
		cancel:   cancel,
		askTable: make(map[uint64]chan interface{}),
	}
}

// Start 启动 Actor 的消息处理循环。
// 必须且只能调用一次。
func (a *Actor) Start() {
	a.wg.Add(1)
	go a.loop()
}

// Stop 优雅停止 Actor：
// 1. 标记 stopped，拒绝新消息
// 2. 等待 inbox 中已接收的消息全部处理完
// 3. 关闭 inbox，等待处理循环退出
// 可以安全地多次调用（幂等）。
func (a *Actor) Stop() {
	a.mu.Lock()
	if a.stopped {
		a.mu.Unlock()
		return
	}
	a.stopped = true
	a.mu.Unlock()

	// 关闭 inbox 并等待处理循环退出
	close(a.inbox)
	a.wg.Wait()

	// 清理 Ask 表
	a.askMu.Lock()
	for id, ch := range a.askTable {
		close(ch)
		delete(a.askTable, id)
	}
	a.askMu.Unlock()
	a.cancel()
}

// GetState 非阻塞读取当前状态（只读，不做任何修改）。
// 注意：此方法直接返回 state 指针，调用方必须确保不修改它。
// 用于高频读取场景（如心跳、状态展示），避免 Ask 的阻塞开销。
func (a *Actor) GetState() interface{} {
	return a.state
}

// Send 非阻塞发送消息。返回值表示发送结果。
// - Sent: 成功
// - Full: inbox 满，消息被丢弃
// - Stopped: Actor 已停止
func (a *Actor) Send(msg Message) SendResult {
	a.mu.RLock()
	stopped := a.stopped
	a.mu.RUnlock()
	if stopped {
		return Stopped
	}

	select {
	case a.inbox <- msg:
		return Sent
	default:
		return Full
	}
}

// Ask 发送消息并等待响应。适用于需要获取结果的场景。
// 超时返回 error。如果 Actor 已停止，立即返回 error。
func (a *Actor) Ask(msg Message, timeout time.Duration) (interface{}, error) {
	a.mu.RLock()
	stopped := a.stopped
	a.mu.RUnlock()
	if stopped {
		return nil, fmt.Errorf("actor: stopped")
	}

	a.askMu.Lock()
	a.askID++
	id := a.askID
	replyCh := make(chan interface{}, 1)
	a.askTable[id] = replyCh
	a.askMu.Unlock()

	select {
	case a.inbox <- askRequest{id: id, replyCh: replyCh, msg: msg}:
		// 发送成功，等待响应
	case <-time.After(timeout):
		a.askMu.Lock()
		delete(a.askTable, id)
		a.askMu.Unlock()
		return nil, fmt.Errorf("actor: send timeout")
	}

	select {
	case result := <-replyCh:
		a.askMu.Lock()
		delete(a.askTable, id)
		a.askMu.Unlock()
		return result, nil
	case <-time.After(timeout):
		a.askMu.Lock()
		delete(a.askTable, id)
		a.askMu.Unlock()
		return nil, fmt.Errorf("actor: response timeout")
	}
}

// loop 是 Actor 的主循环，在独立 goroutine 中运行。
func (a *Actor) loop() {
	defer a.wg.Done()
	for msg := range a.inbox {
		// 处理 Ask 请求：handler 的返回值是响应，state 不变
		if req, ok := msg.(askRequest); ok {
			result := a.handler(a.state, req.msg)
			select {
			case req.replyCh <- result:
			default:
				// 响应 channel 可能已被超时清理，忽略
			}
			continue
		}

		// 普通消息：handler 的返回值成为新的 state
		a.state = a.handler(a.state, msg)
	}
}

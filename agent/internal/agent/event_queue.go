package agent

import (
	"sync"
	"sync/atomic"

	"github.com/CoderXinNing/ebpf-system/agent/internal/actor"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
)

// EventPriority 事件优先级
type EventPriority int

const (
	// PriorityNormal 普通事件（exec/bash/tcp）
	PriorityNormal EventPriority = iota
	// PriorityHigh 高优先级事件（XDP/安全告警/基线异常）
	PriorityHigh
)

// EventQueue 是双优先级非阻塞事件队列。
// 高优先级队列满时才会丢低优先级事件。
// 所有操作非阻塞，绝不拖慢探针回调。
type EventQueue struct {
	highQueue chan *pb.ProbeEvent
	lowQueue  chan *pb.ProbeEvent

	// 统计信息（原子操作）
	droppedHigh atomic.Uint64
	droppedLow  atomic.Uint64
	totalHigh   atomic.Uint64
	totalLow    atomic.Uint64

	// 关闭状态
	mu      sync.RWMutex
	stopped bool
}

// NewEventQueue 创建事件队列。
// highCapacity: 高优先级队列容量
// lowCapacity: 低优先级队列容量
func NewEventQueue(highCapacity, lowCapacity int) *EventQueue {
	if highCapacity <= 0 {
		highCapacity = 100
	}
	if lowCapacity <= 0 {
		lowCapacity = 1000
	}
	return &EventQueue{
		highQueue: make(chan *pb.ProbeEvent, highCapacity),
		lowQueue:  make(chan *pb.ProbeEvent, lowCapacity),
	}
}

// Push 非阻塞推入事件。返回值表示推入结果。
func (q *EventQueue) Push(evt *pb.ProbeEvent, priority EventPriority) actor.SendResult {
	if evt == nil {
		return actor.Full
	}

	q.mu.RLock()
	stopped := q.stopped
	q.mu.RUnlock()
	if stopped {
		return actor.Stopped
	}

	switch priority {
	case PriorityHigh:
		q.totalHigh.Add(1)
		select {
		case q.highQueue <- evt:
			return actor.Sent
		default:
			q.droppedHigh.Add(1)
			return actor.Full
		}

	case PriorityNormal:
		q.totalLow.Add(1)
		select {
		case q.lowQueue <- evt:
			return actor.Sent
		default:
			q.droppedLow.Add(1)
			return actor.Full
		}

	default:
		return actor.Full
	}
}

// Pop 阻塞读取一个事件。优先读高优先级队列。
// 如果队列已停止且两队列都空，返回 nil。
func (q *EventQueue) Pop() *pb.ProbeEvent {
	// 先检查高优先级队列
	select {
	case evt := <-q.highQueue:
		return evt
	default:
	}

	// 高优先级空，等待任一队列有数据
	select {
	case evt := <-q.highQueue:
		return evt
	case evt := <-q.lowQueue:
		return evt
	}
}

// Stop 关闭队列。关闭后 Push 返回 Stopped。
func (q *EventQueue) Stop() {
	q.mu.Lock()
	if q.stopped {
		q.mu.Unlock()
		return
	}
	q.stopped = true
	q.mu.Unlock()
}

// Stats 返回统计信息。
type QueueStats struct {
	DroppedHigh uint64
	DroppedLow  uint64
	TotalHigh   uint64
	TotalLow    uint64
}

func (q *EventQueue) Stats() QueueStats {
	return QueueStats{
		DroppedHigh: q.droppedHigh.Load(),
		DroppedLow:  q.droppedLow.Load(),
		TotalHigh:   q.totalHigh.Load(),
		TotalLow:    q.totalLow.Load(),
	}
}

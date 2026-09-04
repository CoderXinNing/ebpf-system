package actor

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// 测试用状态
type counterState struct {
	mu    sync.Mutex
	count int
	last  string
}

func counterHandler(state interface{}, msg Message) interface{} {
	s := state.(*counterState)
	s.mu.Lock()
	defer s.mu.Unlock()
	switch m := msg.(type) {
	case string:
		s.last = m
	case int:
		s.count += m
	}
	return s
}

func TestActorSendAndProcess(t *testing.T) {
	state := &counterState{}
	a := New(counterHandler, state, ActorConfig{InboxSize: 10})
	a.Start()
	defer a.Stop()

	result := a.Send(1)
	if result != Sent {
		t.Fatalf("期望 Sent，得到 %v", result)
	}
	result = a.Send(2)
	if result != Sent {
		t.Fatalf("期望 Sent，得到 %v", result)
	}
	result = a.Send("hello")
	if result != Sent {
		t.Fatalf("期望 Sent，得到 %v", result)
	}

	// 等待处理完成
	time.Sleep(50 * time.Millisecond)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.count != 3 {
		t.Fatalf("期望 count=3，得到 %d", state.count)
	}
	if state.last != "hello" {
		t.Fatalf("期望 last=hello，得到 %s", state.last)
	}
}

func TestActorFullBackpressure(t *testing.T) {
	state := &counterState{}
	a := New(counterHandler, state, ActorConfig{InboxSize: 2})
	// 不 Start，让 inbox 积压
	// 直接发送 3 条消息（inbox 容量 2，第 3 条应该 Full）

	r1 := a.Send(1)
	r2 := a.Send(2)
	r3 := a.Send(3)

	if r1 != Sent || r2 != Sent {
		t.Fatalf("前两条应该 Sent，得到 %v %v", r1, r2)
	}
	if r3 != Full {
		t.Fatalf("第三条应该 Full，得到 %v", r3)
	}
}

func TestActorStopped(t *testing.T) {
	state := &counterState{}
	a := New(counterHandler, state, ActorConfig{InboxSize: 10})
	a.Start()
	a.Stop()

	result := a.Send(1)
	if result != Stopped {
		t.Fatalf("期望 Stopped，得到 %v", result)
	}
}

func TestActorAsk(t *testing.T) {
	state := &counterState{}
	a := New(counterHandler, state, ActorConfig{InboxSize: 10})
	a.Start()
	defer a.Stop()

	result, err := a.Ask(5, time.Second)
	if err != nil {
		t.Fatalf("Ask 失败: %v", err)
	}
	s := result.(*counterState)
	if s.count != 5 {
		t.Fatalf("期望 count=5，得到 %d", s.count)
	}
	if s != state {
		t.Fatal("Ask 返回的状态应该与 Actor 内部状态一致")
	}
}

func TestActorAskTimeout(t *testing.T) {
	// 用一个会阻塞的 handler
	blockingHandler := func(state interface{}, msg Message) interface{} {
		time.Sleep(200 * time.Millisecond)
		return state
	}
	a := New(blockingHandler, nil, ActorConfig{InboxSize: 10})
	a.Start()
	defer a.Stop()

	_, err := a.Ask("test", 50*time.Millisecond)
	if err == nil {
		t.Fatal("期望超时错误")
	}
}

func TestActorConcurrentSend(t *testing.T) {
	state := &counterState{}
	a := New(counterHandler, state, ActorConfig{InboxSize: 100})
	a.Start()
	defer a.Stop()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.Send(1)
		}()
	}
	wg.Wait()

	time.Sleep(100 * time.Millisecond)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.count != 100 {
		t.Fatalf("期望 count=100，得到 %d", state.count)
	}
}

func TestActorMultipleStop(t *testing.T) {
	state := &counterState{}
	a := New(counterHandler, state, ActorConfig{InboxSize: 10})
	a.Start()

	a.Stop()
	a.Stop() // 第二次应该安全返回

	result := a.Send(1)
	if result != Stopped {
		t.Fatalf("期望 Stopped，得到 %v", result)
	}
}

func ExampleActor() {
	state := &counterState{}
	a := New(counterHandler, state, ActorConfig{InboxSize: 10})
	a.Start()
	defer a.Stop()

	a.Send(1)
	a.Send(2)
	fmt.Println("消息已发送")
	// Output: 消息已发送
}

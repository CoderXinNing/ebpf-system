package agent

import (
	"testing"
	"time"
)

func TestCorrelationEnd(t *testing.T) {
	mgr := NewCorrelationManager("test-agent-001", 100*time.Millisecond)

	// 生成关联
	corrID := mgr.GetOrCreate(12345)
	if corrID == "" {
		t.Fatal("corrID 不应为空")
	}
	t.Logf("生成 corrID: %s", corrID)

	// 验证存在
	if !mgr.Has(12345) {
		t.Fatal("关联应存在")
	}

	// 触发 End
	endedID := mgr.End(12345)
	if endedID != corrID {
		t.Fatalf("End 返回错误: got=%s want=%s", endedID, corrID)
	}

	// 验证已清除
	if mgr.Has(12345) {
		t.Fatal("关联应已清除")
	}
	t.Log("✅ End 验证通过")
}

func TestCorrelationExpiry(t *testing.T) {
	mgr := NewCorrelationManager("test-agent-001", 100*time.Millisecond)

	corrID := mgr.GetOrCreate(67890)
	t.Logf("生成 corrID: %s", corrID)

	// 等待过期
	time.Sleep(200 * time.Millisecond)

	expired := mgr.CleanupExpired()
	if len(expired) != 1 {
		t.Fatalf("应有 1 个过期条目, got=%d", len(expired))
	}
	if expired[0] != corrID {
		t.Fatalf("过期 ID 错误: got=%s want=%s", expired[0], corrID)
	}
	t.Log("✅ Expiry 验证通过")
}

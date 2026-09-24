package rules

import (
	"strings"
	"testing"
)

func TestCanonicalStable(t *testing.T) {
	rs := &RuleSet{
		Version: 1,
		SensitivePaths: &SensitivePaths{
			ExactPaths:  []string{"/etc/shadow", "/etc/passwd"},
			PrefixPaths: []string{"/home/"},
		},
	}

	a, _ := Canonical(rs)
	b, _ := Canonical(rs)
	if string(a) != string(b) {
		t.Fatalf("canonical 不稳定:\n%s\n%s", a, b)
	}
}

func TestHashStable(t *testing.T) {
	rs := &RuleSet{Version: 1, SensitivePaths: &SensitivePaths{ExactPaths: []string{"/x"}}}
	h1, _ := Hash(rs)
	h2, _ := Hash(rs)
	if h1 != h2 || h1 == "" {
		t.Fatalf("hash 不稳定: %s vs %s", h1, h2)
	}
}

func TestValidate(t *testing.T) {
	// 正常
	if err := Validate(&RuleSet{Version: 1}); err != nil {
		t.Fatalf("正常规则应通过: %v", err)
	}

	// version 缺失
	if err := Validate(&RuleSet{Version: 0}); err == nil {
		t.Fatal("version=0 应拒绝")
	}

	// 前缀不以 / 结尾
	rs := &RuleSet{Version: 1, SensitivePaths: &SensitivePaths{PrefixPaths: []string{"/home"}}}
	if err := Validate(rs); err == nil {
		t.Fatal("前缀 /home 应拒绝")
	}

	// 超长路径
	long := strings.Repeat("a", 300)
	rs2 := &RuleSet{Version: 1, SensitivePaths: &SensitivePaths{ExactPaths: []string{long}}}
	if err := Validate(rs2); err == nil {
		t.Fatal("超长路径应拒绝")
	}
}

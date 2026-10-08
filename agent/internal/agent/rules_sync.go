package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/CoderXinNing/ebpf-system/agent/internal/paths"
	"github.com/CoderXinNing/ebpf-system/internal/rules"
	"github.com/CoderXinNing/ebpf-system/internal/rulesign"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
)

// 规则同步状态常量
const (
	RulesStatusSynced  = "synced"
	RulesStatusStale   = "stale"
	RulesStatusUnknown = "unknown"
)

// syncRulesOnStartup 启动时：优先加载本地缓存（已验签），避免启动期"裸奔"
func (a *Agent) syncRulesOnStartup() {
	content, sig, err := loadRulesCache()
	if err != nil {
		a.setRulesStatus(RulesStatusUnknown, 0, "")
		log.Printf("📋 本地无规则缓存（%v），等待 Server 下发", err)
		return
	}

	rs, err := a.verifyAndApplyRules(content, sig)
	if err != nil {
		a.setRulesStatus(RulesStatusUnknown, 0, "")
		log.Printf("⚠️ 本地规则缓存验签失败: %v（拒绝加载）", err)
		return
	}

	a.setRulesStatus(RulesStatusSynced, rs.Version, "")
	log.Printf("📋 启动加载本地规则: version=%d", rs.Version)
}

// syncRulesFromServer 主动从 Server 拉取规则（比对版本 → 拉全量 → 验签 → 应用）
func (a *Agent) syncRulesFromServer(ctx context.Context) error {
	if a.client == nil || a.token == "" {
		return fmt.Errorf("Server 未连接")
	}

	rpcCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// 1. 查版本
	verResp, err := a.client.GetRulesVersion(a.getAuthContext(rpcCtx), &pb.RulesVersionRequest{
		AgentId: a.id,
	})
	if err != nil {
		a.markRulesStale()
		return fmt.Errorf("GetRulesVersion 失败: %w", err)
	}
	if !verResp.Success {
		a.markRulesStale()
		return fmt.Errorf("GetRulesVersion 被拒绝: %s", verResp.Message)
	}
	if verResp.Version == 0 {
		log.Printf("📋 Server 无规则，保持现状")
		a.setRulesStatus(RulesStatusSynced, 0, "")
		return nil
	}

	// 2. 版本一致 → 无需拉全量
	a.rulesMu.RLock()
	curVer, curSha := a.rulesVersion, a.rulesSha256
	a.rulesMu.RUnlock()

	if curVer == verResp.Version && curSha == verResp.Sha256 && curVer > 0 {
		a.setRulesStatus(RulesStatusSynced, curVer, curSha)
		return nil
	}

	// 3. 拉全量
	fullResp, err := a.client.GetRulesFull(a.getAuthContext(rpcCtx), &pb.RulesFullRequest{
		AgentId: a.id,
	})
	if err != nil {
		a.markRulesStale()
		return fmt.Errorf("GetRulesFull 失败: %w", err)
	}
	if !fullResp.Success {
		a.markRulesStale()
		return fmt.Errorf("GetRulesFull 被拒绝: %s", fullResp.Message)
	}
	if fullResp.Content == "" {
		a.setRulesStatus(RulesStatusSynced, 0, "")
		return nil
	}

	// 4. 验签 + 应用 + 写缓存
	rs, err := a.verifyAndApplyRules([]byte(fullResp.Content), fullResp.Signature)
	if err != nil {
		a.markRulesStale()
		return fmt.Errorf("规则验签/应用失败: %w", err)
	}

	// 5. 写本地缓存
	if err := saveRulesCache([]byte(fullResp.Content), fullResp.Signature); err != nil {
		log.Printf("⚠️ 规则缓存写入失败: %v", err)
	}

	a.setRulesStatus(RulesStatusSynced, rs.Version, fullResp.Sha256)
	log.Printf("📋 规则已更新: version=%d sha256=%s...", rs.Version, fullResp.Sha256[:16])
	return nil
}

// verifyAndApplyRules 验签 + 应用到 fileProbe
func (a *Agent) verifyAndApplyRules(content []byte, sigB64 string) (*rules.RuleSet, error) {
	// 1. 验签（CA 公钥）
	caPEM, err := os.ReadFile(a.cfg.Certs.CA)
	if err != nil {
		return nil, fmt.Errorf("读取 CA 证书失败: %w", err)
	}
	if err := rulesign.Verify(caPEM, content, sigB64); err != nil {
		return nil, fmt.Errorf("验签失败: %w", err)
	}

	// 2. 反序列化
	var rs rules.RuleSet
	if err := json.Unmarshal(content, &rs); err != nil {
		return nil, fmt.Errorf("规则反序列化失败: %w", err)
	}

	// 3. 校验
	if err := rules.Validate(&rs); err != nil {
		return nil, fmt.Errorf("规则校验失败: %w", err)
	}

	// 4. 应用到 fileProbe
	if a.fileProbe == nil {
		log.Printf("⚠️ fileProbe 未初始化，规则暂时无法应用（启动过早）")
		return &rs, nil
	}
	if rs.SensitivePaths != nil {
		if err := a.fileProbe.UpdateSensitivePaths(
			rs.SensitivePaths.ExactPaths,
			rs.SensitivePaths.PrefixPaths,
		); err != nil {
			return nil, fmt.Errorf("应用规则失败: %w", err)
		}
		log.Printf("📋 敏感路径已应用: 精确 %d 条, 前缀 %d 条",
			len(rs.SensitivePaths.ExactPaths), len(rs.SensitivePaths.PrefixPaths))
	}

	return &rs, nil
}

// ========== 本地缓存 ==========

func saveRulesCache(content []byte, sig string) error {
	if err := os.MkdirAll(paths.AgentDataDir(), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(paths.RulesCacheFile(), content, 0644); err != nil {
		return err
	}
	return os.WriteFile(paths.RulesSigFile(), []byte(sig), 0644)
}

func loadRulesCache() (content []byte, sig string, err error) {
	content, err = os.ReadFile(paths.RulesCacheFile())
	if err != nil {
		return nil, "", err
	}
	sigBytes, err := os.ReadFile(paths.RulesSigFile())
	if err != nil {
		return nil, "", err
	}
	return content, string(sigBytes), nil
}

// ========== 状态管理 ==========

func (a *Agent) setRulesStatus(status string, version int64, sha256 string) {
	a.rulesMu.Lock()
	a.rulesStatus = status
	a.rulesVersion = version
	if sha256 != "" {
		a.rulesSha256 = sha256
	}
	a.rulesLastCheck = time.Now().Unix()
	a.rulesMu.Unlock()
}

func (a *Agent) markRulesStale() {
	a.rulesMu.Lock()
	a.rulesStatus = RulesStatusStale
	a.rulesLastCheck = time.Now().Unix()
	a.rulesMu.Unlock()
}

// getRulesStatus 返回 (status, version, lastCheck) 供心跳用
func (a *Agent) getRulesStatus() (string, int64, int64) {
	a.rulesMu.RLock()
	defer a.rulesMu.RUnlock()
	s := a.rulesStatus
	if s == "" {
		s = RulesStatusUnknown
	}
	return s, a.rulesVersion, a.rulesLastCheck
}

// ========== 同步循环 ==========

// rulesSyncLoop 定时同步（带退避）
func (a *Agent) rulesSyncLoop(ctx context.Context) {
	// 启动后先等 5 秒（让探针加载完）
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Second):
	}

	if err := a.syncRulesFromServer(ctx); err != nil {
		log.Printf("⚠️ 首次规则同步失败: %v", err)
	}

	// 退避参数
	failures := 0
	baseInterval := 5 * time.Minute

	for {
		interval := baseInterval
		if failures >= 5 {
			interval = 10 * time.Minute // 连续失败降频
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}

		if err := a.syncRulesFromServer(ctx); err != nil {
			failures++
			log.Printf("⚠️ 规则同步失败 (第%d次): %v", failures, err)
		} else {
			if failures > 0 {
				log.Printf("✅ 规则同步恢复（前 %d 次失败）", failures)
			}
			failures = 0
		}
	}
}

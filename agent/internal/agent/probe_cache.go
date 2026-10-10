package agent

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	localcrypto "github.com/CoderXinNing/ebpf-system/agent/internal/crypto"
	"github.com/CoderXinNing/ebpf-system/agent/internal/paths"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
)

// cachedProbe 本地探针缓存条目。
//
// 与 pb.ProbeInfo 显式对齐（用本地结构避免依赖 proto 内部字段）。
type cachedProbe struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Remove  bool   `json:"remove"`
	Path    string `json:"path"`
	Sha256  string `json:"sha256"`
}

// probeCacheFile 缓存文件布局
type probeCacheFile struct {
	Version int           `json:"version"`
	Probes  []cachedProbe `json:"probes"`
}

const probeCacheVersion = 1

// saveProbeListCache 加密写探针名单缓存。
//
// 内容视为安全资产（防御能力清单 + .o SHA256），
// 与 rules.enc 走同一套 AES-GCM + HKDF。
//
// 降级：machine-id / agent.id 不可读时，落回明文 probes.json 并打警告。
func saveProbeListCache(probes []*pb.ProbeInfo) error {
	if len(probes) == 0 {
		return nil
	}
	if err := os.MkdirAll(paths.AgentDataDir(), 0755); err != nil {
		return err
	}

	f := probeCacheFile{Version: probeCacheVersion}
	for _, p := range probes {
		f.Probes = append(f.Probes, cachedProbe{
			Name:    p.Name,
			Enabled: p.Enabled,
			Remove:  p.Remove,
			Path:    p.Path,
			Sha256:  p.Sha256,
		})
	}

	plain, err := json.Marshal(f)
	if err != nil {
		return err
	}

	// 加密
	enc, err := localcrypto.Encrypt(plain, paths.AgentIDFile())
	if err != nil {
		log.Printf("⚠️ 探针名单加密失败（降级明文）: %v", err)
		// 删旧 probes.enc，避免下次启动 loadProbeListCache 优先读到过期加密缓存
		if rerr := os.Remove(paths.ProbeListEncFile()); rerr != nil && !os.IsNotExist(rerr) {
			log.Printf("⚠️ 删除旧 probes.enc 失败: %v", rerr)
		}
		return writePlainProbeCache(plain)
	}

	// 写加密文件（先删旧，保证新文件权限）
	_ = os.Remove(paths.ProbeListEncFile())
	if err := os.WriteFile(paths.ProbeListEncFile(), enc, 0600); err != nil {
		return err
	}

	// 迁移：旧明文删掉
	if _, err := os.Stat(paths.ProbeListCacheFile()); err == nil {
		if err := os.Remove(paths.ProbeListCacheFile()); err != nil {
			log.Printf("⚠️ 删除旧明文探针名单失败（不影响运行）: %v", err)
		} else {
			log.Printf("🗑️ 旧明文探针名单已删除（已迁移至 probes.enc）")
		}
	}
	return nil
}

func writePlainProbeCache(plain []byte) error {
	tmp := paths.ProbeListCacheFile() + ".tmp"
	if err := os.WriteFile(tmp, plain, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, paths.ProbeListCacheFile())
}

// loadProbeListCache 读探针名单缓存，转为 pb.ProbeInfo 结构。
//
// 优先级：
//  1. probes.enc（加密）→ 解密
//  2. probes.json（旧明文）→ 读明文（下次写时迁移）
//  3. 都没有 → 返回 os.ErrNotExist
func loadProbeListCache() ([]*pb.ProbeInfo, error) {
	var plain []byte

	if enc, err := os.ReadFile(paths.ProbeListEncFile()); err == nil {
		p, derr := localcrypto.Decrypt(enc, paths.AgentIDFile())
		if derr != nil {
			return nil, fmt.Errorf("探针名单缓存解密失败（可能换机器）: %w", derr)
		}
		plain = p
	} else if !os.IsNotExist(err) {
		return nil, err
	} else {
		// 降级：旧明文
		p, rerr := os.ReadFile(paths.ProbeListCacheFile())
		if rerr != nil {
			return nil, rerr
		}
		plain = p
	}

	var f probeCacheFile
	if err := json.Unmarshal(plain, &f); err != nil {
		return nil, fmt.Errorf("探针名单缓存解析失败: %w", err)
	}
	if f.Version != probeCacheVersion {
		return nil, fmt.Errorf("探针名单缓存版本不匹配: %d", f.Version)
	}

	out := make([]*pb.ProbeInfo, 0, len(f.Probes))
	for _, p := range f.Probes {
		out = append(out, &pb.ProbeInfo{
			Name:    p.Name,
			Enabled: p.Enabled,
			Remove:  p.Remove,
			Path:    p.Path,
			Sha256:  p.Sha256,
		})
	}
	return out, nil
}

// loadProbesFromCacheOffline 离线保命模式：用缓存名单加载探针。
//
// 语义：
//   - 有缓存：走 loadProbesByList（保留 SHA256 校验）
//   - 无缓存：静默跳过，等 Server 重连后走在线流程
func (a *Agent) loadProbesFromCacheOffline() {
	probes, err := loadProbeListCache()
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("📋 离线模式：无探针名单缓存，跳过加载（等 Server 重连）")
			return
		}
		log.Printf("⚠️ 离线模式：探针名单缓存读取失败: %v", err)
		return
	}
	if len(probes) == 0 {
		log.Printf("📋 离线模式：探针名单缓存为空，跳过加载")
		return
	}
	log.Printf("📋 离线模式：从缓存加载探针名单（%d 个）", len(probes))
	a.loadProbesByList(probes)
}

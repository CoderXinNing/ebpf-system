package collector

import (
	"os"
	"sync"
	"time"
)

// fileCache 系统文件缓存（TTL 内复用，避免同周期重复读）
//
// 为什么需要：
//   - resolveUID 每进程调一次 → 300 进程 = 300 次读 /etc/passwd
//   - getAllUsernames 在 sudoers 循环里调 → 多次读
//   - 采集周期 5 分钟，一次采集内文件内容几乎不变
//
// 安全注意：
//   - 这些是系统账号文件，60s TTL 不会错过攻击（攻击通常持续数分钟）
//   - file_access 探针仍在 C 层工作，读被缓存但事件不受影响
type fileCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	ttl     time.Duration
}

type cacheEntry struct {
	data      []byte
	expiresAt time.Time
}

var globalFileCache = &fileCache{
	entries: make(map[string]*cacheEntry),
	ttl:     60 * time.Second,
}

func cachedReadFile(path string) ([]byte, error) {
	globalFileCache.mu.RLock()
	if e, ok := globalFileCache.entries[path]; ok && time.Now().Before(e.expiresAt) {
		data := e.data
		globalFileCache.mu.RUnlock()
		return data, nil
	}
	globalFileCache.mu.RUnlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	globalFileCache.mu.Lock()
	globalFileCache.entries[path] = &cacheEntry{
		data:      data,
		expiresAt: time.Now().Add(globalFileCache.ttl),
	}
	globalFileCache.mu.Unlock()
	return data, nil
}

// uidCache uid → username 映射缓存（避免重复扫描 passwd）
type uidCache struct {
	mu      sync.RWMutex
	entries map[int]string
	builtAt time.Time
}

var globalUIDCache = &uidCache{
	entries: make(map[int]string),
}

const uidCacheTTL = 60 * time.Second

// resolveUIDCached 从缓存解析 UID → 用户名
func resolveUIDCached(uid int) string {
	globalUIDCache.mu.RLock()
	if time.Since(globalUIDCache.builtAt) < uidCacheTTL {
		if name, ok := globalUIDCache.entries[uid]; ok {
			globalUIDCache.mu.RUnlock()
			return name
		}
	}
	globalUIDCache.mu.RUnlock()

	// 缓存过期或未命中 → 重建
	globalUIDCache.mu.Lock()
	defer globalUIDCache.mu.Unlock()

	if time.Since(globalUIDCache.builtAt) >= uidCacheTTL {
		globalUIDCache.entries = buildUIDMap()
		globalUIDCache.builtAt = time.Now()
	}

	if name, ok := globalUIDCache.entries[uid]; ok {
		return name
	}
	return ""
}

// buildUIDMap 从 /etc/passwd 建立 uid→name 映射
func buildUIDMap() map[int]string {
	data, err := cachedReadFile("/etc/passwd")
	if err != nil {
		return make(map[int]string)
	}
	result := make(map[int]string)
	for _, line := range splitLines(data) {
		fields := splitColon(line)
		if len(fields) < 3 {
			continue
		}
		if uid, ok := parseUint(fields[2]); ok {
			result[uid] = fields[0]
		}
	}
	return result
}

import { ref, onMounted, onUnmounted } from 'vue'
import http from '../api/http'

const WARN_BEFORE_TIMEOUT_MS = 60 * 1000  // 超时前 1 分钟警告

/**
 * useSession 会话管理（v3：统一心跳模型）
 *
 * 设计：
 *   1. idle 由任何后端交互重置（API 请求 / 心跳）
 *   2. 心跳 = 用户显式开启的“自动交互”，每 N 秒发一次 keepalive
 *   3. 心跳关闭时，用户不操作 → idle 分钟倒数 → 后端踢（401）
 *   4. banner 基于“最后一次 API 请求”时间
 *
 * 与 v2 的差异：
 *   - 去掉鼠标/键盘监听（不触发后端）
 *   - 去掉 visibilitychange 逻辑
 *   - 心跳开关由用户控制（导航栏）
 */
export function useSession() {
  const lastRequestAt   = ref(Date.now())
  const idleMinutes     = ref(10)
  const heartbeatEnabled = ref(false)
  const heartbeatInterval = ref(180)  // 秒
  const showWarning     = ref(false)

  let heartbeatTimer: number | null = null
  let warnTimer: number | null = null

  // ---------- 配置加载/保存 ----------
  function loadConfig() {
    const raw = localStorage.getItem('session')
    if (!raw) return
    try {
      const cfg = JSON.parse(raw)
      idleMinutes.value = cfg.idle_minutes || 10
      heartbeatEnabled.value = cfg.heartbeat_enabled || false
      heartbeatInterval.value = cfg.heartbeat_interval_seconds || 180
    } catch {}
  }

  // 从后端拉取最新配置（管理员改动后同步）
  async function syncConfig() {
    try {
      const { data } = await http.get('/session/config')
      if (data.idle_minutes) idleMinutes.value = data.idle_minutes
      if (data.heartbeat_enabled !== undefined) heartbeatEnabled.value = data.heartbeat_enabled
      if (data.heartbeat_interval_seconds) heartbeatInterval.value = data.heartbeat_interval_seconds
      saveConfig()
    } catch {
      // 401 由 http.ts 拦截器处理
    }
  }

  function saveConfig() {
    const cfg = {
      idle_minutes: idleMinutes.value,
      heartbeat_enabled: heartbeatEnabled.value,
      heartbeat_interval_seconds: heartbeatInterval.value,
    }
    localStorage.setItem('session', JSON.stringify(cfg))
  }

  // ---------- 心跳 ----------
  function startHeartbeat() {
    if (heartbeatTimer) return
    // 立即同步一次配置
    syncConfig()
    heartbeatTimer = window.setInterval(async () => {
      try {
        await http.post('/session/keepalive')
        // 每个心跳周期同步配置（idle / interval 可能被改）
        await syncConfig()
      } catch {
        // 401 由 http.ts 拦截器处理
      }
    }, heartbeatInterval.value * 1000)
  }

  function stopHeartbeat() {
    if (heartbeatTimer) {
      clearInterval(heartbeatTimer)
      heartbeatTimer = null
    }
  }

  async function toggleHeartbeat(enabled: boolean) {
    try {
      await http.post('/session/heartbeat', { enabled })
      heartbeatEnabled.value = enabled
      saveConfig()
      if (enabled) {
        startHeartbeat()
      } else {
        stopHeartbeat()
      }
      showWarning.value = false
    } catch (err) {
      console.error('切换心跳失败:', err)
    }
  }

  // ---------- 活动追踪 ----------
  function onActivity() {
    lastRequestAt.value = Date.now()
    showWarning.value = false
    scheduleWarning()
  }

  // ---------- 超时警告 ----------
  function scheduleWarning() {
    if (warnTimer) clearTimeout(warnTimer)

    const idleMs = idleMinutes.value * 60 * 1000
    const elapsed = Date.now() - lastRequestAt.value
    const remain = idleMs - elapsed - WARN_BEFORE_TIMEOUT_MS

    if (remain <= 0) {
      showWarning.value = true
      return
    }

    warnTimer = window.setTimeout(() => {
      scheduleWarning()
    }, remain)
  }

  // ---------- 卸载通知 ----------
  function onBeforeUnload() {
    const token = localStorage.getItem('token')
    if (!token) return
    try {
      fetch('/api/session/close', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
        keepalive: true,
      })
    } catch {}
  }

  // ---------- 生命周期 ----------
  onMounted(() => {
    loadConfig()
    // 拉一次最新配置（管理员改动后最多一次 mount 感知）
    syncConfig()
    if (heartbeatEnabled.value) startHeartbeat()

    // 监听 http.ts 广播的活动事件
    window.addEventListener('astertrack:activity', onActivity)

    // 卸载通知
    window.addEventListener('beforeunload', onBeforeUnload)

    // 启动警告计时
    scheduleWarning()
  })

  onUnmounted(() => {
    stopHeartbeat()
    if (warnTimer) clearTimeout(warnTimer)
    window.removeEventListener('astertrack:activity', onActivity)
    window.removeEventListener('beforeunload', onBeforeUnload)
  })

  return {
    showWarning,
    idleMinutes,
    heartbeatEnabled,
    heartbeatInterval,
    toggleHeartbeat,
  }
}

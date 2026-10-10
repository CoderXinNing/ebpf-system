import { ref, onMounted, onUnmounted } from 'vue'
import http from '../api/http'

/**
 * useSession 会话管理（v4：去 banner）
 *
 * 设计：
 *   1. idle 由任何后端交互重置（API 请求 / 心跳）
 *   2. 心跳 = 用户显式开启的“自动交互”，每 N 秒发一次 keepalive
 *   3. 心跳关闭时，用户不操作 → 后端 idle 超时 → 401 → 跳登录页
 *   4. 前端不做超时预判，只看后端 401
 *
 * 与 v3 的差异：
 *   - 去掉 showWarning banner（同步问题多，直接后端 401 踢）
 *   - 去掉 lastRequestAt / activity 监听
 *   - 前端不再预测超时
 */
export function useSession() {
  const idleMinutes       = ref(10)
  const heartbeatEnabled  = ref(false)
  const heartbeatInterval = ref(180)  // 秒

  let heartbeatTimer: number | null = null

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
    syncConfig()
    heartbeatTimer = window.setInterval(async () => {
      try {
        await http.post('/session/keepalive')
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
    } catch (err) {
      console.error('切换心跳失败:', err)
    }
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
    syncConfig()
    if (heartbeatEnabled.value) startHeartbeat()
    window.addEventListener('beforeunload', onBeforeUnload)
  })

  onUnmounted(() => {
    stopHeartbeat()
    window.removeEventListener('beforeunload', onBeforeUnload)
  })

  return {
    idleMinutes,
    heartbeatEnabled,
    heartbeatInterval,
    toggleHeartbeat,
  }
}

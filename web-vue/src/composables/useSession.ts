import { ref, onMounted, onUnmounted } from 'vue'
import http from '@/api/http'

const HEARTBEAT_INTERVAL_MS   = 5 * 60 * 1000   // 心跳间隔：5 分钟
const ACTIVITY_CHECK_MS       = 30 * 1000       // 空闲检查：30 秒
const WARN_BEFORE_TIMEOUT_MS  = 60 * 1000       // 超时前 1 分钟警告
const ACTIVITY_EVENTS = ['mousemove', 'keydown', 'click', 'scroll', 'touchstart']

// 多标签同步通道（同源同页面共享）
const channel: BroadcastChannel | null =
  typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel('astertrack_session') : null

let visibleTabs = 0

/**
 * useSession 会话管理
 *
 * 职责：
 *   1. 跟踪用户活动（滑动续期由后端 Touch 完成，前端只判 idle 警告）
 *   2. 页面可见时定时心跳（POST /session/keepalive）
 *   3. 多标签页协同：只在至少一个标签可见时发心跳
 *   4. 页面卸载时通知后端（best-effort）
 *   5. idle 超时前 1 分钟弹警告
 */
export function useSession() {
  const lastActivityAt = ref(Date.now())
  const idleMinutes    = ref(10)   // 从 localStorage.session 读，登录时写入
  const keepalive      = ref(false)
  const showWarning    = ref(false)

  let heartbeatTimer: number | null = null
  let activityTimer:  number | null = null

  // ---------- 配置加载 ----------
  function loadConfig() {
    const raw = localStorage.getItem('session')
    if (!raw) return
    try {
      const cfg = JSON.parse(raw)
      idleMinutes.value = cfg.idle_minutes || 10
      keepalive.value = cfg.keepalive || false
    } catch {}
  }

  // ---------- 活动追踪 ----------
  function onActivity() {
    lastActivityAt.value = Date.now()
    showWarning.value = false
  }

  // ---------- 心跳 ----------
  function startHeartbeat() {
    if (heartbeatTimer) return
    heartbeatTimer = window.setInterval(async () => {
      try {
        await http.post('/session/keepalive')
      } catch {
        // 401 由 http.ts 拦截器处理（跳登录页）
      }
    }, HEARTBEAT_INTERVAL_MS)
  }

  function stopHeartbeat() {
    if (heartbeatTimer) {
      clearInterval(heartbeatTimer)
      heartbeatTimer = null
    }
  }

  // ---------- 空闲检查 ----------
  function checkIdle() {
    const idleMs = idleMinutes.value * 60 * 1000
    const elapsed = Date.now() - lastActivityAt.value
    // 超时前 1 分钟警告
    if (elapsed > idleMs - WARN_BEFORE_TIMEOUT_MS) {
      showWarning.value = true
    }
    // 实际超时由后端判定（下次请求返回 401），前端不主动踢
  }

  // ---------- 卸载通知 ----------
  function onBeforeUnload() {
    const token = localStorage.getItem('token')
    if (!token) return
    // fetch keepalive 允许页面卸载后继续请求
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

    // 活动监听
    ACTIVITY_EVENTS.forEach((evt) =>
      window.addEventListener(evt, onActivity, { passive: true })
    )

    // 页面可见性
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') {
        visibleTabs++
        startHeartbeat()
        channel?.postMessage('visible')
      } else {
        visibleTabs = Math.max(0, visibleTabs - 1)
        // 只有无任何可见标签时才停
        if (visibleTabs === 0) {
          stopHeartbeat()
          channel?.postMessage('hidden')
        }
      }
    })

    // 多标签同步
    if (channel) {
      channel.onmessage = (e) => {
        if (e.data === 'visible') {
          startHeartbeat()
        } else if (e.data === 'hidden') {
          // 其他标签隐藏了，若本标签也隐藏才停（简化：不做复杂协调）
        }
      }
    }

    // 卸载
    window.addEventListener('beforeunload', onBeforeUnload)

    // 定时检查
    activityTimer = window.setInterval(checkIdle, ACTIVITY_CHECK_MS)

    // 初始启动
    if (document.visibilityState === 'visible') {
      visibleTabs = 1
      startHeartbeat()
    }
  })

  onUnmounted(() => {
    stopHeartbeat()
    if (activityTimer) clearInterval(activityTimer)
    ACTIVITY_EVENTS.forEach((evt) =>
      window.removeEventListener(evt, onActivity)
    )
    window.removeEventListener('beforeunload', onBeforeUnload)
  })

  return { showWarning, idleMinutes, keepalive }
}

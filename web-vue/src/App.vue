<template>
  <n-config-provider :theme="isDark ? darkTheme : lightTheme">
    <n-message-provider>
      <router-view v-if="isLoginPage" />
      <n-layout v-else :style="{ minHeight: '100vh', background: isDark ? '#18181c' : '#f5f5f5' }">
        <n-layout-header bordered style="padding: 12px 24px !important; background: #fff !important">
          <n-space align="center" justify="space-between">
            <n-space align="center">
              <n-h3 style="margin: 0; white-space: nowrap; color: #1e3a5f !important">AsterTrack</n-h3>
              <div style="color: #fff">
                <n-menu mode="horizontal" :options="menuOptions" :value="currentPath" @update:value="handleMenu"
                  style="overflow-x: auto; max-width: 50vw" />
              </div>
            </n-space>
            <n-space align="center">
              <n-input
                v-model:value="globalSearch"
                placeholder="搜索主机/IP/告警..."
                size="small"
                style="width: 220px"
                clearable
                @keyup.enter="handleGlobalSearch"
              />
              <n-popover trigger="click" placement="bottom-end" style="width: 320px">
                <template #trigger>
                  <n-badge :value="notifications.length" :max="99" :show="notifications.length > 0">
                    <n-button size="small" quaternary>🔔</n-button>
                  </n-badge>
                </template>
                <div class="notify-panel">
                  <div class="notify-title">通知</div>
                  <n-empty v-if="notifications.length === 0" description="暂无通知" size="small" />
                  <n-list v-else>
                    <n-list-item v-for="(n, idx) in notifications.slice(0, 10)" :key="idx">
                      <n-space vertical :size="2">
                        <n-text strong style="font-size: 13px">🚨 {{ n.rule_name }}</n-text>
                        <n-text depth="3" style="font-size: 12px">{{ n.comm }} (PID: {{ n.pid }})</n-text>
                      </n-space>
                    </n-list-item>
                  </n-list>
                </div>
              </n-popover>
              <n-button size="small" @click="isDark = !isDark">
                {{ isDark ? '🌞' : '🌙' }}
              </n-button>
              <n-text>{{ username }}</n-text>
              <n-button size="small" @click="handleLogout">退出</n-button>
            </n-space>
          </n-space>
        </n-layout-header>
        <n-layout-content :style="{ background: isDark ? '#18181c' : '#f5f5f5', minHeight: 'calc(100vh - 60px)' }">
          <router-view v-slot="{ Component }">
            <transition name="fade" mode="out-in">
              <component :is="Component" />
            </transition>
          </router-view>
        </n-layout-content>
      </n-layout>
    </n-message-provider>
  </n-config-provider>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { connectWS, onWSMessage } from './api/ws'
import { useRoute, useRouter } from 'vue-router'
import { NConfigProvider, NMessageProvider, NLayout, NLayoutHeader, NLayoutContent, NSpace, NH3, NMenu, NButton, NText, darkTheme, lightTheme, NBadge, NPopover, NList, NListItem, NEmpty, NInput } from 'naive-ui'

const route = useRoute()
const router = useRouter()
const isDark = ref(false)
const notifications = ref<any[]>([])
const globalSearch = ref('')

function handleGlobalSearch() {
  if (!globalSearch.value.trim()) return
  router.push(`/star?corr_id=${globalSearch.value.trim()}`)
}

const isLoginPage = computed(() => route.path === '/login')
const username = computed(() => {
  const user = localStorage.getItem('user')
  if (user) {
    try {
      return JSON.parse(user).username
    } catch {}
  }
  return ''
})

const menuOptions = [
  { label: '仪表盘', key: '/dashboard' },
  { label: '攻击链', key: '/star' },
  { label: '告警', key: '/alerts' },
  { label: '白名单', key: '/whitelist' },
]

onMounted(() => {
  connectWS()
  onWSMessage('new_alert', (data) => {
    notifications.value.unshift(data)
    if (notifications.value.length > 50) {
      notifications.value = notifications.value.slice(0, 50)
    }
  })
})

const currentPath = computed(() => route.path)

function handleMenu(key: string) {
  router.push(key)
}

function handleLogout() {
  localStorage.removeItem('token')
  localStorage.removeItem('user')
  router.push('/login')
}
</script>

<style>
/* 导航栏菜单强制白色 */
.n-layout-header :deep(.n-menu-item) {
  color: #fff !important;
}

.n-layout-header :deep(.n-menu-item:hover) {
  color: #fff !important;
}

.n-layout-header :deep(.n-menu-item.n-menu-item--active) {
  color: #fff !important;
}

:root {
  --brand-primary: #1e3a5f;
  --brand-secondary: #2d5a8e;
  --brand-accent: #38bdf8;
  --brand-success: #10b981;
  --brand-warning: #f59e0b;
  --brand-danger: #ef4444;
  --radius-md: 8px;
  --shadow-sm: 0 1px 3px rgba(0,0,0,0.08);
  --shadow-md: 0 4px 12px rgba(0,0,0,0.1);
}

@media (max-width: 768px) {
  .n-layout-header {
    padding: 8px 12px !important;
  }
  .n-h3 {
    font-size: 16px !important;
  }
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

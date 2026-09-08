<template>
  <n-config-provider :theme="isDark ? darkTheme : null">
    <n-message-provider>
      <router-view v-if="isLoginPage" />
      <n-layout v-else :style="{ minHeight: '100vh', background: isDark ? '#18181c' : '#f5f5f5' }">
        <n-layout-header bordered style="padding: 12px 24px; background: isDark ? '#242428' : '#fff'">
          <n-space align="center" justify="space-between">
            <n-space align="center">
              <n-h3 style="margin: 0; white-space: nowrap">AsterTrack</n-h3>
              <n-menu mode="horizontal" :options="menuOptions" :value="currentPath" @update:value="handleMenu"
                style="overflow-x: auto; max-width: 50vw" />
            </n-space>
            <n-space align="center">
              <n-button size="small" @click="isDark = !isDark">
                {{ isDark ? '🌞 浅色' : '🌙 深色' }}
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
import { connectWS } from './api/ws'
import { useRoute, useRouter } from 'vue-router'
import { NConfigProvider, NMessageProvider, NLayout, NLayoutHeader, NLayoutContent, NSpace, NH3, NMenu, NButton, NText, darkTheme } from 'naive-ui'

const route = useRoute()
const router = useRouter()
const isDark = ref(false)

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

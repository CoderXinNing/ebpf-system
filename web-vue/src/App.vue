<template>
  <n-config-provider>
    <n-message-provider>
      <router-view v-if="isLoginPage" />
      <n-layout v-else>
        <n-layout-header bordered style="padding: 12px 24px">
          <n-space align="center" justify="space-between">
            <n-space align="center">
              <n-h3 style="margin: 0">AsterTrack</n-h3>
              <n-menu mode="horizontal" :options="menuOptions" :value="currentPath" @update:value="handleMenu" />
            </n-space>
            <n-space align="center">
              <n-text>{{ username }}</n-text>
              <n-button size="small" @click="handleLogout">退出</n-button>
            </n-space>
          </n-space>
        </n-layout-header>
        <n-layout-content>
          <router-view />
        </n-layout-content>
      </n-layout>
    </n-message-provider>
  </n-config-provider>
</template>

<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { connectWS } from './api/ws'
import { useRoute, useRouter } from 'vue-router'
import { NConfigProvider, NMessageProvider, NLayout, NLayoutHeader, NLayoutContent, NSpace, NH3, NMenu, NButton, NText } from 'naive-ui'

const route = useRoute()
const router = useRouter()

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

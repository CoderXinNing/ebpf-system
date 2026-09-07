<template>
  <n-config-provider>
    <n-message-provider>
      <n-layout>
        <n-layout-header bordered style="padding: 12px 24px">
          <n-space align="center" justify="space-between">
            <n-space align="center">
              <n-h3 style="margin: 0">AsterTrack</n-h3>
              <n-menu mode="horizontal" :options="menuOptions" :value="currentPath" @update:value="handleMenu" />
            </n-space>
            <n-button size="small" @click="handleLogout">退出</n-button>
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
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { NConfigProvider, NMessageProvider, NLayout, NLayoutHeader, NLayoutContent, NSpace, NH3, NMenu, NButton } from 'naive-ui'

const route = useRoute()
const router = useRouter()

const menuOptions = [
  { label: '仪表盘', key: '/dashboard' },
  { label: '攻击链', key: '/star' },
  { label: '告警', key: '/alerts' },
]

const currentPath = computed(() => route.path)

function handleMenu(key: string) {
  router.push(key)
}

function handleLogout() {
  localStorage.removeItem('token')
  router.push('/login')
}
</script>

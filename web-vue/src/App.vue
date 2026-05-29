<template>
  <n-config-provider :theme="darkTheme" :theme-overrides="themeOverrides">
    <n-dialog-provider>
      <n-message-provider>
      <div v-if="!authStore.isLoggedIn">
        <login-view />
      </div>
      <div v-else class="layout">
        <n-layout has-sider>
          <n-layout-sider bordered :width="220">
            <div class="logo">🛡️ Sentinel</div>
            <n-menu :value="currentRoute" :options="menuOptions" @update:value="goRoute" />
          </n-layout-sider>
          <n-layout>
            <n-layout-header bordered class="topbar">
              <n-space align="center" justify="end" style="padding-right:24px">
                <n-tag>{{ authStore.user?.username }}</n-tag>
                <n-tag type="info">{{ authStore.user?.role }}</n-tag>
                <n-button size="small" @click="logout">退出</n-button>
              </n-space>
            </n-layout-header>
            <n-layout-content>
              <router-view v-slot="{ Component }">
                <keep-alive>
                  <component :is="Component" />
                </keep-alive>
              </router-view>
            </n-layout-content>
          </n-layout>
        </n-layout>
      </div>
    </n-message-provider>
    </n-dialog-provider>
  </n-config-provider>
</template>

<script setup>
import { computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from './stores/auth'
import { darkTheme } from 'naive-ui'
import LoginView from './views/LoginView.vue'

const authStore = useAuthStore()
const router = useRouter()
const route = useRoute()

const currentRoute = computed(() => route.path)

const menuOptions = [
  { label: '仪表盘', key: '/', icon: renderIcon('📊') },
  { label: '事件流', key: '/events', icon: renderIcon('📡') },
  { label: '部署探针', key: '/deploy', icon: renderIcon('📦') },
]

if (authStore.user?.role === 'admin') {
  menuOptions.push({ label: '用户管理', key: '/users', icon: renderIcon('👥') })
}

function renderIcon(icon) { return () => icon }
function goRoute(key) { router.push(key) }
function logout() { authStore.logout(); router.push('/login') }

const themeOverrides = {
  common: { bodyColor: '#101014', cardColor: '#1a1a20', inputColor: '#121218', borderColor: '#2a2a35' }
}
</script>

<style>
body { margin: 0; background: #101014; }
.logo { padding: 20px; font-size: 18px; font-weight: 700; color: #18c08c; text-align: center; }
.topbar { height: 52px; display: flex; align-items: center; justify-content: flex-end; }
.n-layout-content { padding: 24px; min-height: calc(100vh - 52px); }
</style>

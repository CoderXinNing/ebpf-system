<template>
  <div class="admin-layout">
    <!-- 侧边栏 -->
    <aside class="sidebar" :class="{ collapsed }">
      <div class="logo-area" @click="collapsed = !collapsed">
        <div class="logo-icon">🐝</div>
        <span v-if="!collapsed" class="logo-text">Sentinel</span>
      </div>

      <nav class="nav-menu">
        <div
          v-for="item in menu"
          :key="item.key"
          class="nav-item"
          :class="{ active: isActive(item.key) }"
          @click="go(item.key)"
        >
          <span class="nav-icon">{{ item.icon }}</span>
          <span v-if="!collapsed" class="nav-label">{{ item.label }}</span>
        </div>
      </nav>
    </aside>

    <!-- 右侧主区 -->
    <div class="main-area">
      <!-- 顶栏 -->
      <header class="topbar">
        <div class="page-title">{{ pageTitle }}</div>
        <div class="user-area">
          <span class="username">{{ username }}</span>
          <span class="logout" @click="logout">退出</span>
        </div>
      </header>

      <!-- 内容区 -->
      <main class="content">
        <slot />
      </main>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'

const router = useRouter()
const route = useRoute()
const collapsed = ref(false)

const menu = [
  { label: '仪表盘', key: '/', icon: '📊' },
  { label: '主机管理', key: '/hosts', icon: '🖥️' },
  { label: '事件流', key: '/events', icon: '📡' },
  { label: '告警中心', key: '/alerts', icon: '🚨' },
  { label: '资产清点', key: '/processes', icon: '📦' },
  { label: '探针管理', key: '/probes', icon: '🔧' },
]

const titleMap = {
  '/': '仪表盘',
  '/hosts': '主机管理',
  '/events': '事件流',
  '/alerts': '告警中心',
  '/processes': '资产清点',
  '/probes': '探针管理',
}

const pageTitle = computed(() => titleMap[route.path] || 'eBPF Sentinel')

function isActive(key) {
  if (key === '/') return route.path === '/'
  return route.path.startsWith(key)
}

function go(key) {
  router.push(key)
}

function logout() {
  localStorage.clear()
  router.push('/login')
}

const user = JSON.parse(localStorage.getItem('user') || '{}')
const username = computed(() => user.username || 'admin')
</script>

<style scoped>
.admin-layout {
  display: flex;
  width: 100vw;
  height: 100vh;
  background: #E8EDF4;
  overflow: hidden;
}

/* 侧边栏 */
.sidebar {
  width: 14vw;
  min-width: 180px;
  max-width: 240px;
  background: linear-gradient(180deg, #001529 0%, #002B5C 100%);
  display: flex;
  flex-direction: column;
  transition: width 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  flex-shrink: 0;
}

.sidebar.collapsed {
  width: 5vw;
  min-width: 60px;
}

.logo-area {
  display: flex;
  align-items: center;
  gap: 0.8vw;
  padding: 2vh 1vw;
  cursor: pointer;
}

.logo-icon {
  font-size: 1.8vw;
  flex-shrink: 0;
}

.logo-text {
  color: #FFFFFF;
  font-size: 1.1vw;
  font-weight: 600;
  white-space: nowrap;
}

.nav-menu {
  flex: 1;
  padding: 1.5vh 0.6vw;
  display: flex;
  flex-direction: column;
  gap: 0.2vh;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 0.8vw;
  padding: 1.2vh 0.8vw;
  border-radius: 0.4vw;
  cursor: pointer;
  color: #B8C7D9;
  transition: background 0.25s, color 0.25s;
}

.nav-item:hover {
  background: rgba(255, 255, 255, 0.06);
  color: #FFFFFF;
}

.nav-item.active {
  background: rgba(26, 115, 232, 0.25);
  color: #FFFFFF;
}

.nav-icon {
  font-size: 1.2vw;
  flex-shrink: 0;
}

.nav-label {
  font-size: 0.95vw;
  white-space: nowrap;
}

/* 右侧主区 */
.main-area {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.topbar {
  height: 6vh;
  min-height: 48px;
  background: #FFFFFF;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 1vw;
  box-shadow: 0 1px 2px rgba(0,0,0,0.03);
  flex-shrink: 0;
}

.page-title {
  font-size: 1.1vw;
  font-weight: 600;
  color: #202124;
}

.user-area {
  display: flex;
  align-items: center;
  gap: 1vw;
}

.username {
  font-size: 0.9vw;
  color: #5F6368;
}

.logout {
  font-size: 0.9vw;
  color: #1A73E8;
  cursor: pointer;
}

.logout:hover {
  text-decoration: underline;
}

/* 内容区 */
.content {
  flex: 1;
  overflow-y: auto;
  padding: 0.5vh 0.5vw;
}
</style>

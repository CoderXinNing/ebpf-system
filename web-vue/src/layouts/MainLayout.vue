<template>
  <div class="admin-layout">
    <!-- 侧边栏 -->
    <aside class="sidebar" :class="{ collapsed }">
      <div class="logo-area" @click="collapsed = !collapsed">
        <div class="logo-icon">🐝</div>
        <span v-if="!collapsed" class="logo-text">Sentinel</span>
      </div>

      <nav class="nav-menu">
        <template v-for="item in menu" :key="item.key">
          <!-- 有子菜单 -->
          <div v-if="item.children" class="nav-group">
            <div
              class="nav-item"
              :class="{ active: isGroupActive(item) }"
              @click="toggleGroup(item.key)"
            >
              <span class="nav-icon">{{ item.icon }}</span>
              <span v-if="!collapsed" class="nav-label">{{ item.label }}</span>
              <span v-if="!collapsed" class="nav-arrow" :class="{ open: openGroups.includes(item.key) }">▾</span>
            </div>
            <div v-if="!collapsed && openGroups.includes(item.key)" class="nav-children">
              <div
                v-for="child in item.children"
                :key="child.key"
                class="nav-item child"
                :class="{ active: isActive(child.key) }"
                @click="go(child.key)"
              >
                <span class="nav-icon">{{ child.icon }}</span>
                <span class="nav-label">{{ child.label }}</span>
              </div>
            </div>
          </div>

          <!-- 无子菜单 -->
          <div
            v-else
            class="nav-item"
            :class="{ active: isActive(item.key) }"
            @click="go(item.key)"
          >
            <span class="nav-icon">{{ item.icon }}</span>
            <span v-if="!collapsed" class="nav-label">{{ item.label }}</span>
          </div>
        </template>
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
import { computed, ref, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'

const router = useRouter()
const route = useRoute()
const collapsed = ref(false)
const openGroups = ref([])

const menu = [
  { label: '仪表盘', key: '/', icon: '📊' },
  {
    label: '资产管理',
    key: 'asset',
    icon: '📦',
    children: [
      { label: '主机管理', key: '/hosts', icon: '🖥️' },
      { label: '资产清点', key: '/processes', icon: '📋' },
    ],
  },
  {
    label: '分析中心',
    key: 'analysis',
    icon: '📊',
    children: [
      { label: '事件流', key: '/events', icon: '📡' },
      { label: '告警中心', key: '/alerts', icon: '🚨' },
    ],
  },
  {
    label: 'Agent管理',
    key: 'agent',
    icon: '🤖',
    children: [
      { label: 'Agent部署', key: '/install', icon: '📥' },
      { label: 'eBPF探针下发', key: '/probes', icon: '🔧' },
    ],
  },
  {
    label: '系统设置',
    key: 'system',
    icon: '⚙️',
    children: [
      { label: '用户管理', key: '/users', icon: '👤' },
      { label: '系统日志', key: '/logs', icon: '📋' },
      { label: '日志管理', key: '/log-settings', icon: '⚙️' },
      { label: '时间设置', key: '/time-settings', icon: '🕐' },
      { label: '个性化', key: '/personalize', icon: '🎨' },
      { label: '关于系统', key: '/about', icon: 'ℹ️' },
    ],
  },
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

function isGroupActive(group) {
  return group.children.some(child => isActive(child.key))
}

function toggleGroup(key) {
  const idx = openGroups.value.indexOf(key)
  if (idx >= 0) {
    openGroups.value.splice(idx, 1)
  } else {
    openGroups.value.push(key)
  }
}

// 监听路由变化，自动展开当前分组
// 记录页面访问日志
watch(() => route.path, () => {
  const token = localStorage.getItem('token')
  if (token) {
    fetch('/api/system/page-visit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body: JSON.stringify({ page: route.path })
    }).catch(() => {})
  }
})

watch(() => route.path, () => {
  menu.forEach(item => {
    if (item.children && isGroupActive(item)) {
      if (!openGroups.value.includes(item.key)) {
        openGroups.value.push(item.key)
      }
    }
  })
}, { immediate: true })

// 详情页等子路由也要保持父分组展开
// 记录页面访问日志
watch(() => route.path, () => {
  const token = localStorage.getItem('token')
  if (token) {
    fetch('/api/system/page-visit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body: JSON.stringify({ page: route.path })
    }).catch(() => {})
  }
})

watch(() => route.path, () => {
  menu.forEach(item => {
    if (item.children) {
      const isChildRoute = item.children.some(child => {
        if (child.key === '/hosts') return route.path.startsWith('/host')
        if (child.key === '/processes') return route.path.startsWith('/proc')
        return route.path.startsWith(child.key)
      })
      if (isChildRoute && !openGroups.value.includes(item.key)) {
        openGroups.value.push(item.key)
      }
    }
  })
}, { immediate: true })

function go(key) {
  router.push(key)
}

async function logout() {
  const token = localStorage.getItem('token')
  try {
    await fetch('/api/logout', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token }
    })
  } catch (e) {
    // 忽略
  }
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

.nav-arrow {
  margin-left: auto;
  font-size: 0.7vw;
  transition: transform 0.3s;
}

.nav-arrow.open {
  transform: rotate(180deg);
}

.nav-children {
  padding-left: 1vw;
  display: flex;
  flex-direction: column;
  gap: 0.2vh;
}

.nav-item.child {
  padding-left: 0.8vw;
}

.nav-item.child .nav-label {
  font-size: 0.85vw;
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

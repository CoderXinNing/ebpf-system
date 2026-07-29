<template>
  <div style="display:flex;height:100vh;overflow:hidden">
    <!-- 侧边栏：固定不动 -->
    <div style="width:200px;flex-shrink:0;background:#161b22;border-right:1px solid #30363d;display:flex;flex-direction:column;overflow-y:auto">
      <div class="logo">Sentinel</div>
      <n-menu :value="path" :options="menu" @update:value="go" style="flex:1" />
    </div>

    <!-- 右侧：顶栏固定 + 内容区滚动 -->
    <div style="flex:1;display:flex;flex-direction:column;overflow:hidden;background:#0d1117">
      <!-- 顶栏：固定不动 -->
      <div class="topbar">
        <div class="topbar-left">{{ pageTitle }}</div>
        <div class="topbar-right">
          <n-button text size="small" style="font-size:18px;margin-right:12px" @click="showNotify=true">🔔</n-button>
          <n-avatar round size="small" style="background:#58a6ff;margin-right:6px">{{ initial }}</n-avatar>
          <span style="font-size:13px;color:#c9d1d9;margin-right:12px">{{ username }}</span>
          <n-button text size="small" @click="logout">退出</n-button>
        </div>
      </div>
      <!-- 内容区：独立滚动，不影响侧边栏和顶栏 -->
      <div style="flex:1;overflow-y:auto;padding:20px">
        <slot />
      </div>
    </div>
  </div>

  <n-modal v-model:show="showNotify" title="通知" style="width:400px" preset="card" :bordered="false">
    <n-empty description="暂无通知" />
  </n-modal>
</template>

<script setup>
import { computed, ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'

const router = useRouter()
const route = useRoute()
const path = computed(() => route.path)
const showNotify = ref(false)

const menu = [
  { label: '资产清点', key: '/' },
  { label: '进程端口', key: '/processes' },
  { label: 'Web资产', key: '/web' },
    { label: '软件应用', key: '/packages' },
  { label: '事件流', key: '/events' },
  { label: '探针管理', key: '/probes' },
]

const titleMap = {
  '/': '资产清点', '/processes': '进程端口', '/web': 'Web资产',
  '/events': '事件流', '/probes': '探针管理'
}
const pageTitle = computed(() => {
  if (route.path.startsWith('/host')) return '主机详情'
  return titleMap[route.path] || 'eBPF Sentinel'
})

const user = JSON.parse(localStorage.getItem('user') || '{}')
const username = computed(() => user.username || 'admin')
const initial = computed(() => (user.username || 'A')[0].toUpperCase())

function go(key) { router.push(key) }
function logout() { localStorage.clear(); router.push('/login') }
</script>

<style>
.logo { padding: 18px 20px; font-size: 17px; font-weight: 700; color: #58a6ff; border-bottom: 1px solid #30363d; }
.topbar {
  height: 48px; display: flex; align-items: center; justify-content: space-between;
  padding: 0 20px; background: #161b22; border-bottom: 1px solid #30363d; flex-shrink: 0;
}
.topbar-left { font-size: 15px; font-weight: 600; color: #c9d1d9; }
.topbar-right { display: flex; align-items: center; }
</style>

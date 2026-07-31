<template>
  <div style="display:flex;height:100vh;overflow:hidden">
    <!-- 侧边栏 -->
    <div :style="{width: collapsed ? '64px' : '220px', flexShrink:0, background:'linear-gradient(180deg, #001529 0%, #002140 100%)', display:'flex', flexDirection:'column', transition:'width .2s'}">
      <div style="padding:16px 16px;display:flex;align-items:center;gap:8px;cursor:pointer" @click="collapsed=!collapsed">
        <div style="width:32px;height:32px;background:#1e6fff;border-radius:6px;display:flex;align-items:center;justify-content:center;color:#fff;font-size:18px;flex-shrink:0">🛡</div>
        <span v-if="!collapsed" style="color:#fff;font-size:16px;font-weight:600;white-space:nowrap">Sentinel</span>
      </div>
      <n-menu :value="path" :options="menu" @update:value="go" :collapsed="collapsed"
        :theme-overrides="{ itemColorActive: 'rgba(30,111,255,0.2)', itemTextColor: '#b8c7d9', itemTextColorActive: '#fff' }" />
    </div>

    <!-- 右侧 -->
    <div style="flex:1;display:flex;flex-direction:column;overflow:hidden;background:#f0f2f5;min-width:0">
      <div style="height:52px;display:flex;align-items:center;justify-content:space-between;padding:0 24px;background:#fff;border-bottom:1px solid #e4e7ed;flex-shrink:0">
        <div style="font-size:15px;font-weight:600;color:#1d2129">{{ pageTitle }}</div>
        <div style="display:flex;align-items:center;gap:16px">
          <span style="cursor:pointer;font-size:18px;color:#86909c" @click="showNotify=true">🔔</span>
          <n-avatar round size="small" style="background:#1e6fff;flex-shrink:0">{{ initial }}</n-avatar>
          <span style="font-size:13px;color:#4e5969" class="hide-mobile">{{ username }}</span>
          <span style="color:#e4e7ed" class="hide-mobile">|</span>
          <span style="cursor:pointer;font-size:13px;color:#86909c" class="hide-mobile" @click="logout">退出</span>
        </div>
      </div>
      <div style="flex:1;overflow-y:auto;padding:20px 24px">
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
const collapsed = ref(false)
const showNotify = ref(false)

const menu = [
  { label: '资产清点', key: '/' },
    { label: '主机管理', key: '/hosts' },
  { label: '端口服务', key: '/processes' },
    { label: '进程聚合', key: '/proc_agg' },
  { label: 'Web资产', key: '/web' },
  { label: '软件应用', key: '/packages' },
  { label: '事件流', key: '/events' },
    { label: 'Agent管理', key: 'agent', children: [
      { label: 'Agent列表', key: '/probes' },
      { label: '安装Agent', key: '/install' },
    ] },
]

const titleMap = {
  '/': '资产清点', '/processes': '进程端口', '/web': 'Web资产',
  '/packages': '软件应用', '/events': '事件流', '/probes': '探针管理'
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
@media (max-width: 768px) {
  .hide-mobile { display: none !important; }
}
</style>

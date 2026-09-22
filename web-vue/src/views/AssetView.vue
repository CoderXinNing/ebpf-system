<template>
  <div class="asset-page">
    <!-- 左侧：主机列表 -->
    <div class="host-panel">
      <div class="panel-header">
        <n-input v-model:value="hostKeyword" placeholder="搜索主机" size="small" clearable />
      </div>
      <div class="host-list">
        <div
          v-for="host in filteredHosts"
          :key="host.id"
          class="host-item"
          :class="{ active: selectedHost?.id === host.id }"
          @click="selectHost(host)"
        >
          <div class="host-item-top">
            <span class="host-name">{{ host.hostname }}</span>
            <span class="host-status" :class="isOnline(host) ? 'online' : 'offline'"></span>
          </div>
          <div class="host-item-bottom">
            <span class="host-ip">{{ host.ip_addr }}</span>
            <span class="host-probes">{{ host.active_probes }} 探针</span>
          </div>
        </div>
        <n-empty v-if="filteredHosts.length === 0" description="无主机" size="small" style="margin-top: 40px" />
      </div>
    </div>

    <!-- 右侧：主机详情 -->
    <div class="asset-panel">
      <template v-if="selectedHost">
        <!-- 顶部信息栏 -->
        <div class="asset-header">
          <div class="asset-header-left">
            <h3 style="margin: 0">{{ selectedHost.hostname }}</h3>
            <n-tag :type="isOnline(selectedHost) ? 'success' : 'default'" size="small" round>
              {{ isOnline(selectedHost) ? '在线' : '离线' }}
            </n-tag>
            <n-tag size="small">{{ selectedHost.ip_addr }}</n-tag>
            <n-tag size="small" type="info">{{ selectedHost.capability_level || 'unknown' }}</n-tag>
          </div>
          <div class="asset-header-right">
            <n-button size="small" @click="reloadAll">刷新</n-button>
          </div>
        </div>

        <!-- Tab 切换 -->
        <div class="tabs-wrapper">
        <n-tabs v-model:value="mainTab" type="line" animated style="height: 100%">
          <!-- 概览 -->
          <n-tab-pane name="overview" tab="概览" style="padding: 16px; overflow-y: auto">
            <n-descriptions :column="2" bordered size="small">
              <n-descriptions-item label="Agent ID">{{ selectedHost.id }}</n-descriptions-item>
              <n-descriptions-item label="主机名">{{ selectedHost.hostname }}</n-descriptions-item>
              <n-descriptions-item label="IP 地址">{{ selectedHost.ip_addr }}</n-descriptions-item>
              <n-descriptions-item label="版本">{{ selectedHost.version }}</n-descriptions-item>
              <n-descriptions-item label="能力层级">{{ selectedHost.capability_level }}</n-descriptions-item>
              <n-descriptions-item label="探针数">{{ selectedHost.active_probes }}</n-descriptions-item>
              <n-descriptions-item label="最后心跳" :span="2">{{ formatTime(selectedHost.last_seen) }}</n-descriptions-item>
            </n-descriptions>

            <n-divider style="margin: 16px 0">探针状态</n-divider>
            <n-space vertical :size="8">
              <div v-for="probe in probes" :key="probe.name" class="probe-row">
                <n-space justify="space-between" align="center">
                  <n-text>{{ probe.name }}</n-text>
                  <n-tag :type="probe.loaded ? 'success' : 'error'" round size="small">
                    {{ probe.loaded ? '运行中' : '未加载' }}
                  </n-tag>
                </n-space>
              </div>
            </n-space>
          </n-tab-pane>

          <!-- 资产 -->
          <n-tab-pane name="assets" tab="资产" style="padding: 0; overflow: hidden">
            <div class="stat-row">
              <div class="stat-item" :class="{ active: assetTab === 'process' }" @click="assetTab = 'process'">
                <div class="stat-num">{{ assetCounts.process }}</div>
                <div class="stat-label">进程</div>
              </div>
              <div class="stat-item" :class="{ active: assetTab === 'user' }" @click="assetTab = 'user'">
                <div class="stat-num">{{ assetCounts.user }}</div>
                <div class="stat-label">用户</div>
              </div>
              <div class="stat-item" :class="{ active: assetTab === 'package' }" @click="assetTab = 'package'">
                <div class="stat-num">{{ assetCounts.package }}</div>
                <div class="stat-label">软件包</div>
              </div>
              <div class="stat-item" :class="{ active: assetTab === 'service' }" @click="assetTab = 'service'">
                <div class="stat-num">{{ assetCounts.service }}</div>
                <div class="stat-label">服务</div>
              </div>
            </div>

            <div class="asset-search">
              <n-input v-model:value="assetKeyword" :placeholder="`搜索${tabLabel}...`" size="small" clearable style="width: 300px" />
              <n-text depth="3" style="font-size: 12px">共 {{ currentList.length }} 项</n-text>
            </div>

            <div class="asset-table">
              <n-data-table
                :columns="currentColumns"
                :data="filteredList"
                :loading="loading"
                :pagination="{ pageSize: 15 }"
                :bordered="false"
                size="small"
              />
            </div>
          </n-tab-pane>

          <!-- 告警 -->
          <n-tab-pane name="alerts" tab="最近告警" style="padding: 16px; overflow-y: auto">
            <n-data-table
              :columns="alertColumns"
              :data="recentAlerts"
              :loading="loading"
              :pagination="{ pageSize: 10 }"
              :bordered="false"
              size="small"
            />
          </n-tab-pane>

          <!-- 攻击链 -->
          <n-tab-pane name="chains" tab="攻击链" style="padding: 16px; overflow-y: auto">
            <n-empty v-if="starChains.length === 0" description="暂无攻击链" />
            <n-list v-else>
              <n-list-item v-for="corrId in starChains" :key="corrId">
                <div class="chain-row">
                  <n-text code style="font-size: 12px">{{ corrId }}</n-text>
                  <n-button size="small" type="primary" @click="goToStarChain(corrId)">查看</n-button>
                </div>
              </n-list-item>
            </n-list>
          </n-tab-pane>
        </n-tabs>
        </div>
      </template>
      <n-empty v-else description="请从左侧选择主机" style="margin: auto" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { NInput, NTag, NButton, NDataTable, NEmpty, NText, NTabs, NTabPane, NDescriptions, NDescriptionsItem, NDivider, NSpace, NList, NListItem } from 'naive-ui'
import http from '../api/http'
import { getAlerts, type AlertItem } from '../api/alert'

interface Host {
  id: string
  hostname: string
  ip_addr: string
  version: string
  active_probes: number
  capability_level: string
  last_seen: number
}

const route = useRoute()
const router = useRouter()

const hosts = ref<Host[]>([])
const selectedHost = ref<Host | null>(null)
const hostKeyword = ref('')
const assetKeyword = ref('')
const loading = ref(false)
const mainTab = ref('overview')
const assetTab = ref('process')

const assets = ref<any>({})
const recentAlerts = ref<AlertItem[]>([])
const starChains = ref<string[]>([])

const probes = ref([
  { name: 'exec_monitor', loaded: true },
  { name: 'bash_monitor', loaded: true },
  { name: 'tcp_monitor', loaded: true },
  { name: 'file_access', loaded: true },
  { name: 'xdp_reporter', loaded: true },
])

const alertColumns = [
  { title: '规则', key: 'rule_name' },
  { title: '严重度', key: 'severity', width: 100 },
  { title: '进程', key: 'comm', width: 120 },
  { title: '时间', key: 'detected_at', render(row: AlertItem) { return new Date(row.detected_at).toLocaleString('zh-CN', { hour12: false }) } },
]

const filteredHosts = computed(() => {
  if (!hostKeyword.value.trim()) return hosts.value
  const kw = hostKeyword.value.toLowerCase()
  return hosts.value.filter(h =>
    h.hostname.toLowerCase().includes(kw) || h.ip_addr.toLowerCase().includes(kw)
  )
})

const isOnline = (host: Host) => (Date.now() / 1000 - host.last_seen) < 120

const assetCounts = computed(() => ({
  process: Array.isArray(assets.value.process) ? assets.value.process.length : 0,
  user: Array.isArray(assets.value.user) ? assets.value.user.length : 0,
  package: assets.value.package ? Object.values(assets.value.package).reduce((s: number, v: any) => s + (Array.isArray(v) ? v.length : 0), 0) : 0,
  service: assets.value.service?.services?.length || 0,
}))

const tabLabel = computed(() => {
  const map: Record<string, string> = { process: '进程', user: '用户', package: '软件包', service: '服务' }
  return map[assetTab.value] || ''
})

const currentList = computed(() => {
  if (assetTab.value === 'process') return assets.value.process || []
  if (assetTab.value === 'user') return assets.value.user || []
  if (assetTab.value === 'service') return assets.value.service?.services || []
  if (assetTab.value === 'package') {
    const pkgs = assets.value.package || {}
    const all: any[] = []
    Object.entries(pkgs).forEach(([type, list]: [string, any]) => {
      if (Array.isArray(list)) {
        list.forEach(item => all.push({ ...item, _type: type }))
      }
    })
    return all
  }
  return []
})

const filteredList = computed(() => {
  if (!assetKeyword.value.trim()) return currentList.value
  const kw = assetKeyword.value.toLowerCase()
  return currentList.value.filter((item: any) =>
    JSON.stringify(item).toLowerCase().includes(kw)
  )
})

const processColumns = [
  { title: 'PID', key: 'pid', width: 80 },
  { title: '进程名', key: 'name', ellipsis: { tooltip: true } },
  { title: '用户', key: 'user', width: 100 },
  { title: '状态', key: 'state', width: 80 },
  { title: '命令行', key: 'cmdline', ellipsis: { tooltip: true } },
]

const userColumns = [
  { title: '用户名', key: 'username', width: 120 },
  { title: 'UID', key: 'uid', width: 80 },
  { title: 'Shell', key: 'shell', ellipsis: { tooltip: true } },
  { title: 'Home', key: 'home', ellipsis: { tooltip: true } },
]

const packageColumns = [
  { title: '类型', key: '_type', width: 120 },
  { title: '包名', key: 'name', ellipsis: { tooltip: true } },
  { title: '版本', key: 'version', width: 150, ellipsis: { tooltip: true } },
]

const serviceColumns = [
  { title: '服务名', key: 'name', ellipsis: { tooltip: true } },
  { title: '状态', key: 'status', width: 100 },
  { title: '运行用户', key: 'user', width: 120 },
]

const currentColumns = computed(() => {
  if (assetTab.value === 'process') return processColumns
  if (assetTab.value === 'user') return userColumns
  if (assetTab.value === 'package') return packageColumns
  if (assetTab.value === 'service') return serviceColumns
  return []
})

onMounted(async () => {
  await loadHosts()

  // 支持从 URL 参数指定主机
  const urlHostId = route.query.host as string
  let target: Host | null = null
  if (urlHostId) {
    target = hosts.value.find(h => h.id === urlHostId) || null
  }
  if (!target && hosts.value.length > 0) {
    target = hosts.value[0]
  }
  if (target) {
    await selectHost(target)
  }
})

async function loadHosts() {
  try {
    const { data } = await http.get('/agents')
    hosts.value = data.agents || []
  } catch (err) {
    console.error('加载主机失败:', err)
  }
}

async function selectHost(host: Host) {
  selectedHost.value = host
  await reloadAll()
}

async function reloadAll() {
  if (!selectedHost.value) return
  loading.value = true
  try {
    // 资产
    try {
      const { data } = await http.get(`/assets/${selectedHost.value.id}`)
      assets.value = data || {}
    } catch {
      assets.value = {}
    }

    // 告警
    const alerts = await getAlerts()
    recentAlerts.value = alerts.filter(a => a.agent_id === selectedHost.value!.id).slice(0, 10)
    starChains.value = [...new Set(recentAlerts.value.filter(a => a.correlation_id).map(a => a.correlation_id))]
  } catch (err) {
    console.error('加载失败:', err)
  } finally {
    loading.value = false
  }
}

function formatTime(ts: number): string {
  return new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false })
}

function goToStarChain(corrId: string) {
  router.push(`/star?corr_id=${corrId}`)
}
</script>

<style scoped>
.asset-page {
  display: flex;
  height: calc(100vh - 60px);
  background: #f5f7fa;
  padding: 12px;
  gap: 12px;
}

/* 左侧主机列表 */
.host-panel {
  flex: 0 0 260px;
  background: #fff;
  border-radius: 8px;
  display: flex;
  flex-direction: column;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.06);
  overflow: hidden;
}

.panel-header {
  padding: 10px 12px;
  border-bottom: 1px solid #e2e8f0;
}

.host-list {
  flex: 1;
  overflow-y: auto;
  padding: 4px;
}

.host-item {
  padding: 10px 12px;
  border-radius: 6px;
  cursor: pointer;
  margin-bottom: 2px;
  transition: background 0.15s;
}

.host-item:hover {
  background: #f1f5f9;
}

.host-item.active {
  background: #e0e7ff;
  border-left: 3px solid #4f46e5;
  padding-left: 9px;
}

.host-item-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 4px;
}

.host-name {
  font-weight: 600;
  font-size: 13px;
  color: #1e293b;
}

.host-status {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}

.host-status.online {
  background: #10b981;
  box-shadow: 0 0 6px rgba(16, 185, 129, 0.5);
}

.host-status.offline {
  background: #94a3b8;
}

.host-item-bottom {
  display: flex;
  justify-content: space-between;
  font-size: 11px;
  color: #64748b;
}

/* 右侧 */
.asset-panel {
  flex: 1;
  background: #fff;
  border-radius: 8px;
  display: flex;
  flex-direction: column;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.06);
  overflow: hidden;
}

.asset-header {
  padding: 12px 16px;
  border-bottom: 1px solid #e2e8f0;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.asset-header-left {
  display: flex;
  align-items: center;
  gap: 10px;
}

.asset-header-right {
  display: flex;
  gap: 8px;
}

.tabs-wrapper {
  flex: 1;
  overflow: hidden;
  padding: 0 16px;
}

.tabs-wrapper :deep(.n-tabs-nav) {
  padding: 0 16px;
  margin-left: -16px;
  margin-right: -16px;
}

.tabs-wrapper :deep(.n-tabs-pane-wrapper) {
  height: calc(100% - 40px);
  overflow: hidden;
}

.chain-row {
  display: flex;
  align-items: center;
  gap: 12px;
}

.probe-row {
  padding: 8px 12px;
  border-bottom: 1px solid #f1f5f9;
  background: #fafbfc;
  border-radius: 6px;
}

/* 资产统计 */
.stat-row {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 1px;
  background: #e2e8f0;
  border-bottom: 1px solid #e2e8f0;
}

.stat-item {
  background: #fff;
  padding: 16px;
  text-align: center;
  cursor: pointer;
  transition: all 0.2s;
}

.stat-item:hover {
  background: #f8fafc;
}

.stat-item.active {
  background: #eef2ff;
  border-bottom: 3px solid #4f46e5;
}

.stat-num {
  font-size: 24px;
  font-weight: 700;
  color: #1e293b;
  line-height: 1;
}

.stat-label {
  font-size: 12px;
  color: #64748b;
  margin-top: 6px;
}

.asset-search {
  padding: 12px 16px;
  display: flex;
  align-items: center;
  gap: 12px;
  border-bottom: 1px solid #e2e8f0;
}

.asset-table {
  flex: 1;
  overflow: auto;
  padding: 8px 16px;
}

.asset-table :deep(.n-data-table) {
  font-size: 12px;
}
</style>

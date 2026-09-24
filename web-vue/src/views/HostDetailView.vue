<template>
  <div class="host-detail-container">
    <n-card :title="`主机详情: ${hostname}`" bordered hoverable>
      <n-tabs type="line" animated>
        <n-tab-pane name="overview" tab="概览">
          <n-descriptions :column="2" bordered>
            <n-descriptions-item label="Agent ID">{{ agentId }}</n-descriptions-item>
            <n-descriptions-item label="主机名">{{ hostname }}</n-descriptions-item>
            <n-descriptions-item label="IP 地址">{{ ipAddr }}</n-descriptions-item>
            <n-descriptions-item label="版本">{{ version }}</n-descriptions-item>
            <n-descriptions-item label="能力层级">{{ capabilityLevel }}</n-descriptions-item>
            <n-descriptions-item label="探针数">{{ activeProbes }}</n-descriptions-item>
            <n-descriptions-item label="最后心跳">{{ lastSeen }}</n-descriptions-item>
          </n-descriptions>
        </n-tab-pane>

        <n-tab-pane name="probes" tab="探针状态">
          <n-data-table
            :columns="probeColumns"
            :data="probes"
            :pagination="false"
            :bordered="false"
            size="small"
          />
        </n-tab-pane>

        <n-tab-pane name="alerts" tab="最近告警">
          <n-data-table
            :columns="alertColumns"
            :data="recentAlerts"
            :loading="loading"
            :pagination="{ pageSize: 10 }"
            :bordered="false"
          />
        </n-tab-pane>

        <n-tab-pane name="assets" tab="资产">
          <n-tabs type="segment" animated>
            <n-tab-pane name="process" tab="进程">
              <n-data-table
                :columns="processColumns"
                :data="assets.process || []"
                :pagination="{ pageSize: 10 }"
                :bordered="false"
                size="small"
              />
            </n-tab-pane>
            <n-tab-pane name="user" tab="用户">
              <n-data-table
                :columns="userColumns"
                :data="assets.user || []"
                :pagination="{ pageSize: 10 }"
                :bordered="false"
                size="small"
              />
            </n-tab-pane>
            <n-tab-pane name="package" tab="软件包">
              <n-tabs type="line" animated size="small">
                <n-tab-pane name="pkg" tab="系统包">
                  <n-data-table :columns="pkgColumns" :data="assets.package?.packages || []" :pagination="{ pageSize: 10 }" size="small" :bordered="false" />
                </n-tab-pane>
                <n-tab-pane name="jar" tab="JAR">
                  <n-data-table :columns="pkgColumns" :data="assets.package?.jar_packages || []" :pagination="{ pageSize: 10 }" size="small" :bordered="false" />
                </n-tab-pane>
                <n-tab-pane name="python" tab="Python">
                  <n-data-table :columns="pkgColumns" :data="assets.package?.python_packages || []" :pagination="{ pageSize: 10 }" size="small" :bordered="false" />
                </n-tab-pane>
                <n-tab-pane name="npm" tab="NPM">
                  <n-data-table :columns="pkgColumns" :data="assets.package?.npm_packages || []" :pagination="{ pageSize: 10 }" size="small" :bordered="false" />
                </n-tab-pane>
              </n-tabs>
            </n-tab-pane>
            <n-tab-pane name="service" tab="服务">
              <n-data-table
                :columns="serviceColumns"
                :data="assets.service?.services || []"
                :pagination="{ pageSize: 10 }"
                :bordered="false"
                size="small"
              />
            </n-tab-pane>
          </n-tabs>
        </n-tab-pane>

        <n-tab-pane name="chains" tab="攻击链">
          <n-empty v-if="starChains.length === 0" description="暂无攻击链" />
          <n-list v-else>
            <n-list-item v-for="corrId in starChains" :key="corrId">
              <n-space justify="space-between" align="center">
                <n-text code style="font-size: 12px">{{ corrId }}</n-text>
                <n-button size="small" type="primary" @click="goToStarChain(corrId)">查看</n-button>
              </n-space>
            </n-list-item>
          </n-list>
        </n-tab-pane>
      </n-tabs>

    </n-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, h } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { NCard, NSpace, NDescriptions, NDescriptionsItem, NDataTable, NButton, NEmpty, NList, NListItem, NText, NTag, NTabs, NTabPane } from 'naive-ui'
import { getAgents, type AgentInfo } from '../api/agent'
import { getAlerts, type AlertItem } from '../api/alert'

const route = useRoute()
const router = useRouter()

const agentId = ref(route.params.id as string)
const hostname = ref('')
const ipAddr = ref('')
const version = ref('')
const capabilityLevel = ref('')
const activeProbes = ref(0)
const lastSeen = ref('')
const recentAlerts = ref<AlertItem[]>([])
const starChains = ref<string[]>([])
const loading = ref(false)
const assets = ref<any>({})

const processColumns = [
  { title: 'PID', key: 'pid', width: 80 },
  { title: '进程名', key: 'name' },
  { title: '用户', key: 'user', width: 100 },
  { title: '状态', key: 'state', width: 80 },
]

const userColumns = [
  { title: '用户名', key: 'username' },
  { title: 'UID', key: 'uid', width: 80 },
  { title: 'Shell', key: 'shell' },
  { title: 'Home', key: 'home' },
]

const pkgColumns = [
  { title: '包名', key: 'name' },
  { title: '版本', key: 'version', width: 120 },
]

const serviceColumns = [
  { title: '服务名', key: 'name' },
  { title: '状态', key: 'status', width: 100 },
  { title: '运行用户', key: 'user', width: 120 },
]

interface ProbeRow {
  name: string
  status: string
  reason?: string
  last_event_at: number
  last_check_at: number
  consecutive_failures: number
}

const probes = ref<ProbeRow[]>([])

function statusTagType(status: string): 'success' | 'warning' | 'error' | 'info' | 'default' {
  switch (status) {
    case 'loaded': return 'success'
    case 'loaded-silent': return 'warning'
    case 'loaded-no-activity': return 'default'
    case 'failed':
    case 'unknown probe': return 'error'
    case 'loading': return 'info'
    default: return 'default'
  }
}

function statusText(status: string): string {
  switch (status) {
    case 'loaded': return '运行中'
    case 'loaded-silent': return '静默（自检失败）'
    case 'loaded-no-activity': return '无法自检'
    case 'failed': return '加载失败'
    case 'disabled': return '已禁用'
    case 'loading': return '加载中'
    case 'unknown probe': return '未注册'
    default: return status || '未知'
  }
}

function formatProbeTime(ts: number): string {
  if (!ts) return '-'
  return new Date(ts * 1000).toLocaleString('zh-CN')
}

const probeColumns = [
  { title: '探针', key: 'name' },
  {
    title: '状态',
    key: 'status',
    width: 160,
    render(row: ProbeRow) {
      return h(NTag, { type: statusTagType(row.status), round: true, size: 'small' },
        { default: () => statusText(row.status) })
    },
  },
  { title: '原因', key: 'reason', render(row: ProbeRow) { return row.reason || '-' } },
  {
    title: '最近事件',
    key: 'last_event_at',
    width: 170,
    render(row: ProbeRow) { return formatProbeTime(row.last_event_at) },
  },
  {
    title: '最近自检',
    key: 'last_check_at',
    width: 170,
    render(row: ProbeRow) { return formatProbeTime(row.last_check_at) },
  },
]

const alertColumns = [
  { title: '规则', key: 'rule_name' },
  { title: '严重度', key: 'severity' },
  { title: '时间', key: 'detected_at', render(row: AlertItem) { return new Date(row.detected_at).toLocaleString('zh-CN') } },
]

onMounted(async () => {
  loading.value = true
  try {
    const agents = await getAgents()
    const agent = agents.find(a => a.id === agentId.value)
    if (agent) {
      hostname.value = agent.hostname
      ipAddr.value = agent.ip_addr
      version.value = agent.version
      capabilityLevel.value = agent.capability_level
      activeProbes.value = agent.active_probes
      lastSeen.value = new Date(agent.last_seen * 1000).toLocaleString('zh-CN')
      if (agent.probe_status) {
        probes.value = Object.entries(agent.probe_status).map(([name, p]) => ({
          name,
          status: p.status,
          reason: p.reason,
          last_event_at: p.last_event_at,
          last_check_at: p.last_check_at,
          consecutive_failures: p.consecutive_failures,
        }))
      }
    }

    // 加载资产
    try {
      const { default: http } = await import('../api/http')
      const { data } = await http.get(`/assets/${agentId.value}`)
      assets.value = data || {}
    } catch (err) {
      console.error('加载资产失败:', err)
    }

    const alerts = await getAlerts()
    recentAlerts.value = alerts.filter(a => a.agent_id === agentId.value).slice(0, 10)
    starChains.value = [...new Set(recentAlerts.value.filter(a => a.correlation_id).map(a => a.correlation_id))]
  } catch (err: any) {
    console.error('加载主机详情失败:', err)
  } finally {
    loading.value = false
  }
})

function goToStarChain(corrId: string) {
  router.push(`/star?corr_id=${corrId}`)
}
</script>

<style scoped>
.probe-row {
  padding: 8px 0;
  border-bottom: 1px solid #f0f0f0;
}

.probe-row:last-child {
  border-bottom: none;
}

.host-detail-container {
  padding: 24px;
  max-width: 1000px;
  margin: 0 auto;
}
</style>

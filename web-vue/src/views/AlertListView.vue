<template>
  <div class="alert-container">
    <!-- 顶部操作栏 -->
    <div class="toolbar">
      <div class="toolbar-left">
        <n-tag type="info" round size="small">日志检索</n-tag>
        <n-text depth="3" style="font-size: 12px">共 {{ filteredAlerts.length }} 条告警</n-text>
        <span class="live-dot"></span>
        <n-text depth="3" style="font-size: 12px">
          活跃主机 {{ onlineHostCount }} 台 · 待处理 {{ pendingCount }} 条
        </n-text>
      </div>
      <div class="toolbar-right">
        <n-select v-model:value="severityFilter" :options="severityOptions" placeholder="严重度" clearable size="small" style="width: 110px" />
        <n-select v-model:value="sourceFilter" :options="sourceOptions" placeholder="来源" clearable size="small" style="width: 110px" />
        <n-input v-model:value="keyword" placeholder="搜索规则/进程/主机" clearable size="small" style="width: 220px" />
        <n-button size="small" @click="loadAlerts">刷新</n-button>
        <n-button size="small" type="primary" @click="batchResolve">批量解决</n-button>
      </div>
    </div>

    <!-- 表格 -->
    <div class="table-wrapper">
      <n-data-table
        :columns="columns"
        :data="filteredAlerts"
        :loading="loading"
        :pagination="{ pageSize: 20 }"
        :bordered="false"
        :single-line="false"
        size="small"
        :row-key="(row: AlertItem) => row.id"
        :row-props="rowProps"
        @update:checked-row-keys="handleCheck"
      />
    </div>

    <!-- 详情弹窗 -->
    <n-modal v-model:show="showDetail" preset="card" title="告警详情" style="max-width: 700px">
      <n-descriptions v-if="selectedAlert" :column="2" bordered size="small">
        <n-descriptions-item label="规则">{{ selectedAlert.rule_name }}</n-descriptions-item>
        <n-descriptions-item label="严重度">
          <n-tag :type="severityTagType(selectedAlert.severity)" size="small" round>{{ selectedAlert.severity }}</n-tag>
        </n-descriptions-item>
        <n-descriptions-item label="描述" :span="2">{{ selectedAlert.description }}</n-descriptions-item>
        <n-descriptions-item label="主机">{{ selectedAlert.agent_id }}</n-descriptions-item>
        <n-descriptions-item label="PID">{{ selectedAlert.pid }}</n-descriptions-item>
        <n-descriptions-item label="进程">{{ selectedAlert.comm }}</n-descriptions-item>
        <n-descriptions-item label="文件">{{ selectedAlert.filename || '-' }}</n-descriptions-item>
        <n-descriptions-item label="时间" :span="2">{{ formatTime(selectedAlert.detected_at) }}</n-descriptions-item>
        <n-descriptions-item v-if="selectedAlert.correlation_id" label="攻击链" :span="2">
          <n-button size="small" type="primary" @click="goToStarChain(selectedAlert.correlation_id)">
            {{ selectedAlert.correlation_id }}
          </n-button>
        </n-descriptions-item>
      </n-descriptions>

      <n-divider v-if="selectedAlert?.correlation_id" />

      <div v-if="selectedAlert?.correlation_id" style="max-height: 300px; overflow-y: auto">
        <n-timeline v-if="chainEvents.length > 0">
          <n-timeline-item
            v-for="evt in chainEvents"
            :key="evt.id"
            :type="getChainEventType(evt.event_type)"
            :title="evt.event_type"
          >
            <n-text depth="3">PID: {{ evt.pid }} | {{ evt.comm }}</n-text>
          </n-timeline-item>
        </n-timeline>
      </div>
    </n-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, h, computed } from 'vue'
import { NTag, NButton, NDataTable, NModal, NDescriptions, NDescriptionsItem, NTimeline, NTimelineItem, NDivider, NText, NSelect, useMessage, NPopselect, NInput } from 'naive-ui'
import { useRouter } from 'vue-router'
import { getAlerts, type AlertItem } from '../api/alert'
import http from '../api/http'
import { onWSMessage } from '../api/ws'

const alerts = ref<AlertItem[]>([])
const loading = ref(false)
const router = useRouter()
const showDetail = ref(false)
const selectedAlert = ref<AlertItem | null>(null)
const chainEvents = ref<any[]>([])
const severityFilter = ref<string | null>(null)
const onlineHostCount = ref(0)
const sourceFilter = ref<string | null>(null)
const keyword = ref('')
const checkedIds = ref<number[]>([])
const message = useMessage()

const severityOptions = [
  { label: '严重', value: 'critical' },
  { label: '高危', value: 'high' },
  { label: '中危', value: 'medium' },
  { label: '低危', value: 'low' },
]

const sourceOptions = [
  { label: '硬规则', value: 'hard_rule' },
  { label: '软基线', value: 'baseline' },
]

const statusOptions = [
  { label: '未处理', value: 'open' },
  { label: '已确认', value: 'acknowledged' },
  { label: '已解决', value: 'resolved' },
  { label: '误报', value: 'false_positive' },
]

const severityTagType = (sev: string): 'error' | 'warning' | 'info' | 'default' => {
  if (sev === 'critical') return 'error'
  if (sev === 'high') return 'warning'
  if (sev === 'medium') return 'info'
  return 'default'
}

const statusTagType = (status: string): 'error' | 'warning' | 'success' | 'info' | 'default' => {
  if (status === 'open') return 'error'
  if (status === 'acknowledged') return 'warning'
  if (status === 'resolved') return 'success'
  if (status === 'false_positive') return 'info'
  return 'default'
}

const statusLabel = (status: string): string => {
  const map: Record<string, string> = {
    open: '未处理',
    acknowledged: '已确认',
    resolved: '已解决',
    false_positive: '误报',
  }
  return map[status] || status
}

const columns = [
  { type: 'selection', width: 40 },
  {
    title: '时间',
    key: 'detected_at',
    width: 160,
    render(row: AlertItem) {
      return new Date(row.detected_at).toLocaleString('zh-CN', { hour12: false })
    },
  },
  {
    title: '规则',
    key: 'rule_name',
    width: 160,
    ellipsis: { tooltip: true },
  },
  {
    title: '严重度',
    key: 'severity',
    width: 90,
    render(row: AlertItem) {
      return h(NTag, { type: severityTagType(row.severity), size: 'small', round: true }, { default: () => row.severity })
    },
  },
  {
    title: '主机',
    key: 'agent_id',
    width: 180,
    ellipsis: { tooltip: true },
  },
  {
    title: 'PID',
    key: 'pid',
    width: 70,
  },
  {
    title: '进程',
    key: 'comm',
    width: 120,
    ellipsis: { tooltip: true },
  },
  {
    title: '文件',
    key: 'filename',
    width: 180,
    ellipsis: { tooltip: true },
    render(row: AlertItem) {
      return row.filename || '-'
    },
  },
  {
    title: '来源',
    key: 'source',
    width: 90,
    render(row: AlertItem) {
      const isBaseline = row.details?.includes('[参考]') || false
      return h(NTag, { type: isBaseline ? 'info' : 'error', size: 'small', round: true }, { default: () => isBaseline ? '软基线' : '硬规则' })
    },
  },
  {
    title: '攻击链',
    key: 'correlation_id',
    width: 200,
    ellipsis: { tooltip: true },
    render(row: AlertItem) {
      if (!row.correlation_id) return h('span', { style: 'color:#999' }, '-')
      return h('a', {
        style: 'color: #2563eb; cursor: pointer; font-size: 12px',
        onClick: (e: MouseEvent) => { e.stopPropagation(); router.push(`/star?corr_id=${row.correlation_id}`) },
      }, row.correlation_id)
    },
  },
  {
    title: '状态',
    key: 'status',
    width: 90,
    render(row: AlertItem) {
      return h(NTag, { type: statusTagType(row.status), size: 'small', round: true }, { default: () => statusLabel(row.status) })
    },
  },
  {
    title: '操作',
    key: 'actions',
    width: 150,
    fixed: 'right' as const,
    render(row: AlertItem) {
      return h('div', { style: 'display:flex; gap:6px' }, [
        h(NButton, {
          size: 'tiny',
          onClick: (e: MouseEvent) => { e.stopPropagation(); selectedAlert.value = row; showDetail.value = true; chainEvents.value = []; if (row.correlation_id) loadChainEvents(row.correlation_id) },
        }, { default: () => '详情' }),
        h(NPopselect, {
          size: 'tiny',
          options: statusOptions,
          value: row.status,
          onUpdateValue: (v: string) => updateStatus(row, v),
        }, { default: () => h(NButton, { size: 'tiny' }, { default: () => '状态' }) }),
      ])
    },
  },
]

const pendingCount = computed(() => alerts.value.filter(a => a.status === 'open').length)

const filteredAlerts = computed(() => {
  let result = alerts.value
  if (severityFilter.value) result = result.filter(a => a.severity === severityFilter.value)
  if (sourceFilter.value === 'hard_rule') result = result.filter(a => !a.details?.includes('[参考]'))
  if (sourceFilter.value === 'baseline') result = result.filter(a => a.details?.includes('[参考]'))
  if (keyword.value.trim()) {
    const kw = keyword.value.trim().toLowerCase()
    result = result.filter(a =>
      (a.rule_name || '').toLowerCase().includes(kw) ||
      (a.comm || '').toLowerCase().includes(kw) ||
      (a.agent_id || '').toLowerCase().includes(kw) ||
      (a.filename || '').toLowerCase().includes(kw)
    )
  }
  return result
})

onMounted(async () => {
  await loadAlerts()
  onWSMessage('new_alert', async () => { await loadAlerts() })
})

function handleCheck(keys: any) { checkedIds.value = keys || [] }

function rowProps(row: AlertItem) {
  return {
    style: 'cursor: pointer;',
    onClick: (e: MouseEvent) => {
      const target = e.target as HTMLElement
      if (target.closest('.n-checkbox') || target.closest('.n-button') || target.closest('a')) return
      selectedAlert.value = row
      showDetail.value = true
      chainEvents.value = []
      if (row.correlation_id) loadChainEvents(row.correlation_id)
    },
  }
}

async function updateStatus(row: AlertItem, status: string) {
  try {
    await http.post('/alerts/batch-resolve', { ids: [row.id], status })
    message.success('状态已更新')
    await loadAlerts()
  } catch (err: any) {
    message.error(err.response?.data?.error || '更新失败')
  }
}

async function batchResolve() {
  if (checkedIds.value.length === 0) {
    message.warning('请先勾选要解决的告警')
    return
  }
  try {
    await http.post('/alerts/batch-resolve', { ids: checkedIds.value, status: 'resolved' })
    message.success(`已解决 ${checkedIds.value.length} 条告警`)
    checkedIds.value = []
    await loadAlerts()
  } catch (err: any) {
    message.error(err.response?.data?.error || '操作失败')
  }
}

async function goToStarChain(corrId: string) {
  showDetail.value = false
  router.push(`/star?corr_id=${corrId}`)
}

async function loadChainEvents(corrId: string) {
  try {
    const { getStarChain } = await import('../api/star')
    const data = await getStarChain(corrId)
    chainEvents.value = data.events.filter((e: any) => e.event_type !== 'baseline_anomaly').slice(0, 10)
  } catch {
    chainEvents.value = []
  }
}

function getChainEventType(eventType: string): 'success' | 'warning' | 'error' | 'info' {
  const map: Record<string, 'success' | 'warning' | 'error' | 'info'> = {
    execve: 'info', file_access: 'warning', tcp_connect: 'error', bash_input: 'success',
  }
  return map[eventType] || 'info'
}

function formatTime(timeStr: string): string {
  return new Date(timeStr).toLocaleString('zh-CN', { hour12: false })
}

async function loadAlerts() {
  loading.value = true
  try {
    alerts.value = await getAlerts()
    // 加载在线主机数
    try {
      const { data } = await http.get('/agents')
      const agents = data.agents || []
      const now = Date.now() / 1000
      onlineHostCount.value = agents.filter((a: any) => now - a.last_seen < 120).length
    } catch {
      onlineHostCount.value = 0
    }
  } catch (err: any) {
    console.error('加载告警失败:', err)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.alert-container {
  padding: 12px;
  height: calc(100vh - 60px);
  display: flex;
  flex-direction: column;
  background: #f5f7fa;
}

.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 12px;
  background: #fff;
  border-radius: 6px;
  margin-bottom: 8px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.06);
}

.toolbar-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.live-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #10b981;
  box-shadow: 0 0 6px rgba(16, 185, 129, 0.6);
  animation: pulse 2s infinite;
  margin-left: 8px;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}

.toolbar-right {
  display: flex;
  align-items: center;
  gap: 8px;
}

.table-wrapper {
  flex: 1;
  background: #fff;
  border-radius: 6px;
  padding: 8px;
  overflow: auto;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.06);
}

.table-wrapper :deep(.n-data-table) {
  font-size: 12px;
}

.table-wrapper :deep(.n-data-table-th) {
  background: #fafbfc;
  font-weight: 600;
  white-space: nowrap;
}

.table-wrapper :deep(.n-data-table-td) {
  padding: 6px 8px;
}
</style>

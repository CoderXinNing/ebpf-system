<template>
  <div class="alert-container">
    <n-card title="告警列表" bordered hoverable>
      <n-space vertical :size="16">
        <n-space justify="space-between" align="center">
          <n-space>
            <n-select
            v-model:value="severityFilter"
            :options="severityOptions"
            placeholder="严重度"
            clearable
            style="width: 140px"
          />
            <n-select
              v-model:value="sourceFilter"
              :options="sourceOptions"
              placeholder="来源"
              clearable
              style="width: 140px"
            />
          </n-space>
          <n-button size="small" type="success" @click="batchResolve">批量解决</n-button>
        </n-space>
        <n-data-table
          :columns="columns"
          :data="filteredAlerts"
          :loading="loading"
          :pagination="{ pageSize: 20 }"
          :bordered="false"
          @update:checked-row-keys="handleRowClick"
        />

        <!-- 详情弹窗 -->
        <n-modal v-model:show="showDetail" preset="card" title="告警详情" style="max-width: 600px">
          <n-descriptions v-if="selectedAlert" :column="1" bordered>
            <n-descriptions-item label="规则">{{ selectedAlert.rule_name }}</n-descriptions-item>
            <n-descriptions-item label="严重度">{{ selectedAlert.severity }}</n-descriptions-item>
            <n-descriptions-item label="描述">{{ selectedAlert.description }}</n-descriptions-item>
            <n-descriptions-item label="主机">{{ selectedAlert.agent_id }}</n-descriptions-item>
            <n-descriptions-item label="PID">{{ selectedAlert.pid }}</n-descriptions-item>
            <n-descriptions-item label="进程">{{ selectedAlert.comm }}</n-descriptions-item>
            <n-descriptions-item label="时间">{{ formatTime(selectedAlert.detected_at) }}</n-descriptions-item>
            <n-descriptions-item v-if="selectedAlert.correlation_id" label="攻击链">
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
      </n-space>
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, h, computed } from 'vue'
import { NTag, NButton, NCard, NSpace, NDataTable, NModal, NDescriptions, NDescriptionsItem, NEmpty, NTimeline, NTimelineItem, NDivider, NText, NSkeleton, NSelect } from 'naive-ui'
import { useRouter } from 'vue-router'
import { getAlerts, type AlertItem } from '../api/alert'
import { onWSMessage } from '../api/ws'

const alerts = ref<AlertItem[]>([])
const loading = ref(false)
const router = useRouter()
const showDetail = ref(false)
const selectedAlert = ref<AlertItem | null>(null)
const chainEvents = ref<any[]>([])
const severityFilter = ref<string | null>(null)
const sourceFilter = ref<string | null>(null)

const severityOptions = [
  { label: '严重', value: 'critical' },
  { label: '高危', value: 'high' },
  { label: '中危', value: 'medium' },
  { label: '低危', value: 'low' },
]

const sourceOptions = [
  { label: '硬规则', value: 'hard_rule' },
  { label: '软基线参考', value: 'baseline' },
]

const columns = [
  {
    title: '规则',
    key: 'rule_name',
  },
  {
    title: '严重度',
    key: 'severity',
    render(row: AlertItem) {
      const type = row.severity === 'critical' ? 'error' : row.severity === 'high' ? 'warning' : 'info'
      return h(NTag, { type, round: true }, { default: () => row.severity })
    },
  },
  {
    title: '主机',
    key: 'agent_id',
  },
  {
    title: 'PID',
    key: 'pid',
  },
  {
    title: '状态',
    key: 'status',
    render(row: AlertItem) {
      const statusMap: Record<string, { type: 'default' | 'success' | 'warning' | 'error' | 'info', label: string }> = {
        open: { type: 'error', label: '未处理' },
        acknowledged: { type: 'warning', label: '已确认' },
        resolved: { type: 'success', label: '已解决' },
        false_positive: { type: 'info', label: '误报' },
      }
      const s = statusMap[row.status] || { type: 'default' as const, label: row.status }
      return h(NTag, { type: s.type, round: true }, { default: () => s.label })
    },
  },
  {
    title: '来源',
    key: 'source',
    render(row: AlertItem) {
      const isBaseline = row.details?.includes('[参考]') || false
      return h(NTag, { type: isBaseline ? 'info' : 'error', round: true }, { default: () => isBaseline ? '软基线参考' : '硬规则' })
    },
  },
  {
    title: '时间',
    key: 'detected_at',
    render(row: AlertItem) {
      return new Date(row.detected_at).toLocaleString('zh-CN')
    },
  },
  {
    title: '操作',
    key: 'actions',
    render(row: AlertItem) {
      return h(NSpace, { size: 8 }, {
        default: () => [
          h(
            NButton,
            {
              size: 'small',
              type: 'default',
              round: true,
              onClick: () => {
                selectedAlert.value = row
                showDetail.value = true
              },
            },
            { default: () => '详情' }
          ),
          row.correlation_id ? h(
            NButton,
            {
              size: 'small',
              type: 'primary',
              round: true,
              onClick: () => router.push(`/star?corr_id=${row.correlation_id}`),
            },
            { default: () => '攻击链' }
          ) : null,
        ],
      })
    },
  },
]

onMounted(async () => {
  await loadAlerts()
  onWSMessage('new_alert', async () => {
    await loadAlerts()
  })
})

function handleRowClick(keys: any) {
  if (keys && keys.length > 0) {
    selectedAlert.value = alerts.value.find(a => a.id === keys[0]) || null
    showDetail.value = true
    chainEvents.value = []
    if (selectedAlert.value?.correlation_id) {
      loadChainEvents(selectedAlert.value.correlation_id)
    }
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
  } catch (err) {
    chainEvents.value = []
  }
}

function getChainEventType(eventType: string): 'success' | 'warning' | 'error' | 'info' {
  const map: Record<string, 'success' | 'warning' | 'error' | 'info'> = {
    execve: 'info',
    file_access: 'warning',
    tcp_connect: 'error',
    bash_input: 'success',
  }
  return map[eventType] || 'info'
}

function formatTime(timeStr: string): string {
  return new Date(timeStr).toLocaleString('zh-CN')
}

const filteredAlerts = computed(() => {
  let result = alerts.value
  if (severityFilter.value) {
    result = result.filter(a => a.severity === severityFilter.value)
  }
  if (sourceFilter.value === 'hard_rule') {
    result = result.filter(a => !a.details?.includes('[参考]'))
  }
  if (sourceFilter.value === 'baseline') {
    result = result.filter(a => a.details?.includes('[参考]'))
  }
  return result
})

function batchResolve() {
  // 简化版：只提示，后续对接 API
  alert('批量解决功能开发中')
}

async function loadAlerts() {
  loading.value = true
  try {
    alerts.value = await getAlerts()
  } catch (err: any) {
    console.error('加载告警失败:', err)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.alert-container {
  padding: 24px;
  max-width: 1100px;
  margin: 0 auto;
}
</style>

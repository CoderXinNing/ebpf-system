<template>
  <div class="alert-container">
    <n-card title="告警列表" bordered hoverable>
      <n-space vertical :size="16">
        <n-data-table
          :columns="columns"
          :data="alerts"
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
        </n-modal>
      </n-space>
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, h } from 'vue'
import { NTag, NButton, NCard, NSpace, NDataTable, NModal, NDescriptions, NDescriptionsItem, NEmpty } from 'naive-ui'
import { useRouter } from 'vue-router'
import { getAlerts, type AlertItem } from '../api/alert'
import { onWSMessage } from '../api/ws'

const alerts = ref<AlertItem[]>([])
const loading = ref(false)
const router = useRouter()
const showDetail = ref(false)
const selectedAlert = ref<AlertItem | null>(null)

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
  }
}

function goToStarChain(corrId: string) {
  showDetail.value = false
  router.push(`/star?corr_id=${corrId}`)
}

function formatTime(timeStr: string): string {
  return new Date(timeStr).toLocaleString('zh-CN')
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

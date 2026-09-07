<template>
  <div class="alert-container">
    <n-card title="告警列表" bordered>
      <n-space vertical>
        <n-data-table
          :columns="columns"
          :data="alerts"
          :loading="loading"
          :pagination="{ pageSize: 20 }"
        />
      </n-space>
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, h } from 'vue'
import { NTag, NButton } from 'naive-ui'
import { useRouter } from 'vue-router'
import { getAlerts, type AlertItem } from '../api/alert'

const alerts = ref<AlertItem[]>([])
const loading = ref(false)
const router = useRouter()

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
      return h(NTag, { type }, { default: () => row.severity })
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
      if (row.correlation_id) {
        return h(
          NButton,
          {
            size: 'small',
            type: 'primary',
            onClick: () => router.push(`/star?corr_id=${row.correlation_id}`),
          },
          { default: () => '查看攻击链' }
        )
      }
      return h('span', '-')
    },
  },
]

onMounted(async () => {
  loading.value = true
  try {
    alerts.value = await getAlerts()
  } catch (err: any) {
    console.error('加载告警失败:', err)
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.alert-container {
  padding: 24px;
  max-width: 1100px;
  margin: 0 auto;
}
</style>

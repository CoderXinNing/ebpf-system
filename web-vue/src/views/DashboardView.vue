<template>
  <div class="dashboard-container">
    <n-space vertical>
      <n-card title="AsterTrack 仪表盘" bordered>
        <n-grid :cols="3" :x-gap="16">
          <n-grid-item>
            <n-statistic label="主机数" :value="agents.length" />
          </n-grid-item>
          <n-grid-item>
            <n-statistic label="告警数" :value="alertCount" />
          </n-grid-item>
          <n-grid-item>
            <n-statistic label="攻击链数" :value="starCount" />
          </n-grid-item>
        </n-grid>
      </n-card>

      <n-card title="主机列表" bordered>
        <n-data-table :columns="columns" :data="agents" :loading="loading" />
      </n-card>
    </n-space>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { NGrid, NGridItem, NStatistic, NDataTable } from 'naive-ui'
import { getAgents, type AgentInfo } from '../api/agent'
import { getAlerts } from '../api/alert'

const agents = ref<AgentInfo[]>([])
const alertCount = ref(0)
const starCount = ref(0)
const loading = ref(false)

const columns = [
  { title: '主机名', key: 'hostname' },
  { title: 'IP', key: 'ip_addr' },
  { title: '探针数', key: 'active_probes' },
  { title: '能力', key: 'capability_level' },
  {
    title: '最后心跳',
    key: 'last_seen',
    render(row: AgentInfo) {
      return new Date(row.last_seen * 1000).toLocaleString('zh-CN')
    },
  },
]

onMounted(async () => {
  loading.value = true
  try {
    const [agentList, alertList] = await Promise.all([getAgents(), getAlerts()])
    agents.value = agentList
    alertCount.value = alertList.length
    starCount.value = new Set(alertList.filter(a => a.correlation_id).map(a => a.correlation_id)).size
  } catch (err: any) {
    console.error('加载仪表盘失败:', err)
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.dashboard-container {
  padding: 24px;
  max-width: 1200px;
  margin: 0 auto;
}
</style>

<template>
  <div>
    <n-grid :cols="3" :x-gap="12">
      <n-grid-item><n-card><n-spin :show="loading"><n-statistic label="在线Agent" :value="health.online" /></n-spin></n-card></n-grid-item>
      <n-grid-item><n-card><n-spin :show="loading"><n-statistic label="总Agent" :value="health.total" /></n-spin></n-card></n-grid-item>
      <n-grid-item><n-card><n-spin :show="loading"><n-statistic label="状态" :value="health.status" /></n-spin></n-card></n-grid-item>
    </n-grid>

    <n-card title="Agent 列表" style="margin-top:16px">
      <n-spin :show="loading">
        <n-data-table :columns="columns" :data="agents" :bordered="false" />
      </n-spin>
    </n-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { api } from '../utils/api'

const loading = ref(true)
const health = ref({ online: 0, total: 0, status: '-' })
const agents = ref([])

const columns = [
  { title: 'Agent ID', key: 'id', ellipsis: { tooltip: true } },
  { title: '主机名', key: 'hostname' },
  { title: 'IP', key: 'ip_addr' },
  { title: '内核', key: 'kernel_info', render: (row) => row.kernel_info?.version || '-' },
  { title: '探针数', key: 'active_probes' },
  { title: '状态', key: 'last_seen', render: (row) => {
    const now = Math.floor(Date.now()/1000)
    return now - row.last_seen < 30 ? '🟢 在线' : '🔴 离线'
  }},
]

onMounted(async () => {
  loading.value = true
  try { health.value = await api.getHealth() } catch(e) {}
  try { const d = await api.getAgents(); agents.value = d.agents || [] } catch(e) {}
  loading.value = false
})
</script>

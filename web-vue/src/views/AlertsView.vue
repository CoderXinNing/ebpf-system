<template>
  <Layout>
    <n-card title="告警列表" :bordered="false" style="margin-bottom: 16px">
      <template #header-extra>
        <n-tag type="warning">实时告警</n-tag>
      </template>
      <n-data-table
        :columns="columns"
        :data="alerts"
        :loading="loading"
        :pagination="pagination"
      />
    </n-card>
  </Layout>
</template>

<script setup>
import { ref, h, onMounted } from 'vue'
import { NTag } from 'naive-ui'
import Layout from '../layouts/MainLayout.vue'

const loading = ref(false)
const alerts = ref([])
const agents = ref([])
const pagination = ref({ pageSize: 10 })

const severityMap = {
  CRITICAL: { type: 'error', color: '#D03050' },
  HIGH: { type: 'warning', color: '#F0A020' },
  MEDIUM: { type: 'info', color: '#2080F0' },
  LOW: { type: 'default', color: '#909399' },
}

const columns = [
  { title: '级别', key: 'severity', width: 100, render(row) {
    const s = severityMap[row.severity] || severityMap.LOW
    return h(NTag, { type: s.type, bordered: false }, { default: () => row.severity })
  }},
  { title: '规则', key: 'rule_name', width: 180 },
  { title: '描述', key: 'description', ellipsis: true },
  { title: '主机', key: 'agent_id', width: 200, ellipsis: true, render(row) {
    const a = agents.value.find(x => x.id === row.agent_id)
    return a ? `${a.hostname} (${a.ip_addr})` : row.agent_id
  }},
  { title: 'PID', key: 'pid', width: 80 },
  { title: '详情', key: 'details', ellipsis: true },
  { title: '时间', key: 'created_at', width: 180, render(row) {
    return new Date(row.created_at * 1000).toLocaleString()
  }},
]

async function loadAlerts() {
  loading.value = true
  try {
    const token = localStorage.getItem('token')
    const resp = await fetch('/api/agents', {
      headers: { 'Authorization': 'Bearer ' + token }
    })
    const data = await resp.json()
    agents.value = data.agents || []
  } catch (e) {
    console.error('加载主机失败:', e)
  }
  try {
    const token = localStorage.getItem('token')
    const resp = await fetch('/api/alerts', {
      headers: { 'Authorization': 'Bearer ' + token }
    })
    const data = await resp.json()
    alerts.value = data.alerts || []
  } catch (e) {
    console.error('加载告警失败:', e)
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  loadAlerts()
  setInterval(loadAlerts, 10000)
})
</script>

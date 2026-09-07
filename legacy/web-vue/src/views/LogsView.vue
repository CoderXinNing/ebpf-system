<template>
  <Layout>
    <div class="logs-container">
      <div class="table-card">
        <div class="card-header">
          <span class="card-title">系统日志</span>
          <div style="display: flex; gap: 0.5vw; align-items: center;">
            <n-input v-model:value="searchText" size="small" placeholder="搜索用户/操作/详情/IP" style="width: 14vw" clearable />
            <n-button size="small" @click="exportLogs">导出 CSV</n-button>
          </div>
        </div>
        <n-data-table
          :columns="cols"
          :data="filteredLogs"
          :bordered="false"
          size="small"
          :pagination="pagination"
          :row-key="(r) => r.id"
        />
      </div>
    </div>
  </Layout>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import Layout from '../layouts/MainLayout.vue'

const logs = ref([])
const searchText = ref('')
const pagination = ref({ pageSize: 15 })

const cols = [
  { title: '时间', key: 'created_at', minWidth: 90, render: (r) => new Date(r.created_at * 1000).toLocaleString() },
  { title: '用户', key: 'username', minWidth: 90 },
  { title: '操作', key: 'action', minWidth: 120 },
  { title: '详情', key: 'detail', ellipsis: true },
  { title: 'IP', key: 'ip', minWidth: 110 },
]

const filteredLogs = computed(() => {
  const kw = searchText.value.trim().toLowerCase()
  if (!kw) return logs.value
  return logs.value.filter(l =>
    (l.username || '').toLowerCase().includes(kw) ||
    (l.action || '').toLowerCase().includes(kw) ||
    (l.detail || '').toLowerCase().includes(kw) ||
    (l.ip || '').toLowerCase().includes(kw)
  )
})

async function exportLogs() {
  const token = localStorage.getItem('token')
  const resp = await fetch('/api/logs/export', {
    headers: { 'Authorization': 'Bearer ' + token }
  })
  const blob = await resp.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'audit_logs.csv'
  a.click()
  URL.revokeObjectURL(url)
}

async function load() {
  const token = localStorage.getItem('token')
  const resp = await fetch('/api/logs', { headers: { 'Authorization': 'Bearer ' + token } })
  const data = await resp.json()
  logs.value = data.logs || []
}

onMounted(() => {
  load()
  setInterval(load, 15000)
})
</script>

<style scoped>
.logs-container { display: flex; flex-direction: column; gap: 1vh; }
.table-card { background: #FFFFFF; border-radius: 0.8vw; padding: 1.5vh 1.2vw; box-shadow: 0 0.3vh 1.5vh rgba(0,0,0,0.04); }
.card-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1vh; }
.card-title { font-size: 1vw; font-weight: 600; color: #202124; }
</style>

<template>
  <Layout>
    <div class="logs-container">
      <div class="table-card">
        <div class="card-header">
          <span class="card-title">日志审计</span>
        </div>
        <n-data-table
          :columns="cols"
          :data="logs"
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
import { ref, onMounted } from 'vue'
import Layout from '../layouts/MainLayout.vue'

const logs = ref([])
const pagination = ref({ pageSize: 15 })

const cols = [
  { title: '时间', key: 'created_at', minWidth: 90, render: (r) => new Date(r.created_at * 1000).toLocaleString() },
  { title: '用户', key: 'username', minWidth: 90 },
  { title: '操作', key: 'action', minWidth: 120 },
  { title: '详情', key: 'detail', ellipsis: true },
  { title: 'IP', key: 'ip', minWidth: 110 },
]

async function load() {
  const token = localStorage.getItem('token')
  const resp = await fetch('/api/logs', { headers: { 'Authorization': 'Bearer ' + token } })
  const data = await resp.json()
  logs.value = data.logs || []
}

onMounted(load)
</script>

<style scoped>
.logs-container {
  display: flex;
  flex-direction: column;
  gap: 1vh;
}

.table-card {
  background: #FFFFFF;
  border-radius: 0.8vw;
  padding: 1.5vh 1.2vw;
  box-shadow: 0 0.3vh 1.5vh rgba(0,0,0,0.04);
}

.card-header {
  margin-bottom: 1vh;
}

.card-title {
  font-size: 1vw;
  font-weight: 600;
  color: #202124;
}
</style>

<template>
  <Layout>
    <div class="table-card">
      <div class="card-header">
        <span class="card-title">事件流</span>
      </div>
      <n-data-table
        :columns="cols"
        :data="events"
        :bordered="false"
        size="small"
        :pagination="pagination"
        :row-key="(r) => r.id"
      />
    </div>
  </Layout>
</template>

<script setup>
import { ref } from 'vue'
import Layout from '../layouts/MainLayout.vue'

const events = ref([])
const agents = ref([])
const pagination = ref({ pageSize: 15 })

// 解析 details："user: cmdline"
function splitDetails(r) {
  const d = (r.details || '').replace(/\x00/g, '')
  const idx = d.indexOf(':')
  if (idx > 0) {
    return { user: d.slice(0, idx), cmd: d.slice(idx + 1).trim() }
  }
  return { user: '', cmd: d }
}

const cols = [
  { title: '时间', key: 'timestamp', minWidth: 80, render: (r) => new Date(r.timestamp * 1000).toLocaleTimeString() },
  { title: '主机', key: 'agent_id', minWidth: 100, render: (r) => {
    const a = agents.value.find(x => x.id === r.agent_id)
    return a ? a.hostname : r.agent_id.slice(0, 12)
  }},
  { title: '探针', key: 'probe_name', minWidth: 80 },
  { title: 'PID', key: 'pid', minWidth: 60 },
  { title: '执行用户', key: 'user', minWidth: 90, render: (r) => splitDetails(r).user || '-' },
  { title: '进程', key: 'comm', minWidth: 80, render: (r) => (r.comm || '').replace(/\x00/g, '') },
  { title: '详细命令', key: 'cmd', ellipsis: true, render: (r) => splitDetails(r).cmd || (r.filename || '').replace(/\x00/g, '') },
]

async function load() {
  try {
    const token = localStorage.getItem('token')
    const [eventResp, agentResp] = await Promise.all([
      fetch('/api/events?limit=50', { headers: { 'Authorization': 'Bearer ' + token } }).then(r => r.json()),
      fetch('/api/agents', { headers: { 'Authorization': 'Bearer ' + token } }).then(r => r.json()),
    ])
    events.value = eventResp.events || []
    agents.value = agentResp.agents || []
  } catch (e) {
    console.error('加载失败:', e)
  }
}

load()
setInterval(load, 5000)
</script>

<style scoped>
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

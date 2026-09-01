<template>
  <Layout>
    <div class="table-card">
      <div class="card-header">
        <span class="card-title">告警中心</span>
      </div>
      <n-data-table
        :columns="cols"
        :data="alerts"
        :bordered="false"
        size="small"
        :pagination="pagination"
        :row-key="(r) => r.id"
      />
    </div>
  </Layout>
</template>

<script setup>
import { ref, h } from 'vue'
import Layout from '../layouts/MainLayout.vue'
import { NTag } from 'naive-ui'

const alerts = ref([])
const agents = ref([])
const pagination = ref({ pageSize: 15 })

const severityMap = {
  CRITICAL: { type: 'error' },
  HIGH: { type: 'warning' },
  MEDIUM: { type: 'info' },
  LOW: { type: 'default' },
}

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
  { title: '级别', key: 'severity', width: 80, render: (r) => {
    const s = severityMap[r.severity] || severityMap.LOW
    return h(NTag, { type: s.type, bordered: false, size: 'small' }, { default: () => r.severity })
  }},
  { title: '规则', key: 'rule_name', minWidth: 140 },
  { title: '主机', key: 'agent_id', minWidth: 100, render: (r) => {
    const a = agents.value.find(x => x.id === r.agent_id)
    return a ? a.hostname : r.agent_id.slice(0, 12)
  }},
  { title: '执行用户', key: 'user', minWidth: 90, render: (r) => splitDetails(r).user || '-' },
  { title: 'PID', key: 'pid', minWidth: 60 },
  { title: '详细命令', key: 'cmd', ellipsis: true, render: (r) => splitDetails(r).cmd || r.filename || '' },
  { title: '时间', key: 'created_at', minWidth: 90, render: (r) => new Date(r.created_at * 1000).toLocaleString() },
]

async function load() {
  try {
    const token = localStorage.getItem('token')
    const [alertResp, agentResp] = await Promise.all([
      fetch('/api/alerts', { headers: { 'Authorization': 'Bearer ' + token } }).then(r => r.json()),
      fetch('/api/agents', { headers: { 'Authorization': 'Bearer ' + token } }).then(r => r.json()),
    ])
    alerts.value = alertResp.alerts || []
    agents.value = agentResp.agents || []
  } catch (e) {
    console.error('加载失败:', e)
  }
}

load()
setInterval(load, 10000)
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

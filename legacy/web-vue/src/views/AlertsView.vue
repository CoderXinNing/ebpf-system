<template>
  <Layout>
    <div class="table-card">
      <div class="card-header">
        <span class="card-title">告警中心</span>
      </div>
      <div class="stats-row">
        <div class="stat-item">
          <span class="stat-num">{{ stats.total || 0 }}</span>
          <span class="stat-label">总告警</span>
        </div>
        <div class="stat-item">
          <span class="stat-num">{{ stats.today || 0 }}</span>
          <span class="stat-label">今日</span>
        </div>
        <div class="stat-item">
          <span class="stat-num" style="color: #D03050">{{ stats.false_positive || 0 }}</span>
          <span class="stat-label">误报</span>
        </div>
        <div class="stat-item">
          <span class="stat-num" style="color: #18A058">{{ stats.confirmed || 0 }}</span>
          <span class="stat-label">已确认</span>
        </div>
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
const stats = ref({})
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
  const prefix = d.slice(0, 30)
  const idx = prefix.indexOf(':')
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
  { title: '来源', key: 'source', width: 70, render: (r) => {
    const map = { rule: '硬规则', baseline: '软基线', correlation: '关联' }
    return map[r.source] || r.source || '硬规则'
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
  { title: '操作', key: 'actions', width: 120, render: (r) => {
    if (r.feedback) {
      return h('span', { style: 'color: #5F6368' }, r.feedback === 'false_positive' ? '已标记误报' : '已确认')
    }
    return h('div', { style: 'display: flex; gap: 8px' }, [
      h('a', { 
        style: 'color: #D03050; cursor: pointer',
        onClick: () => feedback(r.id, 'false_positive')
      }, '误报'),
      h('a', {
        style: 'color: #18A058; cursor: pointer',
        onClick: () => feedback(r.id, 'confirmed')
      }, '确认'),
    ])
  }},
]

async function feedback(id, type) {
  const token = localStorage.getItem('token')
  await fetch('/api/alerts/' + id + '/feedback', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
    body: JSON.stringify({ type })
  })
  load()
}

async function load() {
  try {
    const token = localStorage.getItem('token')
    const [alertResp, agentResp, statsResp] = await Promise.all([
      fetch('/api/alerts', { headers: { 'Authorization': 'Bearer ' + token } }).then(r => r.json()),
      fetch('/api/agents', { headers: { 'Authorization': 'Bearer ' + token } }).then(r => r.json()),
      fetch('/api/alerts/stats', { headers: { 'Authorization': 'Bearer ' + token } }).then(r => r.json()),
    ])
    stats.value = statsResp || {}
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
.stats-row {
  display: flex;
  gap: 1vw;
  margin-bottom: 1.5vh;
}

.stat-item {
  background: #F8F9FA;
  border-radius: 0.6vw;
  padding: 1vh 1.5vw;
  text-align: center;
  min-width: 6vw;
}

.stat-num {
  font-size: 1.4vw;
  font-weight: 700;
  color: #202124;
  display: block;
}

.stat-label {
  font-size: 0.75vw;
  color: #5F6368;
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

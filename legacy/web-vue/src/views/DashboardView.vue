<template>
  <Layout>
    <!-- 三张统计卡片 -->
    <div class="stats-grid">
      <div v-for="card in cards" :key="card.key" class="stat-card">
        <div class="card-header">
          <span class="card-title">{{ card.title }}</span>
        </div>
        <div class="card-content">
          <div :id="'ring-' + card.key" class="ring-chart"></div>
          <div class="stat-levels">
            <div v-for="lv in card.levels" :key="lv.label" class="level-row">
              <span :style="{ color: lv.color }">{{ lv.label }}</span>
              <span>{{ lv.count }}</span>
            </div>
          </div>
          <div class="top-list">
            <div class="top-header">{{ card.topLabel }}</div>
            <div v-for="item in card.topList" :key="item.name" class="top-row">
              <span class="top-name">{{ item.name }}</span>
              <span class="top-value" :style="{ color: item.color || '#202124' }">{{ item.value }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 学习态势 -->
    <div class="baseline-card">
      <div class="card-header">
        <span class="card-title">基线学习态势</span>
      </div>
      <div class="baseline-stats">
        <div class="baseline-item">
          <span class="dot learning"></span>
          <span>学习中 {{ baselineStats.learning || 0 }}</span>
        </div>
        <div class="baseline-item">
          <span class="dot observe"></span>
          <span>观察期 {{ baselineStats.observe || 0 }}</span>
        </div>
        <div class="baseline-item">
          <span class="dot protect"></span>
          <span>防护中 {{ baselineStats.protect || 0 }}</span>
        </div>
        <div class="baseline-item">
          <span class="dot offline"></span>
          <span>离线 {{ baselineStats.offline || 0 }}</span>
        </div>
      </div>
    </div>

    <!-- 主机列表 -->
    <div class="table-card">
      <div class="card-header" style="display: flex; align-items: center; gap: 1vw;">
        <span class="card-title">主机列表</span>
        <span class="online-count">
          <span class="dot online"></span> 在线 {{ onlineCount }}
        </span>
        <span class="online-count">
          <span class="dot offline"></span> 离线 {{ offlineCount }}
        </span>
      </div>
      <n-data-table
        :columns="cols"
        :data="agents"
        :bordered="false"
        size="small"
        :pagination="pagination"
        :row-key="(r) => r.id"
      />
    </div>
  </Layout>
</template>

<script setup>
import { ref, onMounted, h, nextTick, onUnmounted } from 'vue'
import { api } from '../api'
import Layout from '../layouts/MainLayout.vue'
import * as echarts from 'echarts'

const agents = ref([])
const pagination = ref({ pageSize: 15 })
const onlineCount = ref(0)
const offlineCount = ref(0)
const baselineStats = ref({})

const cards = ref([
  { key: 'cpu', title: 'CPU 负载分布', topLabel: '负载 TOP5', topList: [], levels: [] },
  { key: 'mem', title: '内存使用分布', topLabel: '内存 TOP5', topList: [], levels: [] },
  { key: 'disk', title: '磁盘使用分布', topLabel: '磁盘 TOP5', topList: [], levels: [] },
])

const cols = [
  { title: '主机名', key: 'hostname', minWidth: 120 },
  { title: 'IP', key: 'ip_addr', minWidth: 110 },
  { title: '探针', key: 'active_probes', minWidth: 70 },
  { title: 'CPU', key: 'cpu', minWidth: 70, render: (r) => r.cpu ? Number(r.cpu).toFixed(1) + '%' : '-' },
  { title: '内存', key: 'mem', minWidth: 70, render: (r) => r.mem ? Number(r.mem).toFixed(1) + '%' : '-' },
  { title: '磁盘', key: 'disk', minWidth: 70, render: (r) => r.disk ? Number(r.disk).toFixed(1) + '%' : '-' },
  { title: 'OS', key: 'os', minWidth: 120 },
  { title: '状态', key: 'last_seen', minWidth: 80, render: (r) => {
    const online = Date.now() / 1000 - r.last_seen < 60
    return h('span', { style: { color: online ? '#18A058' : '#D03050' } }, online ? '在线' : '离线')
  }},
  { title: '操作', key: 'id', width: 70, render: (r) => h('a', { href: '#/host/' + r.id }, '详情') },
]

let ws
let dirty = false

function connectWS() {
  const token = localStorage.getItem('token')
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  ws = new WebSocket(`${proto}://${location.host}/ws?token=${token}`)
  ws.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data)
      if (msg.type === 'event' || msg.type === 'alert' || msg.type === 'agent_offline') {
        dirty = true  // 只标记，不直接刷新
      }
    } catch (err) {}
  }
  ws.onclose = () => setTimeout(connectWS, 3000)
}

// 每 10 秒检查一次是否需要刷新
setInterval(() => {
  if (dirty) {
    dirty = false
    loadDashboard()
  }
}, 10000)

async function loadDashboard() {
  const agentData = await api.getAgents()
  agents.value = agentData.agents || []
  const now = Date.now() / 1000
  onlineCount.value = agents.value.filter(a => now - a.last_seen < 60).length
  offlineCount.value = agents.value.length - onlineCount.value

  try {
    const token = localStorage.getItem('token')
    const resp = await fetch('/api/baseline/stats', { headers: { 'Authorization': 'Bearer ' + token } })
    baselineStats.value = await resp.json()
  } catch (e) {}

  // 清空 TOP5
  cards.value.forEach(c => {
    c.topList = []
    c.levels = []
  })

  try {
    const assets = await api.getAssets()
    if (assets.agents) {
      assets.agents.filter(s => s.online).forEach(s => {
        const cpuCard = cards.value.find(c => c.key === 'cpu')
        const memCard = cards.value.find(c => c.key === 'mem')
        const diskCard = cards.value.find(c => c.key === 'disk')
        if (s.cpu_percent) cpuCard.topList.push({ name: s.hostname || s.agent_id, value: s.cpu_percent.toFixed(1) + '%' })
        if (s.mem_percent) memCard.topList.push({ name: s.hostname || s.agent_id, value: s.mem_percent.toFixed(1) + '%' })
        if (s.disk_percent) diskCard.topList.push({ name: s.hostname || s.agent_id, value: s.disk_percent.toFixed(1) + '%' })
        const agent = agents.value.find(a => a.id === s.agent_id)
        if (agent) {
          agent.cpu = s.cpu_percent
          agent.mem = s.mem_percent
          agent.disk = s.disk_percent
          agent.os = s.os || '-'
        }
      })
      cards.value.forEach(c => {
        c.topList = c.topList.slice(0, 5)
        const levelCounts = { '低负载': 0, '中负载': 0, '高负载': 0 }
        c.topList.forEach(item => {
          const v = parseFloat(item.value)
          if (v < 30) levelCounts['低负载']++
          else if (v < 60) levelCounts['中负载']++
          else levelCounts['高负载']++
        })
        c.levels = [
          { label: '低负载', count: levelCounts['低负载'], color: '#18A058' },
          { label: '中负载', count: levelCounts['中负载'], color: '#F0A020' },
          { label: '高负载', count: levelCounts['高负载'], color: '#D03050' },
        ]
      })
    }
  } catch (e) {}

  await nextTick()
  cards.value.forEach(card => {
    const el = document.getElementById('ring-' + card.key)
    if (!el) return
    const chart = echarts.init(el)
    const avg = card.key === 'cpu' ? 35 : card.key === 'mem' ? 50 : 40
    chart.setOption({
      series: [{
        type: 'pie',
        radius: ['58%', '72%'],
        label: { show: false },
        data: [
          { value: avg, name: '使用', itemStyle: { color: card.key === 'cpu' ? '#1A73E8' : card.key === 'mem' ? '#E04A5A' : '#E6A23C' } },
          { value: 100 - avg, name: '空闲', itemStyle: { color: '#E8EDF4' } },
        ],
      }],
    })
  })
}

onMounted(() => {
  connectWS()
  loadDashboard()
})

onUnmounted(() => {
  if (ws) ws.close()
})
</script>

<style scoped>
.baseline-card {
  background: #FFFFFF;
  border-radius: 0.8vw;
  padding: 1.5vh 1.2vw;
  box-shadow: 0 0.3vh 1.5vh rgba(0,0,0,0.04);
  margin-bottom: 1vh;
}

.baseline-stats {
  display: flex;
  gap: 2vw;
}

.baseline-item {
  display: flex;
  align-items: center;
  gap: 0.5vw;
  font-size: 0.9vw;
  color: #5F6368;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1vw;
  margin-bottom: 1vh;
}

.stat-card, .table-card {
  background: #FFFFFF;
  border-radius: 0.8vw;
  padding: 1.5vh 1.2vw;
  box-shadow: 0 0.3vh 1.5vh rgba(0,0,0,0.04);
}

.card-header {
  margin-bottom: 1vh;
}

.online-count {
  font-size: 0.8vw;
  color: #5F6368;
  display: flex;
  align-items: center;
  gap: 0.3vw;
}

.dot {
  width: 0.5vw;
  height: 0.5vw;
  border-radius: 50%;
  display: inline-block;
}

.dot.online {
  background: #18A058;
}

.dot.offline {
  background: #D03050;
}

.card-title {
  font-size: 1vw;
  font-weight: 600;
  color: #202124;
}

.card-content {
  display: flex;
  gap: 1vw;
}

.ring-chart {
  width: 5vw;
  height: 5vw;
  flex-shrink: 0;
}

.stat-levels {
  display: flex;
  flex-direction: column;
  gap: 0.4vh;
  font-size: 0.8vw;
}

.level-row {
  display: flex;
  gap: 0.5vw;
}

.top-list {
  flex: 1;
  font-size: 0.8vw;
}

.top-header {
  color: #5F6368;
  border-bottom: 1px solid #F1F3F4;
  padding-bottom: 0.5vh;
  margin-bottom: 0.5vh;
}

.top-row {
  display: flex;
  justify-content: space-between;
  padding: 0.4vh 0;
}

.top-name {
  color: #5F6368;
}

.top-value {
  font-weight: 500;
}
</style>


onUnmounted(() => {
  if (ws) ws.close()
})

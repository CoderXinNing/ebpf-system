<template>
  <n-card title="事件流">
    <template #header-extra>
      <n-space>
        <n-input v-model:value="filter" placeholder="筛选PID/进程/文件" size="small" clearable style="width:200px" />
        <n-button size="small" @click="refresh">🔄 刷新</n-button>
      </n-space>
    </template>
    <n-spin :show="loading">
      <n-data-table :columns="columns" :data="filteredEvents" :bordered="false" size="small" max-height="500" />
    </n-spin>
  </n-card>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { api } from '../utils/api'

const loading = ref(true)
const events = ref([])
const filter = ref('')
const agents = ref([])

const columns = [
  { title: '时间', key: 'timestamp', width: 90, render: (row) => new Date(row.timestamp*1000).toLocaleTimeString() },
  { title: 'Agent', key: 'agent_id', width: 80, render: (row) => getAgentIP(row.agent_id) },
  { title: '探针', key: 'probe_name', width: 130 },
  { title: 'PID', key: 'pid', width: 60 },
  { title: '进程', key: 'comm', width: 100 },
  { title: '文件', key: 'filename', ellipsis: { tooltip: true } },
]

function getAgentIP(agentId) {
  const a = agents.value.find(a => a.id === agentId)
  return a ? a.ip_addr : agentId?.slice(0,10)
}

const filteredEvents = computed(() => {
  if (!filter.value) return events.value
  const f = filter.value.toLowerCase()
  return events.value.filter(e =>
    String(e.pid).includes(f) ||
    (e.comm||'').toLowerCase().includes(f) ||
    (e.filename||'').toLowerCase().includes(f) ||
    (e.probe_name||"").toLowerCase().includes(f) ||
    getAgentIP(e.agent_id).toLowerCase().includes(f)
  )
})

async function refresh() {
  loading.value = true
  try {
    const [evtData, agtData] = await Promise.all([api.getEvents(), api.getAgents()])
    events.value = evtData.events || []
    agents.value = agtData.agents || []
  } catch(e) {}
  loading.value = false
}
onMounted(refresh)
</script>

<template>
  <Layout>
    <n-card title="事件流" size="small" :bordered="false">
      <n-data-table
        :columns="cols"
        :data="events"
        :bordered="false"
        size="small"
        :pagination="pagination"
        :row-key="(row) => row.id"
      />
      <n-button @click="load" size="small" style="margin-top:12px">🔄 刷新</n-button>
    </n-card>
  </Layout>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { api } from '../api'
import Layout from '../layouts/MainLayout.vue'

const events = ref([]), agents = ref([])
const cols = [
  { title: '时间', key: 'timestamp', minWidth: 80, render: (r) => new Date(r.timestamp*1000).toLocaleTimeString() },
  { title: '主机', key: 'hostname', minWidth: 80, render: (r) => {
    const a = agents.value.find(a => a.id === r.agent_id)
    return a ? a.hostname : (r.agent_id || '').slice(0,12)
  }},
  { title: 'IP', key: 'ip', minWidth: 80, render: (r) => {
    const a = agents.value.find(a => a.id === r.agent_id)
    return a ? a.ip_addr : '-'
  }},
  { title: '探针', key: 'probe_name', minWidth: 80 },
  { title: 'PID', key: 'pid', minWidth: 80 },
  { title: '进程', key: 'comm', minWidth: 80 },
  { title: '文件', key: 'filename', ellipsis: { tooltip: true } }
]

const pagination = reactive({
  page: 1, pageSize: 20, showSizePicker: true,
  pageSizes: [10, 20, 50, 100],
  onChange: (p) => { pagination.page = p },
  onUpdatePageSize: (s) => { pagination.pageSize = s; pagination.page = 1 }
})

async function load() {
  try {
    const [evt, agt] = await Promise.all([api.getEvents(), api.getAgents()])
    agents.value = agt.agents || []
    events.value = evt.events || []
  } catch(e) {}
}
onMounted(load)
setInterval(load, 30000)
  setInterval(() => { load() }, 30000)
</script>

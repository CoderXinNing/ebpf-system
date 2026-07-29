<template>
  <Layout>
    <n-grid :cols="4" :x-gap="12" style="margin-bottom:16px">
      <n-grid-item v-for="s in stats" :key="s.label">
        <n-card size="small" :bordered="false" class="stat-card">
          <div class="stat-value">{{ s.value }}</div>
          <div class="stat-label">{{ s.label }}</div>
        </n-card>
      </n-grid-item>
    </n-grid>

    <n-card title="主机列表" size="small" :bordered="false">
      <n-tabs type="line" v-model:value="filter" @update:value="load">
        <n-tab-pane name="all" tab="全部" />
        <n-tab-pane name="online" tab="在线" />
        <n-tab-pane name="offline" tab="离线" />
      </n-tabs>
      <n-data-table
        :columns="cols"
        :data="filteredAgents"
        :bordered="false"
        size="small"
        :pagination="pagination"
        :row-key="(row) => row.id"
      />
    </n-card>
  </Layout>
</template>

<script setup>
import { ref, reactive, computed, onMounted, h } from 'vue'
import { api } from '../api'
import Layout from '../layouts/MainLayout.vue'

const stats = ref([
  {label:'在线主机',value:0},{label:'离线主机',value:0},{label:'进程总数',value:0},{label:'用户总数',value:0}
])
const agents = ref([]), assets = ref([]), filter = ref('all')

const pagination = reactive({
  page: 1, pageSize: 20, showSizePicker: true,
  pageSizes: [10, 20, 50, 100],
  onChange: (p) => { pagination.page = p },
  onUpdatePageSize: (s) => { pagination.pageSize = s; pagination.page = 1 }
})

const filteredAgents = computed(() => {
  const now = Math.floor(Date.now()/1000)
  if (filter.value === 'online') return agents.value.filter(a => now - a.last_seen < 60)
  if (filter.value === 'offline') return agents.value.filter(a => now - a.last_seen >= 60)
  return agents.value
})

const cols = [
  { title: '主机名', key: 'hostname', width: 160 },
  { title: 'IP', key: 'ip_addr', width: 140 },
  { title: '发行版', key: 'os', width: 160, render: (r) => r.os || '-' },
  { title: '内核', key: 'kernel', width: 160, render: (r) => r.kernel || '-' },
  { title: '进程数', key: 'procs', width: 70 },
  { title: '用户数', key: 'users', width: 70 },
  { title: '探针', key: 'active_probes', width: 50 },
  { title: '状态', key: 'last_seen', width: 60, render: (r) => {
    const now = Math.floor(Date.now()/1000)
    return now - r.last_seen < 60 ? '🟢' : '🔴'
  }},
  { title: '操作', key: 'id', width: 60, render: (r) => h('a', { href: '#/host/' + r.id }, '详情') }
]

async function load() {
  try {
    const [ag, as] = await Promise.all([api.getAgents(), api.getAssets()])
    const agentList = ag.agents || []
    const assetList = as.agents || []
    const assetMap = {}
    assetList.forEach(a => { assetMap[a.agent_id] = a })

    agents.value = agentList.map(a => ({
      ...a,
      os: assetMap[a.id]?.hostname || '-',
      kernel: a.kernel_info?.version || '-',
      procs: assetMap[a.id]?.process_count || 0,
      users: assetMap[a.id]?.user_count || 0,
    }))

    const now = Math.floor(Date.now()/1000)
    stats.value[0].value = agentList.filter(a => now - a.last_seen < 60).length
    stats.value[1].value = agentList.filter(a => now - a.last_seen >= 60).length
    stats.value[2].value = agentList.reduce((s, a) => s + (assetMap[a.id]?.process_count || 0), 0)
    stats.value[3].value = agentList.reduce((s, a) => s + (assetMap[a.id]?.user_count || 0), 0)
  } catch(e) {}
}
onMounted(load)
</script>

<style scoped>
.stat-card { text-align: center; padding: 8px 0; }
.stat-value { font-size: 28px; font-weight: 700; color: #58a6ff; }
.stat-label { font-size: 12px; color: #8b949e; margin-top: 2px; }
</style>

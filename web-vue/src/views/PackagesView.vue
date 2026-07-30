<template>
  <Layout>
    <n-card title="软件应用" size="small" :bordered="false">
      <n-input v-model:value="search" placeholder="搜索软件名..." clearable style="margin-bottom:12px;width:300px" />
      <n-data-table :columns="cols" :data="filtered" size="small" :bordered="false" :pagination="pagination" :row-key="(row) => row.name" />
    </n-card>

    <n-modal v-model:show="show" title="已安装该软件的主机" style="width:700px" preset="card" :bordered="false">
      <n-data-table v-if="detail.length" :columns="detailCols" :data="detail" size="small" :bordered="false" />
      <n-empty v-else />
    </n-modal>
  </Layout>
</template>

<script setup>
import { ref, reactive, computed, onMounted, h } from 'vue'
import { api } from '../api'
import Layout from '../layouts/MainLayout.vue'

const summary = ref([]), show = ref(false), detail = ref([]), search = ref('')
const agents = ref([])

const pagination = reactive({
  page: 1, pageSize: 20, showSizePicker: true,
  pageSizes: [10, 20, 50, 100]
})

const filtered = computed(() => {
  if (!search.value) return summary.value
  return summary.value.filter(s => s.name.toLowerCase().includes(search.value.toLowerCase()))
})

const cols = [
  { title: '软件名', key: 'name', minWidth: 80 },
  { title: '版本', key: 'version', minWidth: 80 },
  { title: '包管理器', key: 'manager', minWidth: 80 },
  { title: '主机数', key: 'count', minWidth: 80 },
  { title: '操作', key: 'name', minWidth: 80, render: (r) => h('a', { href: 'javascript:void(0)', onClick: () => showDetail(r.name), style: 'color:#58a6ff' }, '查看主机') }
]
const detailCols = [
  { title: '主机名', key: 'hostname' }, { title: 'IP', key: 'ip_addr' },
  { title: '版本', key: 'version' }, { title: '操作', key: 'agent_id', minWidth: 80, render: (r) => h('a', { href: '#/host/' + r.agent_id }, '详情') }
]

function showDetail(name) {
  const s = summary.value.find(s => s.name === name)
  detail.value = s ? s.hosts.map(h => ({
    hostname: h.hostname, ip_addr: h.ip_addr || '-', version: h.version, agent_id: h.agent_id
  })) : []
  show.value = true
}

onMounted(async () => {
  setInterval(() => { load() }, 30000)
  try {
    const [agt] = await Promise.all([api.getAgents()])
    agents.value = agt.agents || []

    // 遍历所有Agent的资产，提取软件包
    const map = {}
    for (const a of agents.value) {
      try {
        const d = await api.getAssetDetail(a.id)
        const sysData = d.system || {}
        const pkgs = sysData.packages || []
        pkgs.forEach(p => {
          if (!map[p.name]) map[p.name] = { hosts: [], count: 0, seen: new Set(), version: p.version, manager: p.manager }
          if (!map[p.name].seen.has(a.id)) {
            map[p.name].seen.add(a.id)
            map[p.name].hosts.push({ hostname: a.hostname, ip_addr: a.ip_addr, version: p.version, agent_id: a.id })
            map[p.name].count++
          }
        })
      } catch(e) {}
    }
    summary.value = Object.entries(map)
      .map(([name, v]) => ({ name, count: v.count, version: v.version, manager: v.manager, hosts: v.hosts }))
      .sort((a, b) => b.count - a.count)
  } catch(e) {}
})
</script>

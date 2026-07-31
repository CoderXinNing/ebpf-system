<template>
  <Layout>
    <div style="display:flex;gap:16px;height:calc(100vh - 120px)">
      <div style="width:240px;flex-shrink:0;background:#fff;border-radius:8px;padding:16px;display:flex;flex-direction:column">
        <n-input v-model:value="groupSearch" placeholder="搜索业务组..." size="small" clearable style="margin-bottom:12px" />
        <div style="flex:1;overflow-y:auto">
          <div v-for="item in treeList" :key="item.key"
            style="padding:8px 12px;cursor:pointer;border-radius:4px;font-size:13px;margin-bottom:2px;display:flex;justify-content:space-between"
            :style="{background: selectedGroup===item.key ? '#e8f0fe' : 'transparent', fontWeight: selectedGroup===item.key ? '600' : 'normal'}"
            @click="selectedGroup = item.key">
            <span>{{ item.label }}</span>
            <span style="color:#999">{{ item.count }}</span>
          </div>
        </div>
      </div>

      <div style="flex:1;min-width:0">
        <n-card size="small" :bordered="false">
          <div style="display:flex;gap:8px;margin-bottom:12px">
            <n-input v-model:value="ipFilter" placeholder="搜索IP..." size="small" style="width:160px" clearable />
            <span style="font-size:13px;color:#666;line-height:28px">{{ filtered.length }}台</span>
          </div>
          <n-data-table :columns="cols" :data="filtered" size="small" :bordered="false" :pagination="pagination" :row-key="(r) => r.id" />
        </n-card>
      </div>
    </div>
  </Layout>
</template>

<script setup>
import { ref, reactive, computed, onMounted, h } from 'vue'
import { api } from '../api'
import Layout from '../layouts/MainLayout.vue'

const agents = ref([])
const groupSearch = ref('')
const selectedGroup = ref('all')
const ipFilter = ref('')
const treeList = ref([])

const pagination = reactive({
  page: 1, pageSize: 20, showSizePicker: true,
  pageSizes: [10, 20, 50, 100],
  onUpdatePage: (p) => { pagination.page = p },
  onUpdatePageSize: (s) => { pagination.pageSize = s; pagination.page = 1 }
})

const cols = [
  { title: '主机IP', key: 'ip_addr', minWidth: 130 },
  { title: '主机名', key: 'hostname', minWidth: 140 },
  { title: '业务组', key: 'group', minWidth: 100 },
  { title: 'OS', key: 'os', minWidth: 160 },
  { title: '操作', key: 'id', minWidth: 80, render: (row) => h('a', { href: '#/host/' + row.id, style: 'color:#1e6fff' }, '详情') }
]

const filtered = computed(() => {
  let list = agents.value
  if (selectedGroup.value !== 'all') {
    list = list.filter(a => {
      const g = a.group || '未分组'
      return g === selectedGroup.value
    })
  }
  if (ipFilter.value) {
    list = list.filter(a => a.ip_addr && a.ip_addr.includes(ipFilter.value))
  }
  return list
})

function buildTree() {
  const map = {}
  agents.value.forEach(a => {
    const g = a.group || '未分组'
    if (!map[g]) map[g] = 0
    map[g]++
  })
  const list = [{ label: '全部主机', key: 'all', count: agents.value.length }]
  Object.entries(map).forEach(([name, count]) => {
    if (!groupSearch.value || name.includes(groupSearch.value)) {
      list.push({ label: name, key: name, count })
    }
  })
  treeList.value = list
}

onMounted(async () => {
  try {
    const agRes = await api.getAgents()
    const asRes = await api.getAssets()

    const agentList = agRes.agents || []
    const assetList = asRes.agents || []

    const assetMap = {}
    assetList.forEach(item => {
      assetMap[item.agent_id] = item
    })

    agents.value = agentList.map(a => {
      const asset = assetMap[a.id] || {}
      return {
        id: a.id,
        hostname: a.hostname,
        ip_addr: a.ip_addr,
        group: a.group || '未分组',
        last_seen: a.last_seen,
        os: asset.os || a.kernel_info?.version || '-',
        active_probes: a.active_probes,
      }
    })

    buildTree()
  } catch (e) {
    console.error('加载失败:', e)
  }
})
</script>

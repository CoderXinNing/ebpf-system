<template>
  <Layout>
    <n-card title="软件应用" size="small" :bordered="false">
      <div style="display:flex;gap:12px;margin-bottom:12px">
        <n-input v-model:value="search" placeholder="软件名" clearable size="small" style="width:200px" />
        <n-input v-model:value="searchVersion" placeholder="版本号" clearable size="small" style="width:160px" />
        <n-select v-model:value="searchManager" :options="managerOptions" placeholder="包管理器" clearable size="small" style="width:130px" />
      </div>
      <n-data-table :columns="cols" :data="filtered" size="small" :bordered="false" :pagination="pagination" :row-key="(r) => r.name" />
    </n-card>
  </Layout>
</template>

<script setup>
import { ref, reactive, computed, onMounted, h } from 'vue'
import { api } from '../api'
import Layout from '../layouts/MainLayout.vue'

const summary = ref([]), search = ref(''), searchVersion = ref(''), searchManager = ref(null)
const managerOptions = [{label:'全部',value:null},{label:'dpkg',value:'dpkg'},{label:'rpm',value:'rpm'},{label:'apk',value:'apk'},{label:'pacman',value:'pacman'}]

const pagination = reactive({
  page: 1, pageSize: 20, showSizePicker: true,
  pageSizes: [10, 20, 50, 100],
  onUpdatePage: (p) => { pagination.page = p },
  onUpdatePageSize: (s) => { pagination.pageSize = s; pagination.page = 1 }
})

const cols = [
  { title: '软件名', key: 'name', minWidth: 180 },
  { title: '版本', key: 'version', minWidth: 100 },
  { title: '包管理器', key: 'manager', minWidth: 80 },
  { title: '主机数', key: 'count', minWidth: 80 },
  { title: '操作', key: 'name', minWidth: 80, render: (r) => h('a', { href: '#/pkg_detail/' + encodeURIComponent(r.name), style: 'color:#1e6fff' }, '查看主机') }
]

const filtered = computed(() => {
  return summary.value.filter(s => {
    let match = true
    if (search.value) match = match && s.name.toLowerCase().includes(search.value.toLowerCase())
    if (searchVersion.value) match = match && (s.version || '').toLowerCase().includes(searchVersion.value.toLowerCase())
    if (searchManager.value) match = match && s.manager === searchManager.value
    return match
  })
})

onMounted(async () => {
  try {
    const agt = await api.getAgents()
    const agents = agt.agents || []
    const map = {}
    for (const a of agents) {
      try {
        const d = await api.getAssetDetail(a.id)
        const sysData = d.system || {}
        const pkgs = sysData.packages || []
        pkgs.forEach(p => {
          if (!map[p.name]) map[p.name] = { name: p.name, version: p.version, manager: p.manager, count: 0, seen: new Set() }
          if (!map[p.name].seen.has(a.id)) {
            map[p.name].seen.add(a.id)
            map[p.name].count++
          }
        })
      } catch(e) {}
    }
    summary.value = Object.values(map).sort((a, b) => b.count - a.count)
  } catch(e) {}
})
</script>

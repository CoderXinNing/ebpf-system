<template>
  <Layout>
    <n-button @click="$router.back()" size="small" style="margin-bottom:12px">← 返回</n-button>
    <n-card :title="pkgName" size="small" :bordered="false">
      <n-input v-model:value="search" placeholder="搜索主机IP..." clearable style="margin-bottom:12px;width:300px" />
      <n-data-table :columns="cols" :data="filtered" size="small" :bordered="false" :pagination="pagination" :row-key="(r) => r.ip+r.pid" />
    </n-card>
  </Layout>
</template>

<script setup>
import { ref, reactive, computed, onMounted, h } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '../api'
import Layout from '../layouts/MainLayout.vue'

const route = useRoute()
const pkgName = ref(decodeURIComponent(route.params.name))
const items = ref([]), search = ref('')

const pagination = reactive({
  page: 1, pageSize: 20, showSizePicker: true,
  pageSizes: [10, 20, 50, 100],
  onUpdatePage: (p) => { pagination.page = p },
  onUpdatePageSize: (s) => { pagination.pageSize = s; pagination.page = 1 }
})

const cols = [
  { title: '主机IP', key: 'ip', minWidth: 130, render: (r) => h('span', {}, [h('span', { style: 'color:#67c23a;margin-right:4px' }, '●'), r.ip]) },
  { title: '版本', key: 'version', minWidth: 100 },
  { title: '包管理器', key: 'manager', minWidth: 80 },
  { title: '大小(KB)', key: 'size_kb', minWidth: 80 },
]

const filtered = computed(() => {
  if (!search.value) return items.value
  return items.value.filter(i => i.ip.includes(search.value))
})

onMounted(async () => {
  try {
    const agt = await api.getAgents()
    const agents = agt.agents || []
    const list = []
    for (const a of agents) {
      try {
        const d = await api.getAssetDetail(a.id)
        const sysData = d.system || {}
        const pkgs = sysData.packages || []
        pkgs.filter(p => p.name === pkgName.value).forEach(p => {
          list.push({ ip: a.ip_addr, version: p.version, manager: p.manager })
        })
      } catch(e) {}
    }
    items.value = list
  } catch(e) {}
})
</script>

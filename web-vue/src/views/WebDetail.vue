<template>
  <Layout>
    <n-button @click="$router.back()" size="small" style="margin-bottom:12px">← 返回</n-button>
    <n-card :title="compName" size="small" :bordered="false">
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
const compName = ref(decodeURIComponent(route.params.name))
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
  { title: '部署路径', key: 'base_path', ellipsis: { tooltip: true }, minWidth: 200 },
  { title: 'PID', key: 'pid', minWidth: 60 },
]

const filtered = computed(() => {
  if (!search.value) return items.value
  return items.value.filter(i => i.ip.includes(search.value))
})

onMounted(async () => {
  try {
    const type = '所有'
    const d = await api.getAssetsByCategory(type)
    const webTypes = ['框架', 'Web应用', '数据库']
    const list = (d.items || []).filter(i => {
      const name = i.service_name || i.name || ''
      return webTypes.includes(i.type) && name === compName.value
    }).map(i => ({
      ip: i.hostname || i.ip_addr || '-',
      version: i.version,
      base_path: i.base_path || i.config_path || '-',
      pid: i.pid,
    }))
    items.value = list
  } catch(e) {}
})
</script>

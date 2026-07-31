<template>
  <Layout>
    <n-space style="margin-bottom:16px">
      <n-select v-model:value="type" :options="types" style="width:160px" @update:value="load" />
      <n-button @click="load">刷新</n-button>
    </n-space>
    <n-data-table :columns="cols" :data="items" :bordered="false" size="small" />
  </Layout>
</template>

<script setup>
import { ref, onMounted, h } from 'vue'
import { api } from '../api'
import Layout from '../layouts/MainLayout.vue'

const type = ref('所有')
const types = [{label:'全部',value:'所有'},{label:'数据库',value:'数据库'},{label:'Web服务器',value:'Web服务器'},{label:'中间件',value:'中间件'},{label:'运行时',value:'运行时'},{label:'框架',value:'框架'},{label:'容器',value:'容器'},{label:'监控',value:'监控'},{label:'其他',value:'其他'}]
const items = ref([])

const cols = [
  { title: '主机', key: 'hostname', width: 140 },
  { title: '服务', key: 'service_name', width: 130 },
  { title: '类型', key: 'type', width: 80 },
  { title: '版本', key: 'version', width: 120 },
  { title: 'PID', key: 'pid', width: 60 },
  { title: '端口', key: 'listen_port', render: (r) => (r.listen_port||[]).join(',') },
  { title: '操作', key: 'agent_id', width: 60, render: (r) => h('a', { href: '#/host/' + r.agent_id, style: 'color:#18c08c' }, '主机') }
]

async function load() {
  try {
    const d = await api.getAssetsByCategory(type.value)
    items.value = d.items || []
  } catch(e) {}
}
onMounted(load)
</script>

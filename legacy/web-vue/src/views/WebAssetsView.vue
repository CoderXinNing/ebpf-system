<template>
  <Layout>
    <n-card title="Web资产" size="small" :bordered="false">
      <n-tabs type="line" v-model:value="tab" @update:value="load">
        <n-tab-pane name="全部" tab="全部" />
        <n-tab-pane name="框架" tab="框架" />
        <n-tab-pane name="Web应用" tab="Web应用" />
        <n-tab-pane name="数据库" tab="数据库" />
      </n-tabs>
      <n-input v-model:value="search" placeholder="搜索..." clearable style="margin:12px 0;width:300px" />
      <n-data-table :columns="cols" :data="filtered" size="small" :bordered="false" :pagination="pagination" :row-key="(r) => r.name" />
    </n-card>
  </Layout>
</template>

<script setup>
import { ref, reactive, computed, onMounted, h } from 'vue'
import { api } from '../api'
import Layout from '../layouts/MainLayout.vue'

const tab = ref('全部'), summary = ref([]), search = ref('')

const pagination = reactive({
  page: 1, pageSize: 20, showSizePicker: true,
  pageSizes: [10, 20, 50, 100],
  onUpdatePage: (p) => { pagination.page = p },
  onUpdatePageSize: (s) => { pagination.pageSize = s; pagination.page = 1 }
})

const cols = [
  { title: '组件名', key: 'name', minWidth: 180 },
  { title: '主机数', key: 'count', minWidth: 80 },
  { title: '类型', key: 'type', minWidth: 90 },
  { title: '操作', key: 'name', minWidth: 80, render: (r) => h('a', { href: '#/web_detail/' + encodeURIComponent(r.name), style: 'color:#1e6fff' }, '查看主机') }
]

const filtered = computed(() => {
  if (!search.value) return summary.value
  return summary.value.filter(s => s.name.toLowerCase().includes(search.value.toLowerCase()))
})

async function load() {
  try {
    const type = tab.value === '全部' ? '所有' : tab.value
    const d = await api.getAssetsByCategory(type)
    const webTypes = ['框架', 'Web应用', '数据库']
    const items = (d.items || []).filter(i => webTypes.includes(i.type))

    const map = {}
    items.forEach(i => {
      const name = i.service_name || i.name || '未知'
      if (!map[name]) map[name] = { name, count: 0, seen: new Set(), type: i.type }
      if (!map[name].seen.has(i.agent_id)) {
        map[name].seen.add(i.agent_id)
        map[name].count++
      }
    })
    summary.value = Object.values(map).sort((a, b) => b.count - a.count)
  } catch(e) {}
}
onMounted(load)
</script>

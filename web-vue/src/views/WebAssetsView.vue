<template>
  <Layout>
    <n-card title="Web资产" size="small" :bordered="false">
      <n-tabs type="line" v-model:value="tab" @update:value="load">
        <n-tab-pane name="全部" tab="全部" />
        <n-tab-pane name="框架" tab="框架" />
        <n-tab-pane name="Web应用" tab="Web应用" />
        <n-tab-pane name="数据库" tab="数据库" />
      </n-tabs>
      <n-data-table :columns="cols" :data="summary" size="small" :bordered="false" :pagination="pagination" :row-key="(row) => row.name" style="margin-top:12px" />
    </n-card>

    <n-modal v-model:show="show" title="主机列表" style="width:750px" preset="card" :bordered="false">
      <n-data-table v-if="detail.length" :columns="detailCols" :data="detail" size="small" :bordered="false" />
      <n-empty v-else />
    </n-modal>
  </Layout>
</template>

<script setup>
import { ref, reactive, onMounted, h } from 'vue'
import { api } from '../api'
import Layout from '../layouts/MainLayout.vue'

const tab = ref('全部'), summary = ref([]), show = ref(false), detail = ref([])

const pagination = reactive({
  page: 1, pageSize: 20, showSizePicker: true,
  pageSizes: [10, 20, 50, 100],
  onChange: (p) => { pagination.page = p },
  onUpdatePageSize: (s) => { pagination.pageSize = s; pagination.page = 1 }
})

const cols = [
  { title: '组件名', key: 'name', minWidth: 80 },
  { title: '主机数', key: 'count', minWidth: 80 },
  { title: '类型', key: 'type', minWidth: 80 },
  { title: '操作', key: 'name', minWidth: 80, render: (r) => h('a', { href: 'javascript:void(0)', onClick: () => showDetail(r.name), style: 'color:#58a6ff' }, '查看主机') }
]
const detailCols = [
  { title: '主机名', key: 'hostname' }, { title: 'IP', key: 'ip_addr' }, { title: '版本', key: 'version' },
  { title: '部署路径', key: 'base_path', ellipsis: { tooltip: true }, minWidth: 80 },
  { title: 'PID', key: 'pid', minWidth: 80 },
  { title: '操作', key: 'agent_id', minWidth: 80, render: (r) => h('a', { href: '#/host/' + r.agent_id }, '详情') }
]

function showDetail(name) {
  const s = summary.value.find(s => s.name === name)
  detail.value = s ? s.hosts.map(h => ({
    hostname: h.hostname, ip_addr: h.ip_addr || '-', version: h.version,
    base_path: h.base_path || h.config_path || '-', pid: h.pid, agent_id: h.agent_id
  })) : []
  show.value = true
}

async function load() {
  try {
    const type = tab.value === '全部' ? '所有' : tab.value
    const d = await api.getAssetsByCategory(type)
    const webTypes = ['框架', 'Web应用', 'Web关键路径']
    const items = (d.items || []).filter(i => webTypes.includes(i.type))

    const map = {}
    items.forEach(i => {
      const name = i.service_name || i.name || '未知'
      if (!map[name]) map[name] = { hosts: [], count: 0, seen: new Set(), type: i.type }
      if (!map[name].seen.has(i.agent_id)) {
        map[name].seen.add(i.agent_id)
        map[name].hosts.push(i)
        map[name].count++
      }
    })
    summary.value = Object.entries(map)
      .map(([name, v]) => ({ name, count: v.count, type: v.type, hosts: v.hosts }))
      .sort((a, b) => b.count - a.count)
  } catch(e) {}
}
onMounted(load)
</script>

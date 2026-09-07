<template>
  <Layout>
    <n-card title="端口服务" size="small" :bordered="false">
      <n-input v-model:value="search" placeholder="搜索端口/进程名..." clearable style="margin-bottom:12px;width:300px" />
      <n-data-table :columns="cols" :data="filtered" size="small" :bordered="false" :pagination="pagination" :row-key="(r) => r.key" />
    </n-card>

    <n-modal v-model:show="show" :title="detailTitle" style="width:800px" preset="card" :bordered="false">
      <n-data-table v-if="detail.length" :columns="detailCols" :data="detail" size="small" :bordered="false" />
      <n-empty v-else />
    </n-modal>
  </Layout>
</template>

<script setup>
import { ref, reactive, computed, onMounted, h } from 'vue'
import { api } from '../api'
import Layout from '../layouts/MainLayout.vue'

const summary = ref([]), search = ref(''), show = ref(false), detail = ref([]), detailTitle = ref('')

const pagination = reactive({
  page: 1, pageSize: 20, showSizePicker: true,
  pageSizes: [10, 20, 50, 100],
  onUpdatePage: (p) => { pagination.page = p },
  onUpdatePageSize: (s) => { pagination.pageSize = s; pagination.page = 1 }
})

const cols = [
  { title: '端口号:进程名', key: 'label', minWidth: 160 },
  { title: '主机数', key: 'count', minWidth: 80 },
  { title: '操作', key: 'label', minWidth: 100, render: (r) => h('a', { href: '#/port_detail/' + encodeURIComponent(r.label), style: 'color:#1e6fff' }, '查看主机') }
]

const detailCols = [
  { title: '主机IP', key: 'ip', minWidth: 130, render: (r) => h('span', {}, [h('span', { style: 'color:#67c23a;margin-right:4px' }, '●'), r.ip]) },
  { title: '绑定IP', key: 'bind_ip', minWidth: 120 },
  { title: '协议', key: 'protocol', minWidth: 60 },
  { title: 'PID', key: 'pid', minWidth: 60 },
  { title: '运行用户', key: 'user', minWidth: 80 },
  { title: '进程启动时间', key: 'start_time', minWidth: 140 },
]

const filtered = computed(() => {
  if (!search.value) return summary.value
  return summary.value.filter(s => s.label.toLowerCase().includes(search.value.toLowerCase()))
})

function showDetail(r) {
  detailTitle.value = r.label
  detail.value = r.hosts || []
  show.value = true
}

onMounted(async () => {
  try {
    const agt = await api.getAgents()
    const agents = agt.agents || []
    const map = {}

    for (const a of agents) {
      try {
        const d = await api.getAssetDetail(a.id)
        const procs = d.processes || []
        procs.filter(p => (p.listening_ports||[]).length > 0).forEach(p => {
          p.listening_ports.forEach(port => {
            const key = `${port}:${p.name}`
            if (!map[key]) map[key] = { key, label: key, count: 0, hosts: [] }
            map[key].count++
            map[key].hosts.push({
              ip: a.ip_addr, bind_ip: '0.0.0.0', protocol: 'TCP',
              pid: p.pid, user: p.user, start_time: '-',
            })
          })
        })
      } catch(e) {}
    }

    summary.value = Object.values(map).sort((a, b) => b.count - a.count)
  } catch(e) {}
})
</script>

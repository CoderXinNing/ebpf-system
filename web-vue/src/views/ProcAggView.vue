<template>
  <Layout>
    <n-card title="进程聚合" size="small" :bordered="false">
      <n-input v-model:value="search" placeholder="搜索进程名..." clearable style="margin-bottom:12px;width:300px" />
      <n-data-table :columns="cols" :data="filtered" size="small" :bordered="false" :pagination="pagination" :row-key="(r) => r.name" />
    </n-card>

    <n-modal v-model:show="show" :title="detailTitle" style="width:850px" preset="card" :bordered="false">
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
  { title: '进程名', key: 'name', minWidth: 180 },
  { title: '进程分类', key: 'category', minWidth: 100 },
  { title: '主机数', key: 'count', minWidth: 80 },
  { title: '操作', key: 'name', minWidth: 100, render: (r) => h('a', { href: '#/proc_agg/' + encodeURIComponent(r.name), style: 'color:#1e6fff' }, '查看主机') }
]

const detailCols = [
  { title: '主机IP', key: 'ip', minWidth: 130, render: (r) => h('span', {}, [h('span', { style: 'color:#67c23a;margin-right:4px' }, '●'), r.ip]) },
  { title: '进程状态', key: 'state', minWidth: 70 },
  { title: '进程版本', key: 'version', minWidth: 100 },
  { title: '进程路径', key: 'exe_path', ellipsis: { tooltip: true }, minWidth: 180 },
  { title: '安装包安装', key: 'is_pkg', minWidth: 80 },
  { title: 'PID', key: 'pid', minWidth: 60 },
  { title: '运行用户', key: 'user', minWidth: 80 },
]

const filtered = computed(() => {
  if (!search.value) return summary.value
  return summary.value.filter(s => s.name.toLowerCase().includes(search.value.toLowerCase()))
})

function showDetail(r) {
  detailTitle.value = r.name
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
        const svcs = (d.system || {}).services || []
        const svcMap = {}
        svcs.forEach(s => { if (s.pid > 0) svcMap[s.pid] = s })

        procs.forEach(p => {
          if (p.ppid <= 2) return // 跳过内核线程
          const name = p.name
          if (!map[name]) map[name] = { name, category: svcMap[p.pid]?.type || '其它', count: 0, hosts: [] }
          map[name].count++
          map[name].hosts.push({
            ip: a.ip_addr, state: p.state, version: svcMap[p.pid]?.version || '-',
            exe_path: p.exe_path, is_pkg: svcMap[p.pid] ? '是' : '否',
            pid: p.pid, user: p.user,
          })
        })
      } catch(e) {}
    }

    summary.value = Object.values(map).sort((a, b) => b.count - a.count)
  } catch(e) {}
})
</script>

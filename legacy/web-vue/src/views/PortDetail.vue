<template>
  <Layout>
    <n-button @click="$router.back()" size="small" style="margin-bottom:12px">← 返回</n-button>
    <n-card :title="portLabel" size="small" :bordered="false">
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
const portLabel = ref(decodeURIComponent(route.params.name))
const items = ref([]), search = ref('')

const pagination = reactive({
  page: 1, pageSize: 20, showSizePicker: true,
  pageSizes: [10, 20, 50, 100],
  onUpdatePage: (p) => { pagination.page = p },
  onUpdatePageSize: (s) => { pagination.pageSize = s; pagination.page = 1 }
})

const cols = [
  { title: '主机IP', key: 'ip', minWidth: 130, render: (r) => h('span', {}, [h('span', { style: 'color:#67c23a;margin-right:4px' }, '●'), r.ip]) },
  { title: '绑定IP', key: 'bind_ip', minWidth: 120 },
  { title: '协议', key: 'protocol', minWidth: 60 },
  { title: 'PID', key: 'pid', minWidth: 60 },
  { title: '运行用户', key: 'user', minWidth: 80 },
  { title: '进程启动时间', key: 'start_time', minWidth: 140 },
]

const filtered = computed(() => {
  if (!search.value) return items.value
  return items.value.filter(i => i.ip.includes(search.value))
})

onMounted(async () => {
  try {
    const agt = await api.getAgents()
    const agents = agt.agents || []
    const [portStr, procName] = portLabel.value.split(':')
    const list = []
    for (const a of agents) {
      try {
        const d = await api.getAssetDetail(a.id)
        const procs = d.processes || []
        procs.filter(p => p.name === procName).forEach(p => {
          (p.listening_ports || []).filter(pn => pn === portStr).forEach(() => {
            list.push({
              ip: a.ip_addr, bind_ip: '0.0.0.0', protocol: 'TCP',
              pid: p.pid, user: p.user, start_time: p.start_time || '-',
            })
          })
        })
      } catch(e) {}
    }
    items.value = list
  } catch(e) {}
})
</script>

<template>
  <Layout>
    <n-button @click="$router.back()" size="small" style="margin-bottom:12px">← 返回</n-button>
    <n-tabs type="line" animated>
      <n-tab-pane name="sys" tab="系统">
        <n-card size="small" v-if="sys">
          <n-descriptions :column="3" size="small" bordered>
            <n-descriptions-item label="OS">{{ sys?.os?.name || sys?.name }}</n-descriptions-item>
            <n-descriptions-item label="内核">{{ sys?.os?.kernel || sys?.kernel }}</n-descriptions-item>
            <n-descriptions-item label="CPU">{{ sys?.cpu?.model }} x{{ sys?.cpu?.cores }}</n-descriptions-item>
            <n-descriptions-item label="内存">{{ sys?.memory?.total_mb }}MB</n-descriptions-item>
            <n-descriptions-item label="磁盘">{{ disks }}</n-descriptions-item>
            <n-descriptions-item label="时区">{{ sys?.timezone }}</n-descriptions-item>
          </n-descriptions>
        </n-card>
      </n-tab-pane>
      <n-tab-pane name="svc" tab="服务">
        <n-data-table v-if="svcItems.length" :columns="svcCols" :data="svcItems" size="small" :bordered="false" :pagination="paginationSvc" :row-key="(row) => row.name" />
        <n-empty v-else description="无" />
      </n-tab-pane>
      <n-tab-pane name="port" tab="端口">
        <n-data-table v-if="portItems.length" :columns="portCols" :data="portItems" size="small" :bordered="false" :pagination="paginationPort" :row-key="(row) => row.pid" />
        <n-empty v-else description="无" />
      </n-tab-pane>
      <n-tab-pane name="user" tab="用户">
        <n-data-table v-if="userItems.length" :columns="userCols" :data="userItems" size="small" :bordered="false" :pagination="paginationUser" :row-key="(row) => row.username" />
        <n-empty v-else description="无" />
      </n-tab-pane>
    </n-tabs>
  </Layout>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '../api'
import Layout from '../layouts/MainLayout.vue'

const route = useRoute()
const sys = ref(null), svcItems = ref([]), portItems = ref([]), userItems = ref([])

const paginationPort = reactive({ page: 1, pageSize: 10, showSizePicker: true, pageSizes: [10, 20, 50], onUpdatePage: (p) => { paginationPort.page = p }, onUpdatePageSize: (s) => { paginationPort.pageSize = s; paginationPort.page = 1 } })
const paginationUser = reactive({ page: 1, pageSize: 5, showSizePicker: true, pageSizes: [5, 10, 20], onUpdatePage: (p) => { paginationUser.page = p }, onUpdatePageSize: (s) => { paginationUser.pageSize = s; paginationUser.page = 1 } })
const paginationSvc = reactive({ page: 1, pageSize: 10, showSizePicker: true, pageSizes: [10, 20, 50], onUpdatePage: (p) => { paginationSvc.page = p }, onUpdatePageSize: (s) => { paginationSvc.pageSize = s; paginationSvc.page = 1 } })

const disks = computed(() => {
  const d = sys.value?.disks || []
  return d.map(d => `${d.mount_point} ${d.total_mb}MB`).join(', ')
})

const svcCols = [
  { title: '名称', key: 'name', minWidth: 130 }, { title: '类型', key: 'type', minWidth: 80 },
  { title: '版本', key: 'version', minWidth: 100 }, { title: 'PID', key: 'pid', minWidth: 60 },
  { title: '端口', key: 'listen_port', render: (r) => (r.listen_port||[]).join(',') }
]
const portCols = [
  { title: 'PID', key: 'pid', minWidth: 60 }, { title: '进程', key: 'name', minWidth: 200 },
  { title: '端口', key: 'ports', render: (r) => (r.ports||[]).join(',') }
]
const userCols = [
  { title: '用户名', key: 'username' }, { title: 'UID', key: 'uid', minWidth: 60 },
  { title: 'Shell', key: 'shell' }, { title: 'root', key: 'is_root', render: (r) => r.is_root ? '✅' : '', minWidth: 50 },
  { title: 'sudo', key: 'has_sudo', render: (r) => r.has_sudo ? '✅' : '', minWidth: 50 }
]

onMounted(async () => {
  try {
    const d = await api.getAssetDetail(route.params.id)
    sys.value = (d.system || {}).system || d.system || {}
    const svcMap = {}
    const svcRaw = ((d.system || {}).services || [])
    svcRaw.forEach(s => { if (s.pid > 0) svcMap[s.pid] = s.name })
    svcItems.value = svcRaw.map(s => ({...s}))
    portItems.value = (d.processes || []).filter(p => (p.listening_ports||[]).length).map(p => {
      const svcName = svcMap[p.pid]
      return { ...p, ports: p.listening_ports, name: svcName || p.name }
    })
    userItems.value = d.users || []
  } catch(e) {}
})
</script>

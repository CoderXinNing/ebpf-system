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
        <n-data-table :columns="svcCols" :data="svcItems" size="small" :bordered="false" v-if="svcItems.length" />
            :pagination="pagination_svcItems"
            :row-key="(row) => svcItems === 'svcItems' ? row.name : svcItems === 'portItems' ? row.pid : row.username"
        <n-empty v-else description="无" />
      </n-tab-pane>
      <n-tab-pane name="port" tab="端口">
        <n-data-table :columns="portCols" :data="portItems" size="small" :bordered="false" v-if="portItems.length" />
            :pagination="pagination_portItems"
            :row-key="(row) => portItems === 'svcItems' ? row.name : portItems === 'portItems' ? row.pid : row.username"
        <n-empty v-else description="无" />
      </n-tab-pane>
      <n-tab-pane name="user" tab="用户">
        <n-data-table :columns="userCols" :data="userItems" size="small" :bordered="false" v-if="userItems.length" />
            :pagination="pagination_userItems"
            :row-key="(row) => userItems === 'svcItems' ? row.name : userItems === 'portItems' ? row.pid : row.username"
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

const disks = computed(() => {
  const d = sys.value?.disks || []
  return d.map(d => `${d.mount_point} ${d.total_mb}MB`).join(', ')
})

const pagination_svcItems = reactive({ page: 1, pageSize: 10, showSizePicker: true, pageSizes: [10, 20, 50] })
const pagination_portItems = reactive({ page: 1, pageSize: 10, showSizePicker: true, pageSizes: [10, 20, 50] })
const pagination_userItems = reactive({ page: 1, pageSize: 10, showSizePicker: true, pageSizes: [10, 20, 50] })

const svcCols = [
  { title: '名称', key: 'name', width: 130 }, { title: '类型', key: 'type', width: 80 },
  { title: '版本', key: 'version', width: 100 }, { title: 'PID', key: 'pid', width: 60 },
  { title: '端口', key: 'listen_port', render: (r) => (r.listen_port||[]).join(',') }
]
const portCols = [
  { title: 'PID', key: 'pid', width: 60 }, { title: '进程', key: 'name', width: 200 },
  { title: '端口', key: 'ports', render: (r) => (r.ports||[]).join(',') }
]
const userCols = [
  { title: '用户名', key: 'username' }, { title: 'UID', key: 'uid', width: 60 },
  { title: 'Shell', key: 'shell' }, { title: 'root', key: 'is_root', render: (r) => r.is_root ? '✅' : '', width: 50 },
  { title: 'sudo', key: 'has_sudo', render: (r) => r.has_sudo ? '✅' : '', width: 50 }
]

onMounted(async () => {
  try {
    const d = await api.getAssetDetail(route.params.id)
    sys.value = (d.system || {}).system || d.system || {}
    svcItems.value = ((d.system || {}).services || []).map(s => ({...s}))
    portItems.value = (d.processes || []).filter(p => (p.listening_ports||[]).length).map(p => ({...p, ports: p.listening_ports}))
    userItems.value = d.users || []
  } catch(e) {}
})
</script>

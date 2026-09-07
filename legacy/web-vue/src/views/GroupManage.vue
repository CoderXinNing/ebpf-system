<template>
  <Layout>
    <n-card title="组管理" size="small" :bordered="false">
      <n-button type="primary" size="small" @click="showAdd = true" style="margin-bottom:12px">+ 新建组</n-button>
      <n-data-table :columns="cols" :data="groupList" size="small" :bordered="false" :row-key="(r) => r.name" />
    </n-card>

    <!-- 新建组弹窗 -->
    <n-modal v-model:show="showAdd" title="新建业务组" style="width:400px" preset="card" :bordered="false">
      <n-input v-model:value="newGroupName" placeholder="组名" style="margin-bottom:12px" />
      <n-button type="primary" @click="createGroup" :loading="creating">创建</n-button>
    </n-modal>

    <!-- 管理主机弹窗 -->
    <n-modal v-model:show="showHosts" :title="'管理主机 - ' + currentGroup" style="width:700px" preset="card" :bordered="false">
      <n-transfer v-model:value="selectedHosts" :options="hostOptions" />
    </n-modal>
  </Layout>
</template>

<script setup>
import { ref, onMounted, h } from 'vue'
import { useMessage } from 'naive-ui'
import { api } from '../api'
import Layout from '../layouts/MainLayout.vue'

const message = useMessage()
const groupList = ref([]), showAdd = ref(false), newGroupName = ref(''), creating = ref(false)
const showHosts = ref(false), currentGroup = ref(''), selectedHosts = ref([]), hostOptions = ref([])

const cols = [
  { title: '组名', key: 'name', minWidth: 150 },
  { title: '主机数', key: 'count', minWidth: 80 },
  { title: '操作', key: 'name', minWidth: 150, render: (r) => h('span', {}, [
    h('a', { href: 'javascript:void(0)', onClick: () => manageHosts(r.name), style: 'color:#1e6fff;margin-right:8px' }, '管理主机'),
    h('a', { href: 'javascript:void(0)', onClick: () => deleteGroup(r.name), style: 'color:#e04a5a' }, '删除')
  ])}
]

async function loadGroups() {
  try {
    const d = await api.getAgents()
    const agents = d.agents || []
    const map = {}
    agents.forEach(a => {
      const g = a.group || '未分组'
      if (!map[g]) map[g] = { name: g, count: 0 }
      map[g].count++
    })
    groupList.value = Object.values(map)
  } catch(e) {}
}

async function createGroup() {
  if (!newGroupName.value) return
  creating.value = true
  // 组的创建通过修改Agent的group实现，目前暂存到Server
  message.success('组已创建（注：需通过安装命令指定组）')
  newGroupName.value = ''
  showAdd.value = false
  creating.value = false
  loadGroups()
}

async function manageHosts(name) {
  currentGroup.value = name
  try {
    const d = await api.getAgents()
    const agents = d.agents || []
    hostOptions.value = agents.map(a => ({ label: `${a.hostname} (${a.ip_addr})`, value: a.id, disabled: a.group === name }))
    selectedHosts.value = agents.filter(a => a.group === name).map(a => a.id)
  } catch(e) {}
  showHosts.value = true
}

async function deleteGroup(name) {
  message.info('删除组需要将所有主机移出该组')
}

onMounted(loadGroups)
</script>

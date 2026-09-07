<template>
  <Layout>
    <div class="host-manage">
      <!-- 左侧分组树 -->
      <div class="group-panel">
        <div class="panel-header">
          <span class="panel-title">分组</span>
          <n-button size="tiny" @click="showAddGroup = true">+</n-button>
        </div>
        <div class="group-list">
          <div
            v-for="g in groups"
            :key="g.name"
            class="group-item"
            :class="{ active: selectedGroup === g.name, 'can-delete': g.name !== '全部' && g.name !== '未分组' }"
            @click="selectedGroup = g.name"
          >
            <span class="group-name">{{ g.name }}</span>
            <div class="group-actions">
              <span class="group-count">{{ g.count }}</span>
              <span class="group-del" :class="{ 'can-delete': g.name !== '全部' && g.name !== '未分组' }" @click.stop="delGroup(g.name)">✕</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 右侧主机表 -->
      <div class="host-panel">
        <div class="panel-header">
          <span class="panel-title">主机列表</span>
          <div class="header-actions">
            <n-input
              v-model:value="searchText"
              placeholder="搜索主机名 / IP"
              size="small"
              clearable
              style="width: 15vw"
            />
            <span class="host-count">共 {{ filteredAgents.length }} 台</span>
            <n-button
              v-if="selectedAgents.length > 0"
              size="small"
              type="primary"
              @click="showMove = true"
            >
              移动 ({{ selectedAgents.length }})
            </n-button>
          </div>
        </div>
        <n-data-table
          :columns="cols"
          :data="filteredAgents"
          :bordered="false"
          size="small"
          :pagination="pagination"
          :row-key="(r) => r.id"
          @update:checked-row-keys="onCheck"
        />
      </div>
    </div>

    <!-- 添加组弹窗 -->
    <n-modal v-model:show="showAddGroup" preset="dialog" title="添加分组">
      <n-input v-model:value="newGroupName" placeholder="组名" />
      <template #action>
        <n-button @click="showAddGroup = false">取消</n-button>
        <n-button type="primary" @click="addGroup">确定</n-button>
      </template>
    </n-modal>

    <!-- 移动弹窗 -->
    <n-modal v-model:show="showMove" preset="dialog" title="移动到分组">
      <n-select v-model:value="moveTarget" :options="groupOptions" />
      <template #action>
        <n-button @click="showMove = false">取消</n-button>
        <n-button type="primary" @click="moveHosts">确定</n-button>
      </template>
    </n-modal>
  </Layout>
</template>

<script setup>
import { ref, computed, h } from 'vue'
import { api } from '../api'
import Layout from '../layouts/MainLayout.vue'

const agents = ref([])
const serverGroups = ref([])
const selectedGroup = ref('全部')
const selectedAgents = ref([])
const searchText = ref('')
const showAddGroup = ref(false)
const showMove = ref(false)
const newGroupName = ref('')
const moveTarget = ref('')
const pagination = ref({ pageSize: 15 })

const groups = computed(() => {
  const map = new Map()
  map.set('全部', { name: '全部', count: agents.value.length })
  agents.value.forEach(a => {
    const g = a.group || '未分组'
    if (!map.has(g)) map.set(g, { name: g, count: 0 })
    map.get(g).count++
  })
  // 合并 Server 上创建的空组
  serverGroups.value.forEach(name => {
    if (!map.has(name)) map.set(name, { name, count: 0 })
  })
  return Array.from(map.values())
})

const groupOptions = computed(() =>
  groups.value.filter(g => g.name !== '全部').map(g => ({ label: g.name, value: g.name }))
)

const filteredAgents = computed(() => {
  let list = agents.value
  if (selectedGroup.value !== '全部') {
    list = list.filter(a => (a.group || '未分组') === selectedGroup.value)
  }
  const kw = searchText.value.trim().toLowerCase()
  if (kw) {
    list = list.filter(a => {
      const hostname = (a.hostname || '').toLowerCase()
      const ip = (a.ip_addr || '').toLowerCase()
      return hostname.includes(kw) || ip.includes(kw)
    })
  }
  return list
})

const cols = [
  { type: 'selection' },
  { title: '主机名', key: 'hostname', minWidth: 130 },
  { title: 'IP', key: 'ip_addr', minWidth: 120 },
  { title: '分组', key: 'group', minWidth: 90, render: (r) => r.group || '未分组' },
  { title: '探针', key: 'active_probes', minWidth: 70 },
  { title: '状态', key: 'last_seen', minWidth: 90, render: (r) => {
    const online = Date.now() / 1000 - r.last_seen < 60
    return h('span', { style: { color: online ? '#18A058' : '#D03050' } }, online ? '在线' : '离线')
  }},
  { title: '操作', key: 'id', width: 110, render: (r) => h('div', { style: 'display: flex; gap: 8px' }, [
    h('a', { href: '#/host/' + r.id }, '详情'),
    h('a', { style: 'color: #D03050; cursor: pointer', onClick: () => delHost(r.id) }, '删除'),
  ]) },
]

function onCheck(keys) {
  selectedAgents.value = keys
}

async function addGroup() {
  if (!newGroupName.value) return
  const token = localStorage.getItem('token')
  await fetch('/api/groups', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
    body: JSON.stringify({ name: newGroupName.value })
  })
  newGroupName.value = ''
  showAddGroup.value = false
  load()
}

async function delGroup(name) {
  const token = localStorage.getItem('token')
  await fetch('/api/groups/' + name, {
    method: 'DELETE',
    headers: { 'Authorization': 'Bearer ' + token }
  })
  if (selectedGroup.value === name) selectedGroup.value = '全部'
  load()
}

async function moveHosts() {
  if (!moveTarget.value || selectedAgents.value.length === 0) return
  const token = localStorage.getItem('token')
  await fetch('/api/move', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
    body: JSON.stringify({ agent_ids: selectedAgents.value, group: moveTarget.value })
  })
  showMove.value = false
  selectedAgents.value = []
  load()
}

async function delHost(id) {
  if (!confirm('确认删除该主机？将清除其所有数据')) return
  const token = localStorage.getItem('token')
  await fetch('/api/agents/' + id, {
    method: 'DELETE',
    headers: { 'Authorization': 'Bearer ' + token }
  })
  load()
}

let ws

function connectWS() {
  const token = localStorage.getItem('token')
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  ws = new WebSocket(`${proto}://${location.host}/ws?token=${token}`)
  ws.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data)
      if (msg.type === 'agent_offline') {
        load()
      }
    } catch (err) {}
  }
  ws.onclose = () => setTimeout(connectWS, 3000)
}

async function load() {
  const token = localStorage.getItem('token')
  const [data, groupResp] = await Promise.all([
    api.getAgents(),
    fetch('/api/groups', { headers: { 'Authorization': 'Bearer ' + token } }).then(r => r.json()),
  ])
  agents.value = data.agents || []
  serverGroups.value = groupResp.groups || []
}

load()
connectWS()
setInterval(load, 15000)
</script>

<style scoped>
.host-manage {
  display: flex;
  gap: 1vw;
  height: 100%;
}

.group-panel {
  width: 15vw;
  min-width: 140px;
  background: #FFFFFF;
  border-radius: 0.8vw;
  padding: 1.5vh 0.8vw;
  box-shadow: 0 0.3vh 1.5vh rgba(0,0,0,0.04);
  display: flex;
  flex-direction: column;
}

.host-panel {
  flex: 1;
  background: #FFFFFF;
  border-radius: 0.8vw;
  padding: 1.5vh 1.2vw;
  box-shadow: 0 0.3vh 1.5vh rgba(0,0,0,0.04);
}

.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1vh;
}

.panel-title {
  font-size: 1vw;
  font-weight: 600;
  color: #202124;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 1vw;
}

.host-count {
  font-size: 0.85vw;
  color: #5F6368;
}

.group-list {
  flex: 1;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 0.3vh;
}

.group-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 1vh 0.8vw;
  border-radius: 0.5vw;
  cursor: pointer;
  transition: background 0.2s;
  font-size: 0.9vw;
}

.group-item:hover {
  background: #F1F3F4;
}

.group-item.active {
  background: rgba(26, 115, 232, 0.1);
  color: #1A73E8;
  font-weight: 500;
}

.group-actions {
  display: flex;
  align-items: center;
  gap: 0.4vw;
  min-width: 2.5vw;
  justify-content: flex-end;
  flex-shrink: 0;
}

.group-count {
  background: #F1F3F4;
  border-radius: 1vw;
  padding: 0.2vh 0.5vw;
  font-size: 0.75vw;
  color: #5F6368;
  min-width: 1.5vw;
  text-align: center;
}

.group-del {
  font-size: 0.7vw;
  color: #D03050;
  opacity: 0;
  transition: opacity 0.2s;
  width: 1vw;
  text-align: center;
  flex-shrink: 0;
  visibility: hidden;
}

.group-item.can-delete .group-del {
  visibility: visible;
}

.group-item.can-delete:hover .group-del {
  opacity: 1;
}

.group-item:hover .group-del {
  opacity: 1;
}
</style>

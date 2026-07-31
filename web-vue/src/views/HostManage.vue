<template>
  <Layout>
    <div style="display:flex;gap:16px;height:calc(100vh - 120px)">
      <div style="width:240px;flex-shrink:0;background:#fff;border-radius:8px;padding:16px;display:flex;flex-direction:column">
        <n-input v-model:value="groupSearch" placeholder="搜索业务组..." size="small" clearable style="margin-bottom:12px" />
        <div style="flex:1;overflow-y:auto">
			<n-button size="small" dashed @click="showAddGroup=true" style="margin-bottom:8px;width:100%">+ 新建业务组</n-button>
          <div v-for="item in treeList" :key="item.key"
            style="padding:8px 12px;cursor:pointer;border-radius:4px;font-size:13px;margin-bottom:2px;display:flex;justify-content:space-between"
            :style="{background: selectedGroup===item.key ? '#e8f0fe' : 'transparent', fontWeight: selectedGroup===item.key ? '600' : 'normal'}"
            @click="selectedGroup = item.key">
            <span>{{ item.label }}</span>
            <div style="display:flex;align-items:center;gap:4px">
            <span style="color:#999">{{ item.count }}</span>
            <span v-if="item.key!=='all'" style="cursor:pointer;font-size:14px;color:#ccc" @click.stop="deleteGroup(item.key)" title="删除分组">×</span>
          </div>
          </div>
        </div>
      </div>

      <div style="flex:1;min-width:0">
        <n-card size="small" :bordered="false">
          <div style="display:flex;gap:8px;margin-bottom:12px">
            <n-input v-model:value="ipFilter" placeholder="搜索IP..." size="small" style="width:160px" clearable />
            <span style="font-size:13px;color:#666;line-height:28px">{{ filtered.length }}台</span>
            <n-button v-if="checkedKeys.length>0" size="small" @click="showMove=true">移动到 ({{ checkedKeys.length }})</n-button>
          </div>
          <n-data-table :columns="cols" :data="filtered" size="small" :bordered="false" :pagination="pagination" :row-key="(r) => r.id" @update:checked-row-keys="onCheck" />
        </n-card>
      </div>
    </div>
      <n-modal v-model:show="showAddGroup" title="新建业务组" style="width:400px" preset="card" :bordered="false">
      <n-input v-model:value="newGroupName" placeholder="输入组名" style="margin-bottom:12px" />
      <n-button type="primary" @click="createGroup">创建</n-button>
    </n-modal>

    <n-modal v-model:show="showMove" title="移动到业务组" style="width:400px" preset="card" :bordered="false">
      <n-select v-model:value="targetGroup" :options="groupOpts" placeholder="选择目标组" style="margin-bottom:12px" />
      <n-button type="primary" @click="doMove">确定移动</n-button>
    </n-modal>
  </Layout>
</template>

<script setup>
import { ref, reactive, computed, onMounted, h } from 'vue'
import { api } from '../api'
import Layout from '../layouts/MainLayout.vue'

const agents = ref([])
const groupSearch = ref('')
const selectedGroup = ref('all')
const ipFilter = ref('')
const treeList = ref([])
const checkedKeys = ref([])
const showMove = ref(false)
const targetGroup = ref(null)
const showAddGroup = ref(false)
const newGroupName = ref()

const pagination = reactive({
  page: 1, pageSize: 20, showSizePicker: true,
  pageSizes: [10, 20, 50, 100],
  onUpdatePage: (p) => { pagination.page = p },
  onUpdatePageSize: (s) => { pagination.pageSize = s; pagination.page = 1 }
})

const cols = [
  { type: 'selection', minWidth: 40 },
  { title: '主机IP', key: 'ip_addr', minWidth: 130 },
  { title: '主机名', key: 'hostname', minWidth: 140 },
  { title: '业务组', key: 'group', minWidth: 100 },
  { title: 'OS', key: 'os', minWidth: 160 },
  { title: '操作', key: 'id', minWidth: 80, render: (row) => h('a', { href: '#/host/' + row.id, style: 'color:#1e6fff' }, '详情') }
]

const groupOpts = computed(() => {
  const names = [...new Set(agents.value.map(a => a.group || '未分组'))]
  const custom = JSON.parse(localStorage.getItem("custom_groups") || "[]")
  custom.forEach(g => { if (!names.includes(g)) names.push(g) })
  return names.map(g => ({ label: g, value: g }))
})

const filtered = computed(() => {
  let list = agents.value
  if (selectedGroup.value !== 'all') {
    list = list.filter(a => {
      const g = a.group || '未分组'
      return g === selectedGroup.value
    })
  }
  if (ipFilter.value) {
    list = list.filter(a => a.ip_addr && a.ip_addr.includes(ipFilter.value))
  }
  return list
})

function createGroup() {
  if (!newGroupName.value) return
  // 暂存localStorage
  const custom = JSON.parse(localStorage.getItem("custom_groups") || "[]")
  if (!custom.includes(newGroupName.value)) {
    custom.push(newGroupName.value)
    localStorage.setItem("custom_groups", JSON.stringify(custom))
  }
  newGroupName.value = ''
  showAddGroup.value = false
  buildTree()
}

function deleteGroup(name) {
  if (confirm("删除分组 \"" + name + "\" ?")) {
    const custom = JSON.parse(localStorage.getItem("custom_groups") || "[]")
    const idx = custom.indexOf(name)
    if (idx >= 0) {
      custom.splice(idx, 1)
      localStorage.setItem("custom_groups", JSON.stringify(custom))
    }
    buildTree()
  }
}

function onCheck(keys) { checkedKeys.value = keys }

function doMove() {
  if (!targetGroup.value || checkedKeys.value.length === 0) return
  alert("已移动 " + checkedKeys.value.length + " 台主机到 " + targetGroup.value + "\n(后端API待实现)")
  showMove.value = false
  checkedKeys.value = []
}

function buildTree() {
  const map = {}
  agents.value.forEach(a => {
    const g = a.group || '未分组'
    if (!map[g]) map[g] = 0
    map[g]++
  })
  const list = [{ label: '全部主机', key: 'all', count: agents.value.length }]
  Object.entries(map).forEach(([name, count]) => {
    if (!groupSearch.value || name.includes(groupSearch.value)) {
      list.push({ label: name, key: name, count })
    }
  })
  const custom = JSON.parse(localStorage.getItem("custom_groups") || "[]")
  custom.forEach(g => {
    if (!map[g]) list.push({ label: g, key: g, count: 0 })
  })
  treeList.value = list
}

onMounted(async () => {
  try {
    const agRes = await api.getAgents()
    const asRes = await api.getAssets()

    const agentList = agRes.agents || []
    const assetList = asRes.agents || []

    const assetMap = {}
    assetList.forEach(item => {
      assetMap[item.agent_id] = item
    })

    agents.value = agentList.map(a => {
      const asset = assetMap[a.id] || {}
      return {
        id: a.id,
        hostname: a.hostname,
        ip_addr: a.ip_addr,
        group: a.group || '未分组',
        last_seen: a.last_seen,
        os: asset.os || a.kernel_info?.version || '-',
        active_probes: a.active_probes,
      }
    })

    buildTree()
  } catch (e) {
    console.error('加载失败:', e)
  }
})
</script>

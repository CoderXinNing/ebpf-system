<template>
  <Layout>
    <div class="users-container">
      <div class="table-card">
        <div class="card-header">
          <span class="card-title">用户管理</span>
          <n-button size="small" type="primary" @click="showAdd = true">添加用户</n-button>
        </div>
        <n-data-table
          :columns="cols"
          :data="users"
          :bordered="false"
          size="small"
          :row-key="(r) => r.id"
        />
      </div>
    </div>

    <!-- 添加用户弹窗 -->
    <n-modal v-model:show="showAdd" preset="dialog" title="添加用户">
      <div style="display: flex; flex-direction: column; gap: 1vh;">
        <n-input v-model:value="newUser.username" placeholder="用户名" />
        <n-input v-model:value="newUser.password" type="password" placeholder="密码" />
        <n-select
          v-model:value="newUser.role"
          :options="roleOptions"
          placeholder="角色"
        />
      </div>
      <template #action>
        <n-button @click="showAdd = false">取消</n-button>
        <n-button type="primary" @click="addUser">确定</n-button>
      </template>
    </n-modal>
  </Layout>
</template>

<script setup>
import { ref, h, onMounted } from 'vue'
import Layout from '../layouts/MainLayout.vue'
import { NTag } from 'naive-ui'

const users = ref([])
const showAdd = ref(false)
const newUser = ref({ username: '', password: '', role: 'viewer' })

const roleOptions = [
  { label: '管理员', value: 'admin' },
  { label: '操作员', value: 'operator' },
  { label: '查看者', value: 'viewer' },
]

const roleMap = {
  admin: { label: '管理员', type: 'error' },
  operator: { label: '操作员', type: 'warning' },
  viewer: { label: '查看者', type: 'info' },
}

const cols = [
  { title: 'ID', key: 'id', width: 60 },
  { title: '用户名', key: 'username', minWidth: 120 },
  { title: '角色', key: 'role', minWidth: 90, render: (r) => {
    const role = roleMap[r.role] || { label: r.role, type: 'default' }
    return h(NTag, { type: role.type, size: 'small', bordered: false }, { default: () => role.label })
  }},
]

async function load() {
  const token = localStorage.getItem('token')
  const resp = await fetch('/api/users', { headers: { 'Authorization': 'Bearer ' + token } })
  const data = await resp.json()
  users.value = data.users || []
}

async function addUser() {
  if (!newUser.value.username || !newUser.value.password) return
  const token = localStorage.getItem('token')
  await fetch('/api/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
    body: JSON.stringify(newUser.value)
  })
  showAdd.value = false
  newUser.value = { username: '', password: '', role: 'viewer' }
  load()
}

onMounted(load)
</script>

<style scoped>
.users-container {
  display: flex;
  flex-direction: column;
  gap: 1vh;
}

.table-card {
  background: #FFFFFF;
  border-radius: 0.8vw;
  padding: 1.5vh 1.2vw;
  box-shadow: 0 0.3vh 1.5vh rgba(0,0,0,0.04);
}

.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1vh;
}

.card-title {
  font-size: 1vw;
  font-weight: 600;
  color: #202124;
}
</style>

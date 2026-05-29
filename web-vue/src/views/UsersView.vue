<template>
  <n-card title="用户管理">
    <n-data-table :columns="columns" :data="users" :bordered="false" />
  </n-card>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { api } from '../utils/api'

const users = ref([])
const columns = [
  { title: 'ID', key: 'id', width: 60 },
  { title: '用户名', key: 'username' },
  { title: '角色', key: 'role' },
]

onMounted(async () => {
  try { const d = await api.getUsers(); users.value = d.users || [] } catch(e) {}
})
</script>

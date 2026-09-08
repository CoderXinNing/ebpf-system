<template>
  <div class="whitelist-container">
    <n-card title="白名单管理" bordered hoverable>
      <n-space vertical :size="16">
        <n-input-group>
          <n-input v-model:value="newProcess" placeholder="输入进程名，如 nc、curl" @keyup.enter="handleAdd" />
          <n-button type="primary" @click="handleAdd">添加</n-button>
        </n-input-group>

        <n-data-table
          :columns="columns"
          :data="whitelistData"
          :loading="loading"
          :bordered="false"
        />
      </n-space>
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, h } from 'vue'
import { NButton, NCard, NSpace, NInput, NInputGroup, NDataTable } from 'naive-ui'
import { getWhitelist, addWhitelist, removeWhitelist } from '../api/whitelist'

const whitelist = ref<string[]>([])
const newProcess = ref('')
const loading = ref(false)

const columns = [
  { title: '进程名', key: 'name' },
  {
    title: '操作',
    key: 'actions',
    render(row: any) {
      return h(
        NButton,
        {
          size: 'small',
          type: 'error',
          onClick: () => handleRemove(row.name),
        },
        { default: () => '移除' }
      )
    },
  },
]

const whitelistData = ref<{ name: string }[]>([])

onMounted(async () => {
  await loadWhitelist()
})

async function loadWhitelist() {
  loading.value = true
  try {
    whitelist.value = await getWhitelist()
    whitelistData.value = whitelist.value.map(name => ({ name }))
  } catch (err: any) {
    console.error('加载白名单失败:', err)
  } finally {
    loading.value = false
  }
}

async function handleAdd() {
  if (!newProcess.value.trim()) return
  await addWhitelist(newProcess.value.trim())
  newProcess.value = ''
  await loadWhitelist()
}

async function handleRemove(name: string) {
  // 确认弹窗
  if (confirm(`确认移除白名单: ${name}?`)) {
    await removeWhitelist(name)
    await loadWhitelist()
  }
}
</script>

<style scoped>
.whitelist-container {
  padding: 24px;
  max-width: 800px;
  margin: 0 auto;
}
</style>

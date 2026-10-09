<template>
  <div class="probe-exclude-comms-container">
    <n-card title="探针排除名单" bordered hoverable>
      <n-space vertical :size="16">
        <n-input-group>
          <n-input v-model:value="newComm" placeholder="输入进程 comm，如 nc、curl" @keyup.enter="handleAdd" />
          <n-button type="primary" @click="handleAdd">添加</n-button>
        </n-input-group>

        <n-data-table
          :columns="columns"
          :data="commsData"
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
import { getProbeExcludeComms, addProbeExcludeComms, removeProbeExcludeComms } from '../api/probeExcludeComms'

const comms = ref<string[]>([])
const newComm = ref('')
const loading = ref(false)

const columns = [
  { title: '进程 comm', key: 'name' },
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

const commsData = ref<{ name: string }[]>([])

onMounted(async () => {
  await loadProbeExcludeComms()
})

async function loadProbeExcludeComms() {
  loading.value = true
  try {
    comms.value = await getProbeExcludeComms()
    commsData.value = comms.value.map(name => ({ name }))
  } catch (err: any) {
    console.error('加载探针排除名单失败:', err)
  } finally {
    loading.value = false
  }
}

async function handleAdd() {
  if (!newComm.value.trim()) return
  await addProbeExcludeComms(newComm.value.trim())
  newComm.value = ''
  await loadProbeExcludeComms()
}

async function handleRemove(name: string) {
  if (confirm(`确认移除探针排除名单: ${name}?`)) {
    await removeProbeExcludeComms(name)
    await loadProbeExcludeComms()
  }
}
</script>

<style scoped>
.probe-exclude-comms-container {
  padding: 24px;
  max-width: 800px;
  margin: 0 auto;
}
</style>

<template>
  <Layout>
    <n-card title="探针管理">
      <n-button @click="collect" type="primary" style="margin-bottom:12px">立即采集所有资产</n-button>
    </n-card>
  </Layout>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useMessage } from 'naive-ui'
import { api } from '../api'
import Layout from '../layouts/MainLayout.vue'

const message = useMessage()
const agents = ref([])

onMounted(async () => {
  try { const d = await api.getAgents(); agents.value = d.agents || [] } catch(e) {}
})

async function collect() {
  for (const a of agents.value) {
    try {
      await api.sendCommand({ agent_id: a.id, probe_name: '', action: 'collect' })
      message.success(`已触发 ${a.hostname} 采集`)
    } catch(e) {}
  }
}
</script>

<template>
  <div class="host-detail-container">
    <n-card :title="`主机详情: ${hostname}`" bordered hoverable>
      <n-tabs type="line" animated>
        <n-tab-pane name="overview" tab="概览">
          <n-descriptions :column="2" bordered>
            <n-descriptions-item label="Agent ID">{{ agentId }}</n-descriptions-item>
            <n-descriptions-item label="主机名">{{ hostname }}</n-descriptions-item>
            <n-descriptions-item label="IP 地址">{{ ipAddr }}</n-descriptions-item>
            <n-descriptions-item label="版本">{{ version }}</n-descriptions-item>
            <n-descriptions-item label="能力层级">{{ capabilityLevel }}</n-descriptions-item>
            <n-descriptions-item label="探针数">{{ activeProbes }}</n-descriptions-item>
            <n-descriptions-item label="最后心跳">{{ lastSeen }}</n-descriptions-item>
          </n-descriptions>
        </n-tab-pane>

        <n-tab-pane name="probes" tab="探针状态">
          <n-space vertical :size="8">
            <div v-for="probe in probes" :key="probe.name" class="probe-row">
              <n-space justify="space-between" align="center">
                <n-text>{{ probe.name }}</n-text>
                <n-tag :type="probe.loaded ? 'success' : 'error'" round size="small">
                  {{ probe.loaded ? '运行中' : '未加载' }}
                </n-tag>
              </n-space>
            </div>
          </n-space>
        </n-tab-pane>

        <n-tab-pane name="alerts" tab="最近告警">
          <n-data-table
            :columns="alertColumns"
            :data="recentAlerts"
            :loading="loading"
            :pagination="{ pageSize: 10 }"
            :bordered="false"
          />
        </n-tab-pane>

        <n-tab-pane name="assets" tab="资产">
          <n-empty description="资产数据采集中，即将上线" />
        </n-tab-pane>

        <n-tab-pane name="chains" tab="攻击链">
          <n-empty v-if="starChains.length === 0" description="暂无攻击链" />
          <n-list v-else>
            <n-list-item v-for="corrId in starChains" :key="corrId">
              <n-space justify="space-between" align="center">
                <n-text code style="font-size: 12px">{{ corrId }}</n-text>
                <n-button size="small" type="primary" @click="goToStarChain(corrId)">查看</n-button>
              </n-space>
            </n-list-item>
          </n-list>
        </n-tab-pane>
      </n-tabs>

    </n-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { NCard, NSpace, NDescriptions, NDescriptionsItem, NDataTable, NButton, NEmpty, NList, NListItem, NText, NTag, NTabs, NTabPane } from 'naive-ui'
import { getAgents, type AgentInfo } from '../api/agent'
import { getAlerts, type AlertItem } from '../api/alert'

const route = useRoute()
const router = useRouter()

const agentId = ref(route.params.id as string)
const hostname = ref('')
const ipAddr = ref('')
const version = ref('')
const capabilityLevel = ref('')
const activeProbes = ref(0)
const lastSeen = ref('')
const recentAlerts = ref<AlertItem[]>([])
const starChains = ref<string[]>([])
const loading = ref(false)
const probes = ref([
  { name: 'exec_monitor', loaded: true },
  { name: 'bash_monitor', loaded: true },
  { name: 'tcp_monitor', loaded: true },
  { name: 'file_access', loaded: true },
  { name: 'xdp_reporter', loaded: true },
])

const alertColumns = [
  { title: '规则', key: 'rule_name' },
  { title: '严重度', key: 'severity' },
  { title: '时间', key: 'detected_at', render(row: AlertItem) { return new Date(row.detected_at).toLocaleString('zh-CN') } },
]

onMounted(async () => {
  loading.value = true
  try {
    const agents = await getAgents()
    const agent = agents.find(a => a.id === agentId.value)
    if (agent) {
      hostname.value = agent.hostname
      ipAddr.value = agent.ip_addr
      version.value = agent.version
      capabilityLevel.value = agent.capability_level
      activeProbes.value = agent.active_probes
      lastSeen.value = new Date(agent.last_seen * 1000).toLocaleString('zh-CN')
    }

    const alerts = await getAlerts()
    recentAlerts.value = alerts.filter(a => a.agent_id === agentId.value).slice(0, 10)
    starChains.value = [...new Set(recentAlerts.value.filter(a => a.correlation_id).map(a => a.correlation_id))]
  } catch (err: any) {
    console.error('加载主机详情失败:', err)
  } finally {
    loading.value = false
  }
})

function goToStarChain(corrId: string) {
  router.push(`/star?corr_id=${corrId}`)
}
</script>

<style scoped>
.probe-row {
  padding: 8px 0;
  border-bottom: 1px solid #f0f0f0;
}

.probe-row:last-child {
  border-bottom: none;
}

.host-detail-container {
  padding: 24px;
  max-width: 1000px;
  margin: 0 auto;
}
</style>

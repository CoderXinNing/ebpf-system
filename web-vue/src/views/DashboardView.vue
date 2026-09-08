<template>
  <div class="dashboard-container">
    <n-space vertical :size="20">
      <!-- 统计卡片 -->
      <n-grid :cols="3" :x-gap="16">
        <n-grid-item>
          <n-card class="stat-card" hoverable>
            <div class="stat-content">
              <div class="stat-icon" style="background: #e8f5e9">
                <n-icon :size="28" color="#2e7d32">
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path fill="currentColor" d="M4 6h16v12H4z"/></svg>
                </n-icon>
              </div>
              <div>
                <div class="stat-value">{{ agents.length }}</div>
                <div class="stat-label">在线主机</div>
              </div>
            </div>
          </n-card>
        </n-grid-item>
        <n-grid-item>
          <n-card class="stat-card" hoverable>
            <div class="stat-content">
              <div class="stat-icon" style="background: #fff3e0">
                <n-icon :size="28" color="#e65100">
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path fill="currentColor" d="M12 2l8 16H4z"/></svg>
                </n-icon>
              </div>
              <div>
                <div class="stat-value">{{ alertCount }}</div>
                <div class="stat-label">告警总数</div>
              </div>
            </div>
          </n-card>
        </n-grid-item>
        <n-grid-item>
          <n-card class="stat-card" hoverable>
            <div class="stat-content">
              <div class="stat-icon" style="background: #e3f2fd">
                <n-icon :size="28" color="#1565c0">
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path fill="currentColor" d="M12 2c4 4 6 7 6 11a6 6 0 11-12 0c0-4 2-7 6-11z"/></svg>
                </n-icon>
              </div>
              <div>
                <div class="stat-value">{{ starCount }}</div>
                <div class="stat-label">攻击链</div>
              </div>
            </div>
          </n-card>
        </n-grid-item>
      </n-grid>

      <!-- 主机列表 -->
      <n-card title="主机列表" bordered hoverable>
        <n-data-table :columns="columns" :data="agents" :loading="loading" :bordered="false" />
      </n-card>
    </n-space>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { NGrid, NGridItem, NDataTable, NCard, NSpace, NIcon } from 'naive-ui'
import { getAgents, type AgentInfo } from '../api/agent'
import { getAlerts } from '../api/alert'
import { onWSMessage } from '../api/ws'

const agents = ref<AgentInfo[]>([])
const alertCount = ref(0)
const starCount = ref(0)
const loading = ref(false)

const columns = [
  { title: '主机名', key: 'hostname' },
  { title: 'IP', key: 'ip_addr' },
  { title: '探针数', key: 'active_probes' },
  { title: '能力', key: 'capability_level' },
  {
    title: '最后心跳',
    key: 'last_seen',
    render(row: AgentInfo) {
      return new Date(row.last_seen * 1000).toLocaleString('zh-CN')
    },
  },
]

onMounted(async () => {
  await loadDashboard()
  onWSMessage('new_alert', async () => {
    await loadDashboard()
  })
})

async function loadDashboard() {
  loading.value = true
  try {
    const [agentList, alertList] = await Promise.all([getAgents(), getAlerts()])
    agents.value = agentList
    alertCount.value = alertList.length
    starCount.value = new Set(alertList.filter(a => a.correlation_id).map(a => a.correlation_id)).size
  } catch (err: any) {
    console.error('加载仪表盘失败:', err)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.dashboard-container {
  padding: 24px;
  max-width: 1200px;
  margin: 0 auto;
}

.stat-card {
  border-radius: 12px;
  transition: all 0.3s ease;
}

.stat-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.08);
}

.stat-content {
  display: flex;
  align-items: center;
  gap: 16px;
}

.stat-icon {
  width: 52px;
  height: 52px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.stat-value {
  font-size: 32px;
  font-weight: 700;
  line-height: 1;
}

.stat-label {
  font-size: 14px;
  color: #666;
  margin-top: 4px;
}
</style>

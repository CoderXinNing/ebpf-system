<template>
  <div class="dashboard-container">
    <n-space vertical :size="20">
      <!-- 第一行：3 个统计卡片 -->
      <n-grid :cols="3" :x-gap="16">
        <n-grid-item>
          <n-card class="stat-card" hoverable>
            <div class="stat-content">
              <div class="stat-icon" style="background: #e8f5e9">
                <span style="font-size: 28px">🖥️</span>
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
                <span style="font-size: 28px">🚨</span>
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
                <span style="font-size: 28px">⭐</span>
              </div>
              <div>
                <div class="stat-value">{{ starCount }}</div>
                <div class="stat-label">攻击链</div>
              </div>
            </div>
          </n-card>
        </n-grid-item>
      </n-grid>

      <!-- 第二行：2 个统计卡片 -->
      <n-grid :cols="2" :x-gap="16">
        <n-grid-item>
          <n-card class="stat-card" hoverable>
            <div class="stat-content">
              <div class="stat-icon" style="background: #fce4ec">
                <span style="font-size: 28px">🔴</span>
              </div>
              <div>
                <div class="stat-value">{{ hardRuleCount }}</div>
                <div class="stat-label">硬规则告警</div>
              </div>
            </div>
          </n-card>
        </n-grid-item>
        <n-grid-item>
          <n-card class="stat-card" hoverable>
            <div class="stat-content">
              <div class="stat-icon" style="background: #e8eaf6">
                <span style="font-size: 28px">🔵</span>
              </div>
              <div>
                <div class="stat-value">{{ baselineCount }}</div>
                <div class="stat-label">软基线参考</div>
              </div>
            </div>
          </n-card>
        </n-grid-item>
      </n-grid>

      <!-- 告警趋势 -->
      <n-card title="最近告警趋势" bordered hoverable>
        <div ref="trendContainer" style="width: 100%; height: 300px"></div>
      </n-card>

      <!-- 主机列表 -->
      <n-card title="主机列表" bordered hoverable>
        <n-data-table :columns="columns" :data="agents" :loading="loading" :bordered="false" />
      </n-card>
    </n-space>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, h } from 'vue'
import { useRouter } from 'vue-router'
import { NGrid, NGridItem, NDataTable, NCard, NSpace, NButton } from 'naive-ui'
import * as echarts from 'echarts'
import { getAgents, type AgentInfo } from '../api/agent'
import { getAlerts, type AlertItem } from '../api/alert'
import { onWSMessage } from '../api/ws'

const router = useRouter()
const agents = ref<AgentInfo[]>([])
const alertCount = ref(0)
const starCount = ref(0)
const hardRuleCount = ref(0)
const baselineCount = ref(0)
const loading = ref(false)
const trendContainer = ref<HTMLElement | null>(null)

const columns = [
  {
    title: '主机名',
    key: 'hostname',
    render(row: AgentInfo) {
      return h(NButton, { text: true, type: 'primary', onClick: () => router.push(`/host/${row.id}`) }, { default: () => row.hostname })
    },
  },
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
    hardRuleCount.value = alertList.filter(a => !a.details?.includes('[参考]')).length
    baselineCount.value = alertList.filter(a => a.details?.includes('[参考]')).length
    initTrendChart(alertList)
  } catch (err: any) {
    console.error('加载仪表盘失败:', err)
  } finally {
    loading.value = false
  }
}

function initTrendChart(alerts: AlertItem[]) {
  if (!trendContainer.value) return

  const hourMap = new Map<string, number>()
  alerts.forEach(a => {
    const hour = new Date(a.detected_at).toISOString().slice(0, 13)
    hourMap.set(hour, (hourMap.get(hour) || 0) + 1)
  })

  const hours = [...hourMap.keys()].sort()
  const counts = hours.map(h => hourMap.get(h)!)

  const chart = echarts.init(trendContainer.value)
  chart.setOption({
    tooltip: { trigger: 'axis' },
    xAxis: { type: 'category', data: hours, axisLabel: { rotate: 45 } },
    yAxis: { type: 'value', minInterval: 1 },
    series: [{
      type: 'line',
      smooth: true,
      data: counts,
      areaStyle: { opacity: 0.3 },
      itemStyle: { color: '#e53e3e' },
    }],
  })

  window.addEventListener('resize', () => chart.resize())
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

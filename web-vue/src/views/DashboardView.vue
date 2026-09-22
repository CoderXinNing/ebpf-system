<template>
  <div class="dashboard">
    <!-- 筛选栏 -->
    <div class="filter-bar">
      <n-select v-model:value="filterSeverity" :options="severityOptions" placeholder="严重度" clearable size="small" style="width: 120px" />
      <n-select v-model:value="filterSource" :options="sourceOptions" placeholder="来源" clearable size="small" style="width: 120px" />
      <n-select v-model:value="filterDays" :options="daysOptions" size="small" style="width: 120px" />
      <n-button size="small" @click="loadDashboard">刷新</n-button>
    </div>

    <!-- 统计卡片 6 个 -->
    <div class="stat-grid">
      <div class="stat-card stat-critical">
        <div class="stat-value">{{ stats.critical }}</div>
        <div class="stat-label">严重告警</div>
      </div>
      <div class="stat-card stat-high">
        <div class="stat-value">{{ stats.high }}</div>
        <div class="stat-label">高危告警</div>
      </div>
      <div class="stat-card stat-medium">
        <div class="stat-value">{{ stats.medium }}</div>
        <div class="stat-label">中危告警</div>
      </div>
      <div class="stat-card stat-low">
        <div class="stat-value">{{ stats.low }}</div>
        <div class="stat-label">低危告警</div>
      </div>
      <div class="stat-card stat-pending">
        <div class="stat-value">{{ stats.open }}</div>
        <div class="stat-label">待处理</div>
      </div>
      <div class="stat-card stat-resolved">
        <div class="stat-value">{{ stats.resolved }}</div>
        <div class="stat-label">已解决</div>
      </div>
    </div>

    <!-- 两张图 -->
    <div class="chart-row">
      <div class="chart-card">
        <div class="chart-title">最近 7 天告警趋势</div>
        <div ref="trendContainer" style="width: 100%; height: 240px"></div>
      </div>
      <div class="chart-card">
        <div class="chart-title">告警来源分布</div>
        <div ref="sourceContainer" style="width: 100%; height: 240px"></div>
      </div>
    </div>

    <!-- 最近告警 + 快捷入口 -->
    <div class="bottom-row">
      <div class="table-card">
        <div class="card-header">
          <span class="card-title">最近告警</span>
          <n-button size="tiny" text type="primary" @click="router.push('/alerts')">查看全部 →</n-button>
        </div>
        <n-data-table
          :columns="alertColumns"
          :data="recentAlerts"
          :loading="loading"
          :pagination="{ pageSize: 8 }"
          :bordered="false"
          size="small"
        />
      </div>

      <div class="quick-card">
        <div class="card-header">
          <span class="card-title">快捷入口</span>
        </div>
        <div class="quick-list">
          <div class="quick-item" @click="router.push('/star')">
            <div class="quick-icon">⭐</div>
            <div class="quick-info">
              <div class="quick-name">攻击链查询</div>
              <div class="quick-desc">按 correlation_id / IP / 主机名</div>
            </div>
          </div>
          <div class="quick-item" @click="router.push('/assets')">
            <div class="quick-icon">🖥️</div>
            <div class="quick-info">
              <div class="quick-name">资产管理</div>
              <div class="quick-desc">进程 / 用户 / 软件包 / 服务</div>
            </div>
          </div>
          <div class="quick-item" @click="router.push('/whitelist')">
            <div class="quick-icon">🔒</div>
            <div class="quick-info">
              <div class="quick-name">白名单管理</div>
              <div class="quick-desc">用户干预最高优先级</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, h } from 'vue'
import { useRouter } from 'vue-router'
import { NSelect, NButton, NDataTable, NTag } from 'naive-ui'
import * as echarts from 'echarts'
import { getAlerts, type AlertItem } from '../api/alert'
import { onWSMessage } from '../api/ws'

const router = useRouter()

const alerts = ref<AlertItem[]>([])
const loading = ref(false)
const filterSeverity = ref<string | null>(null)
const filterSource = ref<string | null>(null)
const filterDays = ref(7)
const trendContainer = ref<HTMLElement | null>(null)
const sourceContainer = ref<HTMLElement | null>(null)
let trendChart: echarts.ECharts | null = null
let sourceChart: echarts.ECharts | null = null

const severityOptions = [
  { label: '严重', value: 'critical' },
  { label: '高危', value: 'high' },
  { label: '中危', value: 'medium' },
  { label: '低危', value: 'low' },
]

const sourceOptions = [
  { label: '硬规则', value: 'hard_rule' },
  { label: '软基线', value: 'baseline' },
]

const daysOptions = [
  { label: '最近 7 天', value: 7 },
  { label: '最近 30 天', value: 30 },
  { label: '全部', value: 0 },
]

const stats = computed(() => {
  const list = alerts.value
  return {
    critical: list.filter(a => a.severity === 'critical').length,
    high: list.filter(a => a.severity === 'high').length,
    medium: list.filter(a => a.severity === 'medium').length,
    low: list.filter(a => a.severity === 'low').length,
    open: list.filter(a => a.status === 'open').length,
    resolved: list.filter(a => a.status === 'resolved').length,
  }
})

const recentAlerts = computed(() => {
  let list = alerts.value
  if (filterSeverity.value) list = list.filter(a => a.severity === filterSeverity.value)
  if (filterSource.value === 'hard_rule') list = list.filter(a => !a.details?.includes('[参考]'))
  if (filterSource.value === 'baseline') list = list.filter(a => a.details?.includes('[参考]'))
  return list.slice(0, 20)
})

const alertColumns = [
  { title: '时间', key: 'detected_at', width: 150, render: (row: AlertItem) => new Date(row.detected_at).toLocaleString('zh-CN', { hour12: false }) },
  { title: '规则', key: 'rule_name', width: 160, ellipsis: { tooltip: true } },
  {
    title: '严重度', key: 'severity', width: 90,
    render: (row: AlertItem) => {
      const type = row.severity === 'critical' ? 'error' : row.severity === 'high' ? 'warning' : 'info'
      return h(NTag, { type, size: 'small', round: true }, { default: () => row.severity })
    },
  },
  { title: '主机', key: 'agent_id', width: 180, ellipsis: { tooltip: true } },
  { title: '进程', key: 'comm', width: 100 },
  {
    title: '操作', key: 'actions', width: 80,
    render: (row: AlertItem) => h(NButton, {
      size: 'tiny', text: true, type: 'primary',
      onClick: () => router.push(row.correlation_id ? `/star?corr_id=${row.correlation_id}` : '/alerts'),
    }, { default: () => '详情' }),
  },
]

onMounted(async () => {
  await loadDashboard()
  window.addEventListener('resize', () => {
    trendChart?.resize()
    sourceChart?.resize()
  })
  onWSMessage('new_alert', async () => {
    await loadDashboard()
  })
})

async function loadDashboard() {
  loading.value = true
  try {
    alerts.value = await getAlerts()
    renderTrend()
    renderSource()
  } catch (err) {
    console.error('加载失败:', err)
  } finally {
    loading.value = false
  }
}

function renderTrend() {
  if (!trendContainer.value) return

  const now = new Date()
  const days: string[] = []
  const counts: number[] = []
  const days_count = filterDays.value || 30

  for (let i = days_count - 1; i >= 0; i--) {
    const d = new Date(now)
    d.setDate(d.getDate() - i)
    const key = d.toISOString().slice(0, 10)
    days.push(key.slice(5))
    counts.push(alerts.value.filter(a => a.detected_at.startsWith(key)).length)
  }

  if (!trendChart) {
    trendChart = echarts.init(trendContainer.value)
  }
  trendChart.setOption({
    tooltip: { trigger: 'axis' },
    grid: { left: 40, right: 20, top: 20, bottom: 30 },
    xAxis: { type: 'category', data: days, axisLabel: { fontSize: 11 } },
    yAxis: { type: 'value', minInterval: 1, axisLabel: { fontSize: 11 } },
    series: [{
      type: 'bar',
      data: counts,
      itemStyle: {
        color: '#4f46e5',
        borderRadius: [4, 4, 0, 0],
      },
      barMaxWidth: 40,
    }],
  })
}

function renderSource() {
  if (!sourceContainer.value) return

  const hardRule = alerts.value.filter(a => !a.details?.includes('[参考]')).length
  const baseline = alerts.value.filter(a => a.details?.includes('[参考]')).length

  if (!sourceChart) {
    sourceChart = echarts.init(sourceContainer.value)
  }
  sourceChart.setOption({
    tooltip: { trigger: 'item' },
    legend: { bottom: 0, fontSize: 11 },
    series: [{
      type: 'pie',
      radius: ['45%', '70%'],
      center: ['50%', '45%'],
      data: [
        { value: hardRule, name: '硬规则', itemStyle: { color: '#ef4444' } },
        { value: baseline, name: '软基线', itemStyle: { color: '#3b82f6' } },
      ],
      label: { fontSize: 11 },
    }],
  })
}
</script>

<style scoped>
.dashboard {
  padding: 12px;
  background: #f5f7fa;
  min-height: calc(100vh - 60px);
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.filter-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 12px;
  background: #fff;
  border-radius: 8px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.06);
}

/* 6 个统计卡片 */
.stat-grid {
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: 12px;
}

.stat-card {
  background: #fff;
  border-radius: 8px;
  padding: 20px 16px;
  text-align: center;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.06);
  transition: transform 0.2s;
  border-top: 3px solid #e2e8f0;
}

.stat-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.stat-critical { border-top-color: #dc2626; }
.stat-critical .stat-value { color: #dc2626; }

.stat-high { border-top-color: #f59e0b; }
.stat-high .stat-value { color: #f59e0b; }

.stat-medium { border-top-color: #3b82f6; }
.stat-medium .stat-value { color: #3b82f6; }

.stat-low { border-top-color: #64748b; }
.stat-low .stat-value { color: #64748b; }

.stat-pending { border-top-color: #ef4444; }
.stat-pending .stat-value { color: #ef4444; }

.stat-resolved { border-top-color: #10b981; }
.stat-resolved .stat-value { color: #10b981; }

.stat-value {
  font-size: 32px;
  font-weight: 700;
  line-height: 1;
}

.stat-label {
  font-size: 13px;
  color: #64748b;
  margin-top: 8px;
}

/* 图表 */
.chart-row {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 12px;
}

.chart-card {
  background: #fff;
  border-radius: 8px;
  padding: 12px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.06);
}

.chart-title {
  font-size: 13px;
  font-weight: 600;
  color: #1e293b;
  margin-bottom: 8px;
}

/* 底部行 */
.bottom-row {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 12px;
  flex: 1;
}

.table-card, .quick-card {
  background: #fff;
  border-radius: 8px;
  padding: 12px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.06);
  display: flex;
  flex-direction: column;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.card-title {
  font-size: 13px;
  font-weight: 600;
  color: #1e293b;
}

.quick-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.quick-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px;
  border-radius: 6px;
  cursor: pointer;
  transition: background 0.15s;
  border: 1px solid #f1f5f9;
}

.quick-item:hover {
  background: #f8fafc;
  border-color: #e0e7ff;
}

.quick-icon {
  font-size: 24px;
}

.quick-info {
  flex: 1;
}

.quick-name {
  font-size: 13px;
  font-weight: 600;
  color: #1e293b;
}

.quick-desc {
  font-size: 11px;
  color: #94a3b8;
  margin-top: 2px;
}

@media (max-width: 1400px) {
  .stat-grid { grid-template-columns: repeat(3, 1fr); }
  .chart-row { grid-template-columns: 1fr; }
  .bottom-row { grid-template-columns: 1fr; }
}
</style>

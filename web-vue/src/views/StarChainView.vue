<template>
  <div class="star-page">
    <!-- 左列 -->
    <div class="star-left">
      <div class="search-box">
        <n-input-group>
          <n-input v-model:value="correlationId" placeholder="输入 correlation_id / IP / 主机名" clearable @keyup.enter="handleQuery" />
          <n-button type="primary" @click="handleQuery" :loading="loading">查询</n-button>
        </n-input-group>
        <n-alert v-if="error" type="error" style="margin-top: 8px">{{ error }}</n-alert>
      </div>

      <div class="event-list" v-if="searchAlerts.length > 0">
        <div class="event-list-title">匹配告警（{{ searchAlerts.length }}）</div>
        <div
          v-for="alert in searchAlerts"
          :key="alert.id"
          class="event-item"
          @click="loadAlertChain(alert.correlation_id)"
        >
          <n-tag :type="alert.severity === 'critical' ? 'error' : 'warning'" round size="small">
            {{ alert.severity }}
          </n-tag>
          <span class="event-item-meta">{{ alert.rule_name }}</span>
        </div>
      </div>

      <div class="event-list" v-if="chainData">
        <div class="event-list-title">事件列表（{{ displayEvents.length }}）</div>
        <div
          v-for="(evt, idx) in displayEvents"
          :key="evt.id + '-' + idx"
          class="event-item"
          @click="showEventDetail(evt)"
        >
          <n-tag :type="getEventType(evt.event_type)" round size="small">
            {{ getEventTitle(evt) }}{{ evt.count > 1 ? ` x${evt.count}` : '' }}
          </n-tag>
          <span class="event-item-meta">PID:{{ evt.pid }} {{ truncate(evt.comm, 10) }}</span>
        </div>
        <n-button v-if="hasMore" text type="primary" size="small" @click="showAll = true">
          展开全部
        </n-button>
      </div>
    </div>

    <!-- 右列：Tab 切换 -->
    <div class="star-right" v-if="chainData">
      <n-tabs v-model:value="activeTab" type="line" animated class="star-tabs">
        <!-- Tab 1: 拓扑图（保留现有） -->
        <n-tab-pane name="topology" tab="拓扑图" style="padding: 0">
          <div class="zoom-hint">🖱️ 滚轮缩放 · 拖拽平移</div>
          <div class="topology-container" ref="topologyContainer"
            @wheel.prevent="onWheel"
            @mousedown="onMouseDown"
            @mousemove="onMouseMove"
            @mouseup="onMouseUp"
            @mouseleave="onMouseUp"
            :style="{ cursor: isDragging ? 'grabbing' : 'grab' }">
            <div class="topology-canvas" :style="{ transform: `translate(${panOffset.x}px, ${panOffset.y}px) scale(${zoomLevel})`, transformOrigin: 'center center' }">
              <template v-for="(evt, idx) in displayEvents" :key="idx">
                <div class="topo-node-wrapper">
                  <div
                    class="topo-node"
                    :class="`topo-node-${evt.event_type}`"
                    @click="showEventDetail(evt)"
                  >
                    <span class="topo-icon">{{ getEventIcon(evt.event_type) }}</span>
                    <span class="topo-text">{{ getEventTitle(evt) }}{{ evt.count > 1 ? ` x${evt.count}` : '' }}</span>
                    <span class="topo-pid">PID:{{ evt.pid }}</span>
                  </div>
                  <div v-if="idx < displayEvents.length - 1" class="topo-arrow">→</div>
                </div>
              </template>
            </div>
          </div>
        </n-tab-pane>

        <!-- Tab 2: 进程时间线（新） -->
        <n-tab-pane name="timeline" tab="进程时间线" style="padding: 0">
          <div class="timeline-toolbar">
            <n-text depth="3" style="font-size: 12px">
              {{ pidTimeline.length }} 个进程 · {{ chainData.total }} 个事件
            </n-text>
            <n-space :size="8">
              <n-button size="tiny" @click="expandAll">全部展开</n-button>
              <n-button size="tiny" @click="collapseAll">全部折叠</n-button>
            </n-space>
          </div>
          <div class="timeline-container">
            <div v-for="group in pidTimeline" :key="group.pid" class="pid-group">
              <div class="pid-header" @click="togglePid(group.pid)">
                <span class="toggle">{{ expandedPids.has(group.pid) ? '▼' : '▶' }}</span>
                <span class="pid-name">PID {{ group.pid }}</span>
                <n-tag size="tiny" round>{{ group.comm }}</n-tag>
                <span class="pid-meta">{{ group.events.length }} 个事件</span>
                <n-tag v-if="group.alertCount > 0" size="tiny" type="warning">
                  {{ group.alertCount }} 高危
                </n-tag>
              </div>
              <div v-if="expandedPids.has(group.pid)" class="pid-events">
                <div
                  v-for="(evt, i) in group.events"
                  :key="i"
                  class="timeline-event"
                  :class="`timeline-event-${evt.event_type}`"
                  @click="showEventDetail(evt)"
                >
                  <span class="evt-time">+{{ formatRelTime(evt.timestamp, group.firstTs) }}</span>
                  <span class="evt-icon">{{ getEventIcon(evt.event_type) }}</span>
                  <span class="evt-title">{{ getEventTitle(evt) }}</span>
                  <span class="evt-target" :title="evt.filename || evt.details">
                    {{ truncate(evt.filename || evt.details || '', 40) }}
                  </span>
                  <n-tag v-if="evt.count > 1" size="tiny" type="warning">x{{ evt.count }}</n-tag>
                </div>
              </div>
            </div>
          </div>
        </n-tab-pane>
      </n-tabs>
    </div>

    <div class="star-right" v-else>
      <n-empty description="输入 correlation_id / IP / 主机名 查询攻击链" style="margin: auto">
        <template #extra>
          <n-text depth="3" style="font-size: 12px">
            试试搜索 172.16.2.145 或 server-system
          </n-text>
        </template>
      </n-empty>
    </div>

    <!-- 事件详情弹窗 -->
    <n-modal v-model:show="showEventModal" preset="card" title="事件详情" style="max-width: 500px">
      <n-descriptions v-if="selectedEvent" :column="1" bordered>
        <n-descriptions-item label="类型">{{ getEventTitle(selectedEvent) }}</n-descriptions-item>
        <n-descriptions-item label="PID">{{ selectedEvent.pid }}</n-descriptions-item>
        <n-descriptions-item label="进程">{{ selectedEvent.comm }}</n-descriptions-item>
        <n-descriptions-item v-if="selectedEvent.filename" label="文件">{{ selectedEvent.filename }}</n-descriptions-item>
        <n-descriptions-item v-if="selectedEvent.details && selectedEvent.details !== 'null'" label="详情">{{ selectedEvent.details }}</n-descriptions-item>
        <n-descriptions-item label="时间">{{ formatTime(selectedEvent.timestamp) }}</n-descriptions-item>
      </n-descriptions>
    </n-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue'
import { useRoute } from 'vue-router'
import { NCard, NSpace, NInput, NButton, NInputGroup, NAlert, NTag, NModal, NDescriptions, NDescriptionsItem, NEmpty, NTabs, NTabPane, NText } from 'naive-ui'
import { getStarChain, searchStarChain, type StarChainResponse, type ChainNode } from '../api/star'

const route = useRoute()
const correlationId = ref('')
const chainData = ref<StarChainResponse | null>(null)
const loading = ref(false)
const error = ref('')
const showEventModal = ref(false)
const selectedEvent = ref<ChainNode | null>(null)
const showAll = ref(false)
const maxDisplay = 20
const topologyContainer = ref<HTMLElement | null>(null)
const zoomLevel = ref(1)
const activeTab = ref<'topology' | 'timeline'>('timeline')

const displayEvents = computed(() => {
  if (!chainData.value) return []
  const allEvents = chainData.value.tree || chainData.value.events || []
  const aggregated = aggregateData(allEvents)
  if (showAll.value) return aggregated
  return aggregated.slice(0, maxDisplay)
})

const hasMore = computed(() => {
  if (!chainData.value) return false
  const allEvents = chainData.value.tree || chainData.value.events || []
  return aggregateData(allEvents).length > maxDisplay && !showAll.value
})

// ========== 进程时间线 ==========

interface PidGroup {
  pid: number
  comm: string
  firstTs: number
  events: any[]
  alertCount: number
}

const expandedPids = ref<Set<number>>(new Set())

const pidTimeline = computed<PidGroup[]>(() => {
  if (!chainData.value) return []
  const events = chainData.value.tree || chainData.value.events || []
  const groups = new Map<number, PidGroup>()

  for (const e of events) {
    if (e.event_type === 'baseline_anomaly') continue
    const pid = e.pid || 0
    if (pid === 0) continue

    if (!groups.has(pid)) {
      groups.set(pid, { pid, comm: e.comm, firstTs: e.timestamp, events: [], alertCount: 0 })
    }
    const g = groups.get(pid)!
    g.events.push(e)
    // 高危事件统计
    if (e.event_type === 'tcp_connect' || e.event_type === 'bash_input') {
      g.alertCount++
    }
  }

  const result = [...groups.values()]
  for (const g of result) {
    g.events.sort((a, b) => a.timestamp - b.timestamp)
    g.firstTs = g.events[0].timestamp
  }
  result.sort((a, b) => a.firstTs - b.firstTs)
  return result
})

// 首次加载数据时默认全部展开
watch(pidTimeline, (list) => {
  if (list.length > 0 && expandedPids.value.size === 0) {
    expandedPids.value = new Set(list.map(g => g.pid))
  }
})

function togglePid(pid: number) {
  const s = new Set(expandedPids.value)
  if (s.has(pid)) { s.delete(pid) } else { s.add(pid) }
  expandedPids.value = s
}

function expandAll() {
  expandedPids.value = new Set(pidTimeline.value.map(g => g.pid))
}

function collapseAll() {
  expandedPids.value = new Set()
}

function formatRelTime(ts: number, base: number): string {
  const d = Math.max(0, Math.floor(ts - base))
  if (d < 1) return '0s'
  if (d < 60) return `${d}s`
  const m = Math.floor(d / 60)
  const s = d % 60
  return s > 0 ? `${m}m${s}s` : `${m}m`
}

// ========== 通用辅助 ==========

function aggregateData(events: any[]): ChainNode[] {
  const seen = new Map<string, ChainNode>()
  events.forEach(evt => {
    if (evt.event_type === 'baseline_anomaly') return
    const key = `${evt.pid}-${evt.event_type}-${evt.filename || ''}`
    if (seen.has(key)) {
      seen.get(key)!.count = (seen.get(key)!.count || 1) + 1
    } else {
      seen.set(key, { ...evt, count: 1 })
    }
  })
  return [...seen.values()].sort((a, b) => a.timestamp - b.timestamp)
}

onMounted(() => {
  const corrId = route.query.corr_id as string
  if (corrId) {
    correlationId.value = corrId
    handleQuery()
  }
})

async function handleQuery() {
  const q = correlationId.value.trim()
  if (!q) { error.value = '请输入查询内容'; return }
  loading.value = true
  error.value = ''
  showAll.value = false
  expandedPids.value = new Set()

  try {
    if (q.startsWith('corr_') || q.startsWith('agent-') || q.startsWith('global_')) {
      chainData.value = await getStarChain(q)
      return
    }

    const { searchStarChain } = await import('../api/star')
    const searchResult = await searchStarChain(q)

    if (searchResult.match_type === 'correlation_id' && searchResult.tree) {
      chainData.value = {
        correlation_id: searchResult.correlation_id || q,
        total: searchResult.total || 0,
        tree: searchResult.tree,
      }
    } else if (searchResult.alerts && searchResult.alerts.length > 0) {
      searchAlerts.value = searchResult.alerts
      chainData.value = null
    } else {
      error.value = '未找到匹配结果'
    }
  } catch (err: any) {
    error.value = err.response?.data?.error || '查询失败'
  } finally {
    loading.value = false
  }
}

const searchAlerts = ref<any[]>([])

function loadAlertChain(corrId: string) {
  if (!corrId) return
  loading.value = true
  error.value = ''
  expandedPids.value = new Set()
  getStarChain(corrId)
    .then((data) => { chainData.value = data })
    .catch((err: any) => { error.value = err.response?.data?.error || '查询失败' })
    .finally(() => { loading.value = false })
}

function showEventDetail(evt: any) { selectedEvent.value = evt; showEventModal.value = true }

function getEventType(t: string): 'success' | 'warning' | 'error' | 'info' {
  const m: Record<string, 'success' | 'warning' | 'error' | 'info'> = { execve: 'info', file_access: 'warning', tcp_connect: 'error', bash_input: 'success' }
  return m[t] || 'info'
}

function getEventTitle(evt: any): string {
  const m: Record<string, string> = { execve: '进程执行', file_access: '文件访问', tcp_connect: '网络连接', bash_input: 'Shell命令', xdp_alert: 'XDP告警' }
  return m[evt.event_type] || evt.event_type
}

function getEventIcon(t: string): string {
  const m: Record<string, string> = { execve: '▶', file_access: '📁', tcp_connect: '🌐', bash_input: '💻', xdp_alert: '📡' }
  return m[t] || '•'
}

function truncate(s: string, n: number): string { return s.length > n ? s.substring(0, n) + '..' : s }

const isDragging = ref(false)
const dragStart = ref({ x: 0, y: 0 })
const panOffset = ref({ x: 0, y: 0 })

function onWheel(e: WheelEvent) {
  e.preventDefault()
  const delta = e.deltaY > 0 ? -0.1 : 0.1
  zoomLevel.value = Math.max(0.3, Math.min(3, zoomLevel.value + delta))
}

function onMouseDown(e: MouseEvent) {
  isDragging.value = true
  dragStart.value = { x: e.clientX - panOffset.value.x, y: e.clientY - panOffset.value.y }
}

function onMouseMove(e: MouseEvent) {
  if (!isDragging.value) return
  panOffset.value = { x: e.clientX - dragStart.value.x, y: e.clientY - dragStart.value.y }
}

function onMouseUp() { isDragging.value = false }

function formatTime(ts: number): string { return new Date(ts * 1000).toLocaleString('zh-CN') }
</script>

<style scoped>
.star-page {
  display: flex;
  height: calc(100vh - 60px);
  padding: 12px;
  gap: 12px;
  overflow: hidden;
}

.star-left {
  flex: 0 0 320px;
  min-width: 320px;
  display: flex;
  flex-direction: column;
  gap: 12px;
  overflow-y: auto;
}

.search-box {
  background: #fff;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 12px;
}

.event-list {
  flex: 1;
  background: #fff;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 12px;
  overflow-y: auto;
}

.event-list-title {
  font-weight: 600;
  margin-bottom: 8px;
  font-size: 14px;
}

.event-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px;
  border-radius: 6px;
  cursor: pointer;
  transition: background 0.15s;
}

.event-item:hover { background: #f0f4f8; }

.event-item-meta {
  font-size: 12px;
  color: #64748b;
}

.star-right {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  background: #fff;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  overflow: hidden;
  position: relative;
}

.star-tabs {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.star-tabs :deep(.n-tabs-nav) {
  padding: 0 12px;
}

.star-tabs :deep(.n-tabs-pane-wrapper) {
  flex: 1;
  overflow: hidden;
}

.star-tabs :deep(.n-tab-pane) {
  height: 100%;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

/* ========== 拓扑图（原有） ========== */

.zoom-hint {
  padding: 8px 12px;
  font-size: 12px;
  color: #94a3b8;
  border-bottom: 1px solid #e2e8f0;
  background: #f8fafc;
  flex-shrink: 0;
}

.topology-container {
  flex: 1;
  overflow: hidden;
  position: relative;
  user-select: none;
}

.topology-canvas {
  position: relative;
  min-width: max-content;
  display: flex;
  align-items: center;
  height: 100%;
}

.topo-node-wrapper {
  display: flex;
  align-items: center;
  flex-shrink: 0;
}

.topo-node {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 200px;
  min-height: 44px;
  max-height: 44px;
  padding: 0 14px;
  border-radius: 8px;
  cursor: pointer;
  box-shadow: 0 1px 3px rgba(0,0,0,0.1);
  transition: all 0.2s;
}

.topo-node:hover { transform: translateX(4px); box-shadow: 0 4px 12px rgba(0,0,0,0.15); }

.topo-node-execve { background: #dbeafe; border-left: 4px solid #3b82f6; }
.topo-node-file_access { background: #fef3c7; border-left: 4px solid #f59e0b; }
.topo-node-tcp_connect { background: #fee2e2; border-left: 4px solid #ef4444; }
.topo-node-bash_input { background: #d1fae5; border-left: 4px solid #10b981; }

.topo-icon { font-size: 16px; flex-shrink: 0; }
.topo-text { flex: 1; font-size: 13px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.topo-pid { font-size: 11px; color: #64748b; flex-shrink: 0; }

.topo-arrow {
  font-size: 20px;
  color: #94a3b8;
  margin: 0 8px;
  flex-shrink: 0;
}

/* ========== 进程时间线（新增） ========== */

.timeline-toolbar {
  padding: 8px 12px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid #e2e8f0;
  background: #f8fafc;
  flex-shrink: 0;
}

.timeline-container {
  flex: 1;
  overflow-y: auto;
  padding: 12px 16px;
}

.pid-group {
  margin-bottom: 16px;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  overflow: hidden;
  background: #fff;
}

.pid-header {
  padding: 10px 12px;
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  background: #f8fafc;
  user-select: none;
  transition: background 0.15s;
}

.pid-header:hover { background: #f1f5f9; }

.pid-header .toggle {
  width: 14px;
  font-size: 10px;
  color: #64748b;
}

.pid-header .pid-name {
  font-family: monospace;
  font-weight: 600;
  font-size: 13px;
  color: #1e293b;
}

.pid-header .pid-meta {
  font-size: 12px;
  color: #64748b;
  margin-left: auto;
}

.pid-events {
  padding: 4px 0;
}

.timeline-event {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 6px 12px 6px 30px;
  cursor: pointer;
  transition: background 0.15s;
  border-left: 3px solid transparent;
  font-size: 13px;
}

.timeline-event:hover { background: #f0f4f8; }

.timeline-event-execve      { border-left-color: #3b82f6; }
.timeline-event-file_access { border-left-color: #f59e0b; }
.timeline-event-tcp_connect { border-left-color: #ef4444; }
.timeline-event-bash_input  { border-left-color: #10b981; }
.timeline-event-xdp_alert   { border-left-color: #8b5cf6; }

.timeline-event .evt-time {
  font-family: monospace;
  font-size: 12px;
  color: #94a3b8;
  flex-shrink: 0;
  width: 48px;
  text-align: right;
}

.timeline-event .evt-icon {
  font-size: 14px;
  flex-shrink: 0;
}

.timeline-event .evt-title {
  font-weight: 500;
  flex-shrink: 0;
  width: 70px;
}

.timeline-event .evt-target {
  flex: 1;
  color: #475569;
  font-family: monospace;
  font-size: 12px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
</style>

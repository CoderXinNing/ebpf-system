<template>
  <div class="star-page">
    <!-- 左列 -->
    <div class="star-left">
      <div class="search-box">
        <n-input-group>
          <n-input v-model:value="correlationId" placeholder="输入 correlation_id" clearable @keyup.enter="handleQuery" />
          <n-button type="primary" @click="handleQuery" :loading="loading">查询</n-button>
        </n-input-group>
        <n-alert v-if="error" type="error" style="margin-top: 8px">{{ error }}</n-alert>
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

    <!-- 右列：拓扑图 -->
    <div class="star-right" v-if="chainData">
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
    </div>
    <div class="star-right" v-else>
      <n-empty description="输入 correlation_id 查询攻击链" style="margin: auto" />
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
import { ref, onMounted, computed } from 'vue'
import { useRoute } from 'vue-router'
import { NCard, NSpace, NInput, NButton, NInputGroup, NAlert, NTag, NModal, NDescriptions, NDescriptionsItem, NEmpty } from 'naive-ui'
import { getStarChain, type StarChainResponse, type ChainNode } from '../api/star'

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
  if (!correlationId.value.trim()) { error.value = '请输入 correlation_id'; return }
  loading.value = true
  error.value = ''
  chainData.value = null
  showAll.value = false
  try {
    chainData.value = await getStarChain(correlationId.value.trim())
  } catch (err: any) {
    error.value = err.response?.data?.error || '查询失败'
  } finally {
    loading.value = false
  }
}

function showEventDetail(evt: any) { selectedEvent.value = evt; showEventModal.value = true }

function getEventType(t: string): 'success' | 'warning' | 'error' | 'info' {
  const m: Record<string, 'success' | 'warning' | 'error' | 'info'> = { execve: 'info', file_access: 'warning', tcp_connect: 'error', bash_input: 'success' }
  return m[t] || 'info'
}

function getEventTitle(evt: any): string {
  const m: Record<string, string> = { execve: '进程执行', file_access: '文件访问', tcp_connect: '网络连接', bash_input: 'Shell命令' }
  return m[evt.event_type] || evt.event_type
}

function getEventIcon(t: string): string {
  const m: Record<string, string> = { execve: '▶', file_access: '📁', tcp_connect: '🌐', bash_input: '💻' }
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

function onMouseUp() {
  isDragging.value = false
}

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
</style>

<template>
  <div class="probe-page">
    <!-- 左侧：主机列表 -->
    <div class="host-panel">
      <div class="panel-header">
        <n-input v-model:value="hostKeyword" placeholder="搜索主机" size="small" clearable />
      </div>
      <div class="host-list">
        <div
          v-for="host in filteredHosts"
          :key="host.id"
          class="host-item"
          :class="{ active: selectedHost?.id === host.id }"
          @click="selectHost(host)"
        >
          <div class="host-item-top">
            <span class="host-name">{{ host.hostname }}</span>
            <span class="host-status" :class="isOnline(host) ? 'online' : 'offline'"></span>
          </div>
          <div class="host-item-bottom">
            <span class="host-ip">{{ host.ip_addr }}</span>
            <span class="host-probes" :class="{ abnormal: hostAbnormalCount(host) > 0 }">
              {{ hostAbnormalCount(host) > 0 ? hostAbnormalCount(host) + ' 异常' : hostProbeCount(host) + ' 探针' }}
            </span>
          </div>
        </div>
        <n-empty v-if="filteredHosts.length === 0" description="无主机" size="small" style="margin-top: 40px" />
      </div>
    </div>

    <!-- 右侧：探针详情 -->
    <div class="probe-panel">
      <template v-if="selectedHost">
        <div class="probe-header">
          <div class="probe-header-left">
            <h3 style="margin: 0">{{ selectedHost.hostname }}</h3>
            <n-tag :type="isOnline(selectedHost) ? 'success' : 'default'" size="small" round>
              {{ isOnline(selectedHost) ? '在线' : '离线' }}
            </n-tag>
            <n-tag size="small">{{ selectedHost.ip_addr }}</n-tag>
            <n-tag size="small" type="info">{{ selectedHost.capability_level || 'unknown' }}</n-tag>
            <n-tag v-if="currentAbnormal > 0" type="warning" size="small">
              {{ currentAbnormal }} 异常
            </n-tag>
            <n-tag v-else-if="probeList.length > 0" type="success" size="small">
              全部正常
            </n-tag>
          </div>
          <div class="probe-header-right">
            <n-switch v-model:value="autoRefresh" size="small">
              <template #checked>自动 30s</template>
              <template #unchecked>自动 30s</template>
            </n-switch>
            <n-button size="small" @click="loadHosts">刷新</n-button>
          </div>
        </div>

        <n-tabs v-model:value="activeTab" type="line" animated class="probe-tabs">
        <n-tab-pane name="probes" tab="探针状态" style="padding: 0">
        <div class="probe-toolbar">
          <n-input v-model:value="probeKeyword" placeholder="搜索探针" size="small" clearable style="width: 240px" />
          <n-text depth="3" style="font-size: 12px">
            共 {{ probeList.length }} 个探针 · {{ currentAbnormal }} 异常
          </n-text>
        </div>

        <div class="probe-table">
          <n-data-table
            :columns="columns"
            :data="filteredProbes"
            :loading="loading"
            :pagination="false"
            :bordered="false"
            size="small"
          />
        </div>
        </n-tab-pane>

        <n-tab-pane name="env" tab="环境信息" style="padding: 0">
          <div class="env-content">
            <template v-if="hasEnvData">
              <div class="env-section">
                <div class="env-section-title">内核信息</div>
                <n-descriptions :column="2" bordered size="small">
                  <n-descriptions-item label="内核版本">{{ kernelInfo.version || '-' }}</n-descriptions-item>
                  <n-descriptions-item label="架构">{{ kernelInfo.arch || '-' }}</n-descriptions-item>
                  <n-descriptions-item label="BTF 支持" :span="2">
                    <n-tag :type="kernelInfo.btf_enabled ? 'success' : 'warning'" size="small" round>
                      {{ kernelInfo.btf_enabled ? '✅ 支持（CO-RE 可用）' : '❌ 不支持' }}
                    </n-tag>
                  </n-descriptions-item>
                </n-descriptions>
              </div>

              <div class="env-section">
                <div class="env-section-title">框架 / 工具链</div>
                <n-descriptions :column="2" bordered size="small">
                  <n-descriptions-item
                    v-for="item in frameworkItems"
                    :key="item.key"
                    :label="item.label"
                  >
                    <n-tag :type="item.value ? 'success' : 'default'" size="small" round>
                      {{ item.value ? '✅ 可用' : '—' }}
                    </n-tag>
                  </n-descriptions-item>
                </n-descriptions>
              </div>
            </template>
            <n-empty v-else description="该主机未上报环境信息" style="margin-top: 40px" />
          </div>
        </n-tab-pane>
        </n-tabs>
      </template>
      <n-empty v-else description="请从左侧选择主机" style="margin: auto" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch, h } from 'vue'
import {
  NInput, NTag, NButton, NDataTable, NEmpty, NText, NSwitch,
  NTabs, NTabPane, NDescriptions, NDescriptionsItem,
} from 'naive-ui'
import { getAgents, type AgentInfo, type ProbeStatusEntry } from '../api/agent'

const hosts = ref<AgentInfo[]>([])
const selectedHost = ref<AgentInfo | null>(null)
const hostKeyword = ref('')
const probeKeyword = ref('')
const loading = ref(false)
const autoRefresh = ref(true)
const activeTab = ref<'probes' | 'env'>('probes')

let refreshTimer: number | null = null

// ---- 主机列表 ----
const filteredHosts = computed(() => {
  if (!hostKeyword.value.trim()) return hosts.value
  const kw = hostKeyword.value.toLowerCase()
  return hosts.value.filter(h =>
    h.hostname.toLowerCase().includes(kw) || h.ip_addr.toLowerCase().includes(kw)
  )
})

const isOnline = (host: AgentInfo) => (Date.now() / 1000 - host.last_seen) < 120

function hostProbeCount(host: AgentInfo): number {
  return host.probe_status ? Object.keys(host.probe_status).length : 0
}

function isAbnormalStatus(status: string): boolean {
  return status === 'loaded-silent' || status === 'failed' || status === 'unknown probe'
}

function hostAbnormalCount(host: AgentInfo): number {
  if (!host.probe_status) return 0
  return Object.values(host.probe_status).filter(p => isAbnormalStatus(p.status)).length
}

// ---- 当前主机探针列表 ----
interface ProbeRow extends ProbeStatusEntry {}

const probeList = computed<ProbeRow[]>(() => {
  if (!selectedHost.value?.probe_status) return []
  return Object.entries(selectedHost.value.probe_status).map(([name, p]) => ({
    name,
    status: p.status,
    reason: p.reason,
    last_event_at: p.last_event_at,
    last_check_at: p.last_check_at,
    selftest_ok: p.selftest_ok,
    consecutive_failures: p.consecutive_failures,
    loaded_at: p.loaded_at,
  }))
})

const currentAbnormal = computed(() =>
  probeList.value.filter(p => isAbnormalStatus(p.status)).length
)

const filteredProbes = computed(() => {
  if (!probeKeyword.value.trim()) return probeList.value
  const kw = probeKeyword.value.toLowerCase()
  return probeList.value.filter(p => p.name.toLowerCase().includes(kw))
})

// ---- 状态/时间辅助 ----
function statusTagType(status: string): 'success' | 'warning' | 'error' | 'info' | 'default' {
  switch (status) {
    case 'loaded': return 'success'
    case 'loaded-silent': return 'warning'
    case 'loaded-no-activity': return 'default'
    case 'failed':
    case 'unknown probe': return 'error'
    case 'loading': return 'info'
    default: return 'default'
  }
}

function statusText(status: string): string {
  switch (status) {
    case 'loaded': return '运行中'
    case 'loaded-silent': return '静默（自检失败）'
    case 'loaded-no-activity': return '无法自检'
    case 'failed': return '加载失败'
    case 'disabled': return '已禁用'
    case 'loading': return '加载中'
    case 'unknown probe': return '未注册'
    default: return status || '未知'
  }
}

function formatProbeTime(ts: number): string {
  if (!ts) return '-'
  return new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false })
}

// ---- 环境信息 ----
const kernelInfo = computed(() => {
  return selectedHost.value?.kernel_info || { version: '', arch: '', btf_enabled: false }
})

const frameworkItems = computed(() => {
  const fw = selectedHost.value?.framework
  if (!fw) return []
  return [
    { key: 'bcc', label: 'BCC', value: fw.bcc_available },
    { key: 'libbpf', label: 'libbpf', value: fw.libbpf_available },
    { key: 'libbpf_core', label: 'libbpf CO-RE', value: fw.libbpf_core },
    { key: 'bpftrace', label: 'bpftrace', value: fw.bpftrace_available },
    { key: 'clang', label: 'clang', value: fw.clang_available },
    { key: 'llvm', label: 'LLVM', value: fw.llvm_available },
    { key: 'kernel_headers', label: '内核头文件', value: fw.kernel_headers_available },
    { key: 'go_ebpf', label: 'Go eBPF', value: fw.go_ebpf_available },
  ]
})

const hasEnvData = computed(() => {
  const fw = selectedHost.value?.framework
  const ki = selectedHost.value?.kernel_info
  const fwOK = !!(fw && Object.values(fw).some(v => v === true))
  const kiOK = !!(ki && ki.version)
  return fwOK || kiOK
})

const columns = [
  { title: '探针', key: 'name', width: 180 },
  {
    title: '状态',
    key: 'status',
    width: 180,
    render(row: ProbeRow) {
      return h(NTag, { type: statusTagType(row.status), round: true, size: 'small' },
        { default: () => statusText(row.status) })
    },
  },
  {
    title: '原因',
    key: 'reason',
    render(row: ProbeRow) { return row.reason || '-' },
  },
  {
    title: '最近事件',
    key: 'last_event_at',
    width: 180,
    render(row: ProbeRow) { return formatProbeTime(row.last_event_at) },
  },
  {
    title: '最近自检',
    key: 'last_check_at',
    width: 180,
    render(row: ProbeRow) { return formatProbeTime(row.last_check_at) },
  },
  {
    title: '连续失败',
    key: 'consecutive_failures',
    width: 100,
    render(row: ProbeRow) {
      const n = row.consecutive_failures || 0
      return n > 0 ? h(NText, { type: 'warning' }, { default: () => String(n) }) : '0'
    },
  },
]

// ---- 数据加载 ----
async function loadHosts() {
  loading.value = true
  try {
    const agents = await getAgents()
    hosts.value = agents

    // 保持当前选中；如果没选过或选中的主机没了，默认选第一个
    if (selectedHost.value) {
      const still = agents.find(a => a.id === selectedHost.value!.id)
      if (still) {
        selectedHost.value = still
      } else {
        selectedHost.value = agents[0] || null
      }
    } else {
      selectedHost.value = agents[0] || null
    }
  } catch (err) {
    console.error('加载主机失败:', err)
  } finally {
    loading.value = false
  }
}

function selectHost(host: AgentInfo) {
  selectedHost.value = host
}

function setupAutoRefresh() {
  if (refreshTimer !== null) {
    clearInterval(refreshTimer)
    refreshTimer = null
  }
  if (autoRefresh.value) {
    refreshTimer = window.setInterval(loadHosts, 30_000)
  }
}

onMounted(loadHosts)
onMounted(setupAutoRefresh)
onUnmounted(() => {
  if (refreshTimer !== null) clearInterval(refreshTimer)
})
watch(autoRefresh, setupAutoRefresh)
</script>

<style scoped>
.probe-page {
  display: flex;
  height: calc(100vh - 60px);
  background: #f5f7fa;
  padding: 12px;
  gap: 12px;
}

/* 左侧主机列表（照 AssetView） */
.host-panel {
  flex: 0 0 260px;
  background: #fff;
  border-radius: 8px;
  display: flex;
  flex-direction: column;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.06);
  overflow: hidden;
}

.panel-header {
  padding: 10px 12px;
  border-bottom: 1px solid #e2e8f0;
}

.host-list {
  flex: 1;
  overflow-y: auto;
  padding: 4px;
}

.host-item {
  padding: 10px 12px;
  border-radius: 6px;
  cursor: pointer;
  margin-bottom: 2px;
  transition: background 0.15s;
}

.host-item:hover {
  background: #f1f5f9;
}

.host-item.active {
  background: #e0e7ff;
  border-left: 3px solid #4f46e5;
  padding-left: 9px;
}

.host-item-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 4px;
}

.host-name {
  font-weight: 600;
  font-size: 13px;
  color: #1e293b;
}

.host-status {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}

.host-status.online {
  background: #10b981;
  box-shadow: 0 0 6px rgba(16, 185, 129, 0.5);
}

.host-status.offline {
  background: #94a3b8;
}

.host-item-bottom {
  display: flex;
  justify-content: space-between;
  font-size: 11px;
  color: #64748b;
}

.host-item-bottom .host-probes.abnormal {
  color: #f59e0b;
  font-weight: 600;
}

/* 右侧 */
.probe-panel {
  flex: 1;
  background: #fff;
  border-radius: 8px;
  display: flex;
  flex-direction: column;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.06);
  overflow: hidden;
}

.probe-header {
  padding: 12px 16px;
  border-bottom: 1px solid #e2e8f0;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.probe-header-left {
  display: flex;
  align-items: center;
  gap: 10px;
}

.probe-header-right {
  display: flex;
  gap: 12px;
  align-items: center;
}

.probe-toolbar {
  padding: 12px 16px;
  display: flex;
  align-items: center;
  gap: 12px;
  border-bottom: 1px solid #e2e8f0;
}

.probe-table {
  flex: 1;
  overflow: auto;
  padding: 8px 16px;
}

.probe-tabs {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.probe-tabs :deep(.n-tabs-nav) {
  padding: 0 16px;
}

.probe-tabs :deep(.n-tabs-pane-wrapper) {
  flex: 1;
  overflow: hidden;
}

.probe-tabs :deep(.n-tab-pane) {
  height: 100%;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.env-content {
  padding: 16px;
  overflow-y: auto;
  height: 100%;
}

.env-section {
  margin-bottom: 24px;
}

.env-section-title {
  font-weight: 600;
  font-size: 13px;
  color: #475569;
  margin-bottom: 8px;
}
</style>

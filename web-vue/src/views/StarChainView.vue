<template>
  <div class="star-chain-container">
    <n-card title="星轨攻击链查询" bordered>
      <n-space vertical>
        <n-input-group>
          <n-input
            v-model:value="correlationId"
            placeholder="输入 correlation_id，例如：corr_1788767448273985676"
            clearable
            @keyup.enter="handleQuery"
          />
          <n-button type="primary" @click="handleQuery" :loading="loading">
            查询
          </n-button>
        </n-input-group>

        <n-alert v-if="error" type="error" :show-icon="true">
          {{ error }}
        </n-alert>

        <template v-if="chainData">
          <n-alert type="success" :show-icon="true">
            共找到 {{ chainData.total }} 个关联事件
          </n-alert>

          <n-timeline>
            <n-timeline-item
              v-for="evt in chainData.events"
              :key="evt.id"
              :type="getEventType(evt.event_type)"
              :title="getEventTitle(evt)"
              :time="formatTime(evt.timestamp)"
            >
              <n-space vertical>
                <n-text depth="2">PID: {{ evt.pid }} | 进程: {{ evt.comm }}</n-text>
                <n-text v-if="evt.filename" depth="3">文件: {{ evt.filename }}</n-text>
                <n-text v-if="evt.details" depth="3">详情: {{ evt.details }}</n-text>
              </n-space>
            </n-timeline-item>
          </n-timeline>
        </template>
      </n-space>
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { NCard, NSpace, NInput, NButton, NInputGroup, NAlert, NTimeline, NTimelineItem, NText } from 'naive-ui'
import { getStarChain, type StarChainResponse } from '../api/star'

const route = useRoute()
const correlationId = ref('')
const chainData = ref<StarChainResponse | null>(null)
const loading = ref(false)
const error = ref('')

onMounted(() => {
  const corrId = route.query.corr_id as string
  if (corrId) {
    correlationId.value = corrId
    handleQuery()
  }
})

async function handleQuery() {
  if (!correlationId.value.trim()) {
    error.value = '请输入 correlation_id'
    return
  }

  loading.value = true
  error.value = ''
  chainData.value = null

  try {
    chainData.value = await getStarChain(correlationId.value.trim())
  } catch (err: any) {
    error.value = err.response?.data?.error || '查询失败'
  } finally {
    loading.value = false
  }
}

function getEventType(eventType: string): 'success' | 'warning' | 'error' | 'info' {
  const map: Record<string, 'success' | 'warning' | 'error' | 'info'> = {
    execve: 'info',
    file_access: 'warning',
    tcp_connect: 'error',
    bash_input: 'success',
  }
  return map[eventType] || 'info'
}

function getEventTitle(evt: any): string {
  const titles: Record<string, string> = {
    execve: '进程启动',
    file_access: '文件访问',
    tcp_connect: '网络连接',
    bash_input: 'Shell 命令',
  }
  return titles[evt.event_type] || evt.event_type
}

function formatTime(timestamp: number): string {
  const date = new Date(timestamp * 1000)
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}
</script>

<style scoped>
.star-chain-container {
  padding: 24px;
  max-width: 900px;
  margin: 0 auto;
}
</style>

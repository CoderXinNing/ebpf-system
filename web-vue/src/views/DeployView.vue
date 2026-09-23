<template>
  <div class="deploy-page">
    <!-- 顶部：生成 Token -->
    <n-card title="生成注册 Token" bordered>
      <n-space vertical :size="16">
        <n-grid :cols="3" :x-gap="16">
          <n-grid-item>
            <div class="form-label">名称</div>
            <n-input v-model:value="form.name" placeholder="如：生产环境批次1" />
          </n-grid-item>
          <n-grid-item>
            <div class="form-label">使用次数</div>
            <n-input-number v-model:value="form.max_uses" :min="1" :max="10000" style="width: 100%" />
            <div class="form-hint">默认 1（单台）；批量部署可调大</div>
          </n-grid-item>
          <n-grid-item>
            <div class="form-label">有效期（小时）</div>
            <n-input-number v-model:value="form.ttl_hours" :min="1" :max="8760" style="width: 100%" />
            <div class="form-hint">默认 24 小时</div>
          </n-grid-item>
        </n-grid>
        <n-button type="primary" @click="handleCreate" :loading="creating">
          生成 Token
        </n-button>
      </n-space>
    </n-card>

    <!-- Token 生成后显示安装命令 -->
    <n-modal v-model:show="showCmdModal" preset="card" title="安装命令" style="max-width: 700px">
      <n-space vertical :size="16">
        <n-alert type="success" :show-icon="true">
          Token 已生成。请在目标主机上执行以下命令：
        </n-alert>

        <div class="cmd-block">
          <pre>{{ installCmd }}</pre>
          <n-button size="tiny" type="primary" @click="copyCmd">复制</n-button>
        </div>

        <n-alert type="warning" :show-icon="true">
          <div>⚠️ Token 只显示一次，请立即复制</div>
          <div style="margin-top: 4px; font-size: 12px; opacity: 0.8">
            有效期 {{ form.ttl_hours }} 小时 / 可使用 {{ form.max_uses }} 次
          </div>
        </n-alert>
      </n-space>
    </n-modal>

    <!-- Token 列表 -->
    <n-card title="注册 Token 列表" bordered style="margin-top: 16px">
      <n-data-table
        :columns="tokenColumns"
        :data="tokens"
        :loading="loading"
        :bordered="false"
        size="small"
      />
    </n-card>

    <!-- 已部署 Agent -->
    <n-card title="已部署主机" bordered style="margin-top: 16px">
      <n-data-table
        :columns="agentColumns"
        :data="agents"
        :loading="loading"
        :bordered="false"
        size="small"
      />
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, h, computed } from 'vue'
import { NCard, NSpace, NGrid, NGridItem, NInput, NInputNumber, NButton, NModal, NAlert, NDataTable, NTag, useMessage, useDialog } from 'naive-ui'
import http from '../api/http'
import { listTokens, createToken, revokeToken, type Token } from '../api/deploy'

const message = useMessage()
const dialog = useDialog()

const form = ref({
  name: '',
  max_uses: 1,
  ttl_hours: 24,
})

const creating = ref(false)
const loading = ref(false)
const showCmdModal = ref(false)
const generatedToken = ref('')

const tokens = ref<Token[]>([])
const agents = ref<any[]>([])

const serverURL = computed(() => {
  return window.location.origin
})

const installCmd = computed(() => {
  return `curl -sSL ${serverURL.value}/install.sh | sudo bash -s -- \\
  --server=${serverURL.value} \\
  --token=${generatedToken.value}`
})

const tokenColumns = [
  { title: 'ID', key: 'id', width: 60 },
  { title: '名称', key: 'name', width: 160 },
  {
    title: '用量', key: 'usage', width: 100,
    render: (row: Token) => `${row.used_count} / ${row.max_uses}`,
  },
  {
    title: '过期时间', key: 'expires_at', width: 170,
    render: (row: Token) => new Date(row.expires_at).toLocaleString('zh-CN', { hour12: false }),
  },
  {
    title: '状态', key: 'status', width: 100,
    render: (row: Token) => {
      const now = new Date()
      const expired = new Date(row.expires_at) < now
      const usedUp = row.used_count >= row.max_uses
      if (row.revoked_at) return h(NTag, { type: 'default', size: 'small', round: true }, { default: () => '已撤销' })
      if (expired) return h(NTag, { type: 'warning', size: 'small', round: true }, { default: () => '已过期' })
      if (usedUp) return h(NTag, { type: 'default', size: 'small', round: true }, { default: () => '已用完' })
      return h(NTag, { type: 'success', size: 'small', round: true }, { default: () => '可用' })
    },
  },
  {
    title: '操作', key: 'actions', width: 100,
    render: (row: Token) => {
      if (row.revoked_at) return '-'
      return h(NButton, {
        size: 'tiny',
        type: 'error',
        onClick: () => handleRevoke(row),
      }, { default: () => '撤销' })
    },
  },
]

const agentColumns = [
  { title: '主机名', key: 'hostname', width: 180 },
  { title: 'IP', key: 'ip_addr', width: 140 },
  {
    title: '状态', key: 'status', width: 90,
    render: (row: any) => {
      const now = Date.now() / 1000
      const online = now - row.last_seen < 120
      return h(NTag, { type: online ? 'success' : 'default', size: 'small', round: true },
        { default: () => online ? '在线' : '离线' })
    },
  },
  { title: '能力', key: 'capability_level', width: 80 },
  { title: '版本', key: 'version', width: 80 },
  {
    title: '最后心跳', key: 'last_seen', width: 170,
    render: (row: any) => row.last_seen ? new Date(row.last_seen * 1000).toLocaleString('zh-CN', { hour12: false }) : '-',
  },
  {
    title: '操作', key: 'actions', width: 100,
    render: (row: any) => h(NButton, {
      size: 'tiny',
      type: 'error',
      onClick: () => handleRevokeAgent(row),
    }, { default: () => '撤销' }),
  },
]

onMounted(async () => {
  await loadAll()
})

async function loadAll() {
  loading.value = true
  try {
    await Promise.all([loadTokens(), loadAgents()])
  } finally {
    loading.value = false
  }
}

async function loadTokens() {
  try {
    tokens.value = await listTokens()
  } catch (err: any) {
    console.error('加载 Token 失败:', err)
  }
}

async function loadAgents() {
  try {
    const { data } = await http.get('/agents')
    agents.value = data.agents || []
  } catch (err: any) {
    console.error('加载 Agent 失败:', err)
  }
}

async function handleCreate() {
  if (!form.value.name.trim()) {
    message.warning('请输入名称')
    return
  }
  creating.value = true
  try {
    const resp = await createToken({
      name: form.value.name,
      max_uses: form.value.max_uses,
      ttl_hours: form.value.ttl_hours,
    })
    generatedToken.value = resp.token
    showCmdModal.value = true
    form.value.name = ''
    await loadTokens()
  } catch (err: any) {
    message.error(err.response?.data?.error || '生成失败')
  } finally {
    creating.value = false
  }
}

function copyCmd() {
  const text = installCmd.value
  const textarea = document.createElement('textarea')
  textarea.value = text
  textarea.style.position = 'fixed'
  textarea.style.opacity = '0'
  document.body.appendChild(textarea)
  textarea.select()
  document.execCommand('copy')
  document.body.removeChild(textarea)
  message.success('已复制到剪贴板')
}

function handleRevoke(row: Token) {
  dialog.warning({
    title: '确认撤销',
    content: `撤销 Token "${row.name}" 后，未使用它的 Agent 将无法注册。`,
    positiveText: '撤销',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await revokeToken(row.id)
        message.success('Token 已撤销')
        await loadTokens()
      } catch (err: any) {
        message.error(err.response?.data?.error || '撤销失败')
      }
    },
  })
}

function handleRevokeAgent(row: any) {
  dialog.warning({
    title: '确认撤销 Agent',
    content: `撤销 "${row.hostname}" 后，该 Agent 将无法再连接 Server（L4 校验拒绝）。`,
    positiveText: '撤销',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await http.post('/agents/revoke', { agent_id: row.id })
        message.success('Agent 已撤销')
        await loadAgents()
      } catch (err: any) {
        message.error(err.response?.data?.error || '撤销失败')
      }
    },
  })
}
</script>

<style scoped>
.deploy-page {
  padding: 16px;
  max-width: 1400px;
  margin: 0 auto;
}

.form-label {
  font-size: 13px;
  font-weight: 600;
  color: #334155;
  margin-bottom: 6px;
}

.form-hint {
  font-size: 12px;
  color: #94a3b8;
  margin-top: 4px;
}

.cmd-block {
  background: #1e293b;
  color: #e2e8f0;
  padding: 16px;
  border-radius: 6px;
  position: relative;
  overflow-x: auto;
}

.cmd-block pre {
  margin: 0;
  font-family: 'Monaco', 'Consolas', monospace;
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-all;
}

.cmd-block button {
  position: absolute;
  top: 8px;
  right: 8px;
}
</style>

<template>
  <Layout>
    <div class="probes-container">
      <!-- eBPF 运行要求警告 -->
      <div class="warn-banner">
        ⚠️ eBPF 运行要求：内核 ≥ 5.8 | BTF 支持 | libbpf/CO-RE | Linux x86_64/ARM64
      </div>

      <!-- 默认探针下发 -->
      <div class="probe-card">
        <div class="card-header">
          <span class="card-title">默认探针部署</span>
        </div>

        <div class="deploy-row">
          <label>目标主机</label>
          <n-select
            v-model:value="targetAgent"
            :options="agentOptions"
            size="small"
            style="width: 16vw"
            placeholder="选择已安装 Agent 的主机"
          />
        </div>

        <div class="probe-list">
          <div v-for="p in defaultProbes" :key="p.name" class="probe-item">
            <div class="probe-info">
              <span class="probe-name">{{ p.name }}</span>
              <span class="probe-desc">{{ p.desc }}</span>
            </div>
            <n-switch v-model:value="p.enabled" size="small" />
          </div>
        </div>

        <n-button
          type="primary"
          size="small"
          :loading="deploying"
          @click="deployDefaults"
          style="margin-top: 1.5vh"
        >
          下发探针
        </n-button>
      </div>

      <!-- 主机 eBPF 环境 -->
      <div class="probe-card">
        <div class="card-header">
          <span class="card-title">主机 eBPF 环境</span>
        </div>
        <n-data-table
          :columns="envCols"
          :data="agentEnv"
          :bordered="false"
          size="small"
          :row-key="(r) => r.id"
        />
      </div>
    </div>
  </Layout>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { api } from '../api'
import Layout from '../layouts/MainLayout.vue'
import { useMessage } from 'naive-ui'

const message = useMessage()
const targetAgent = ref('')
const deploying = ref(false)
const agentOptions = ref([])
const agentEnv = ref([])

const defaultProbes = ref([
  { name: 'exec_monitor', desc: '进程执行监控', enabled: true },
  { name: 'bash_monitor', desc: '终端命令审计', enabled: true },
  { name: 'tcp_monitor', desc: 'TCP 连接聚合', enabled: true },
])

const envCols = [
  { title: '主机', key: 'hostname', minWidth: 120 },
  { title: '内核', key: 'kernel', minWidth: 100 },
  { title: 'BTF', key: 'btf', minWidth: 60 },
  { title: 'eBPF框架', key: 'framework', minWidth: 100 },
]

onMounted(async () => {
  const data = await api.getAgents()
  agentOptions.value = (data.agents || []).map(a => ({ label: a.hostname || a.id, value: a.id }))
  agentEnv.value = (data.agents || []).map(a => ({
    id: a.id,
    hostname: a.hostname || a.id,
    kernel: a.kernel_info?.version || '-',
    btf: a.kernel_info?.btf_enabled ? '✅' : '❌',
    framework: a.framework?.libbpf_available ? 'libbpf' : '-',
  }))
})

async function deployDefaults() {
  if (!targetAgent.value) {
    message.warning('请选择目标主机')
    return
  }
  deploying.value = true
  const token = localStorage.getItem('token')
  try {
    for (const p of defaultProbes.value) {
      await fetch('/api/probes/deploy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
        body: JSON.stringify({
          agent_id: targetAgent.value,
          probe_name: p.name,
          enabled: p.enabled,
          remove: true,
        })
      })
    }
    message.success('探针已下发')
  } catch (e) {
    message.error('下发失败')
  } finally {
    deploying.value = false
  }
}
</script>

<style scoped>
.probes-container {
  display: flex;
  flex-direction: column;
  gap: 1vh;
}

.warn-banner {
  background: rgba(240, 160, 32, 0.08);
  border: 1px solid rgba(240, 160, 32, 0.3);
  border-radius: 0.6vw;
  padding: 1vh 1vw;
  font-size: 0.85vw;
  color: #B07A10;
}

.probe-card {
  background: #FFFFFF;
  border-radius: 0.8vw;
  padding: 1.5vh 1.2vw;
  box-shadow: 0 0.3vh 1.5vh rgba(0,0,0,0.04);
}

.card-header {
  margin-bottom: 1vh;
}

.card-title {
  font-size: 1vw;
  font-weight: 600;
  color: #202124;
}

.deploy-row {
  display: flex;
  align-items: center;
  gap: 1vw;
  margin-bottom: 1.5vh;
}

.deploy-row label {
  font-size: 0.9vw;
  color: #5F6368;
  width: 6vw;
}

.probe-list {
  display: flex;
  flex-direction: column;
  gap: 0.5vh;
}

.probe-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 1vh 0.8vw;
  border-radius: 0.5vw;
  background: #F8F9FA;
}

.probe-info {
  display: flex;
  gap: 1vw;
  align-items: center;
}

.probe-name {
  font-size: 0.9vw;
  font-weight: 500;
}

.probe-desc {
  font-size: 0.8vw;
  color: #5F6368;
}
</style>

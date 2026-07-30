<template>
  <Layout>
    <n-card title="eBPF 探针部署" size="small" :bordered="false">
      <n-alert type="warning" style="margin-bottom:12px">
        <template #header>⚠️ eBPF 运行要求</template>
        内核版本 ≥ 5.8 | BTF支持 | libbpf/CO-RE | 当前仅支持Linux x86_64/ARM64
      </n-alert>

      <n-space vertical>
        <n-select v-model:value="targetAgent" :options="agentOptions" placeholder="选择目标Agent" />
        <n-input v-model:value="probeName" placeholder="探针名称" />
        <n-upload :max="1" @change="handleUpload">
          <n-button>📁 选择 .bpf.o 文件</n-button>
        </n-upload>
        <n-text v-if="fileName" type="success">✅ {{ fileName }}</n-text>
        <n-input v-model:value="probeConfig" type="textarea" :rows="6" placeholder="probe.yaml 配置" />
        <n-button type="primary" @click="deploy" :loading="deploying">🚀 部署探针</n-button>
        <n-text v-if="status">{{ status }}</n-text>
      </n-space>
    </n-card>

    <n-card title="主机 eBPF 环境" size="small" :bordered="false" style="margin-top:16px">
      <n-data-table :columns="envCols" :data="agentEnv" size="small" :bordered="false" :row-key="(row) => row.id" />
    </n-card>
  </Layout>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useMessage } from 'naive-ui'
import { api } from '../api'
import Layout from '../layouts/MainLayout.vue'

const message = useMessage()
const agentEnv = ref([]), agentOptions = ref([]), targetAgent = ref(null)
const probeName = ref(''), probeConfig = ref('name: "my_probe"\nversion: "1.0.0"\ndescription: "我的探针"\nhook_type: tracepoint\nhooks:\n  - syscalls/sys_enter_execve\nringbuf_map: events')
const probeData = ref(''), fileName = ref(''), deploying = ref(false), status = ref('')

const envCols = [
  { title: '主机名', key: 'hostname', minWidth: 130 },
  { title: '内核', key: 'kernel', minWidth: 150 },
  { title: 'BTF', key: 'btf', minWidth: 60 },
  { title: 'libbpf', key: 'libbpf', minWidth: 60 },
  { title: 'clang', key: 'clang', minWidth: 60 },
  { title: 'BCC', key: 'bcc', minWidth: 60 },
  { title: 'Go eBPF', key: 'go_ebpf', minWidth: 70 },
  { title: 'eBPF可用', key: 'ebpf_ready', minWidth: 80, render: (r) => {
    if (r.ebpf_ready === true) return '🟢'
    if (r.ebpf_ready === false) return '🔴'
    return '🟡'
  }}
]

function checkEBPFReady(a) {
  const fw = a.framework || {}
  const kn = a.kernel_info || {}
  const btf = kn.btf_enabled === true
  const libbpf = fw.libbpf_available === true
  const clang = fw.clang_available === true
  const goebpf = fw.go_ebpf_available === true
  const ok = btf && libbpf && clang && goebpf
  if (ok) return true
  if (btf || libbpf || goebpf) return null  // 不确定
  return false
}

function handleUpload({ file }) {
  const reader = new FileReader()
  reader.onload = () => {
    probeData.value = reader.result.split(',')[1]
    fileName.value = file.name
  }
  reader.readAsDataURL(file.file)
}

async function loadAgents() {
  try {
    const d = await api.getAgents()
    const list = d.agents || []
    agentOptions.value = list.map(a => ({ label: `${a.hostname} (${a.ip_addr})`, value: a.id }))
    agentEnv.value = list.map(a => ({
      id: a.id,
      hostname: a.hostname,
      kernel: a.kernel_info?.version || '-',
      btf: a.kernel_info?.btf_enabled ? '✅' : '❌',
      libbpf: a.framework?.libbpf_available ? '✅' : '❌',
      clang: a.framework?.clang_available ? '✅' : '❌',
      go_ebpf: a.framework?.go_ebpf_available ? '✅' : '❌',
      bcc: a.framework?.bcc_available ? '✅' : '❌',
      ebpf_ready: checkEBPFReady(a)
    }))
  } catch(e) {}
}

async function deploy() {
  if (!targetAgent.value || !probeName.value || !probeData.value) {
    message.warning('请填写完整信息')
    return
  }
  deploying.value = true; status.value = '⏳ 部署中...'
  try {
    const result = await api.sendCommand({
      agent_id: targetAgent.value,
      probe_name: probeName.value,
      action: 'install',
      probe_data: probeData.value,
      probe_config: probeConfig.value
    })
    status.value = result.success ? '✅ 已下发' : `❌ ${result.error}`
    if (result.success) message.success('部署指令已发送')
  } catch(e) { status.value = '❌ 请求失败' }
  deploying.value = false
}

onMounted(loadAgents)
</script>

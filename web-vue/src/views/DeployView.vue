<template>
  <div>
    <n-card title="📦 部署探针" style="margin-bottom:16px">
      <n-space vertical size="large">
        <div>
          <n-text depth="3" style="font-size:13px">目标 Agent</n-text>
          <n-select v-model:value="agentId" :options="agentOptions" placeholder="选择Agent" style="margin-top:4px" />
        </div>
        <div>
          <n-text depth="3" style="font-size:13px">探针名称</n-text>
          <n-input v-model:value="probeName" placeholder="my_probe" style="margin-top:4px" />
        </div>
        <div>
          <n-text depth="3" style="font-size:13px">上传 probe.bpf.o</n-text>
          <n-upload :max="1" @change="handleUpload" style="margin-top:4px">
            <n-button>📁 选择文件</n-button>
          </n-upload>
          <n-text v-if="fileName" type="success" style="margin-top:4px">✅ {{ fileName }}</n-text>
        </div>
        <div>
          <n-text depth="3" style="font-size:13px">probe.yaml 配置</n-text>
          <n-input v-model:value="probeConfig" type="textarea" :rows="8" style="margin-top:4px" />
        </div>
        <n-button type="primary" @click="deploy" :loading="deploying">🚀 部署</n-button>
        <n-text v-if="status">{{ status }}</n-text>
      </n-space>
    </n-card>

    <n-card title="🔍 已加载探针">
      <n-button @click="loadProbes" size="small" style="margin-bottom:12px">🔄 刷新列表</n-button>
      <n-spin :show="probesLoading">
        <div v-if="probes.length === 0 && !probesLoading">
          <n-text depth="3">暂无探针，点击刷新获取</n-text>
        </div>
        <n-table v-else :bordered="false" :single-line="false" size="small">
          <thead><tr><th>探针名</th><th>描述</th><th style="width:80px">操作</th></tr></thead>
          <tbody>
            <tr v-for="p in probes" :key="p.name">
              <td>{{ p.name }}</td>
              <td>{{ p.desc }}</td>
              <td><n-button size="tiny" type="error" @click="unloadProbe(p.name)">卸载</n-button></td>
            </tr>
          </tbody>
        </n-table>
      </n-spin>
    </n-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { api } from '../utils/api'
import { useMessage, useDialog } from 'naive-ui'

const message = useMessage()
const dialog = useDialog()

const agentId = ref(null)
const agentOptions = ref([])
const probeName = ref('')
const probeConfig = ref('name: "my_probe"\nversion: "1.0.0"\ndescription: "我的探针"\nhook_type: tracepoint\nhooks:\n  - syscalls/sys_enter_execve\nringbuf_map: events')
const probeData = ref('')
const fileName = ref('')
const deploying = ref(false)
const status = ref('')

const probes = ref([])
const probesLoading = ref(false)

onMounted(async () => {
  try {
    const d = await api.getAgents()
    agentOptions.value = (d.agents || []).map(a => ({ label: a.hostname + ' (' + a.id + ')', value: a.id }))
  } catch(e) {}
})

function handleUpload({ file }) {
  const reader = new FileReader()
  reader.onload = () => {
    probeData.value = reader.result.split(',')[1]
    fileName.value = file.name
  }
  reader.readAsDataURL(file.file)
}

async function deploy() {
  if (!agentId.value || !probeName.value || !probeData.value) {
    message.warning('请填写完整信息')
    return
  }
  deploying.value = true; status.value = '⏳ 部署中...'
  try {
    const result = await api.sendCommand({
      agent_id: agentId.value, probe_name: probeName.value,
      action: 'install', probe_data: probeData.value, probe_config: probeConfig.value
    })
    status.value = result.success ? '✅ 指令已下发' : '❌ ' + result.error
        if (result.success) { message.success("部署指令已发送"); probes.value.push({ name: probeName.value, desc: "新部署" }) }
		probes.value.push({ name: probeName.value, desc: "新部署" })
  } catch(e) { status.value = '❌ 请求失败' }
  deploying.value = false
}

async function loadProbes() {
  probesLoading.value = true
  try {
    const d = await api.getEvents()
    const now = Math.floor(Date.now()/1000)
    const recent = (d.events || []).filter(e => now - e.timestamp < 30)
    const names = [...new Set(recent.map(e => e.probe_name))]
    probes.value = names.map(n => ({ name: n, desc: "外部插件" }))
  } catch(e) {}
  probesLoading.value = false
}

async function unloadProbe(name) {
  dialog.warning({
    title: '确认卸载',
    content: '确定要卸载探针 "' + name + '" 吗？',
    positiveText: '确定',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        const result = await api.sendCommand({
          agent_id: agentId.value || (agentOptions.value[0]?.value || ''),
          probe_name: name,
          action: 'unload'
        })
        if (result.success) {
          message.success('卸载指令已发送')
          probes.value = probes.value.filter(p => p.name !== name)
        } else { message.error(result.error) }
      } catch(e) { message.error('请求失败') }
    }
  })
}
</script>

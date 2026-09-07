<template>
  <Layout>
    <n-card title="Agent 安装命令生成器" size="small" :bordered="false">
      <n-form label-placement="left" label-width="120">
        <n-form-item label="操作系统">
          <n-select v-model:value="os" :options="osOptions" style="width:200px" />
        </n-form-item>
        <n-form-item label="通信协议">
          <n-select v-model:value="proto" :options="protoOptions" style="width:200px" />
        </n-form-item>
        <n-form-item label="连接方式">
          <n-select v-model:value="connType" :options="connOptions" style="width:200px" />
        </n-form-item>
        <n-form-item label="所属业务组">
          <n-input v-model:value="group" placeholder="生产/测试/开发" style="width:200px" />
        </n-form-item>
        <n-form-item label="运行权限">
          <n-radio-group v-model:value="runMode">
            <n-radio value="root">root</n-radio>
            <n-radio value="nobody">nobody</n-radio>
            <n-radio value="custom">指定用户</n-radio>
          </n-radio-group>
        </n-form-item>
        <n-form-item v-if="runMode==='custom'" label="运行账号">
          <n-input v-model:value="runUser" placeholder="用户名" style="width:200px" />
        </n-form-item>
        <n-form-item label="Server地址">
          <n-input v-model:value="serverAddr" placeholder="192.168.1.100" style="width:300px" />
        </n-form-item>
      </n-form>

      <n-divider />

      <n-text strong>安装命令：</n-text>
      <n-code :code="installCmd" language="bash" style="margin-top:8px" />
      <n-button @click="copyCmd" type="primary" size="small" style="margin-top:12px">📋 复制命令</n-button>
    </n-card>
  </Layout>
</template>

<script setup>
import { ref, computed } from 'vue'
import { useMessage } from 'naive-ui'
import Layout from '../layouts/MainLayout.vue'

const message = useMessage()

const os = ref('linux')
const proto = ref('ipv4')
const connType = ref('direct')
const group = ref('默认组')
const runMode = ref('root')
const runUser = ref('')
const serverAddr = ref(window.location.hostname || '192.168.1.100')

const osOptions = [
  { label: 'Linux (x86_64)', value: 'linux-amd64' },
  { label: 'Linux (ARM64)', value: 'linux-arm64' },
]
const protoOptions = [
  { label: 'IPv4', value: 'ipv4' },
  { label: 'IPv6', value: 'ipv6' },
]
const connOptions = [
  { label: '直连', value: 'direct' },
  { label: '代理', value: 'proxy' },
  { label: 'NAT', value: 'nat' },
]

const installCmd = computed(() => {
  const arch = os.value === 'linux-amd64' ? 'amd64' : 'arm64'
  const runAs = runMode.value === 'custom' ? runUser.value : runMode.value

  return `# eBPF Sentinel Agent 安装命令
# 业务组: ${group.value} | 连接: ${connType.value} | 运行: ${runAs}

curl -fsSL http://${serverAddr.value}:8080/install.sh | bash -s -- \\
  --os ${os.value} \\
  --group "${group.value}" \\
  --run-as ${runAs} \\
  --server ${serverAddr.value}:50051`
})

function copyCmd() {
  navigator.clipboard.writeText(installCmd.value)
  message.success('已复制')
}
</script>

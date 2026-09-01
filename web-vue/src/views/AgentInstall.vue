<template>
  <Layout>
    <div class="install-container">
      <!-- 左：自动部署 -->
      <div class="install-card">
        <div class="card-header">
          <span class="card-title">自动部署</span>
        </div>

        <div class="deploy-form">
          <div class="form-row">
            <label>操作系统</label>
            <n-select v-model:value="os" :options="osOptions" size="small" style="width: 12vw" />
          </div>

          <div class="form-row">
            <label>所属分组</label>
            <n-input v-model:value="group" size="small" style="width: 12vw" placeholder="留空则默认未分组" />
          </div>

          <div class="cmd-preview">
            <div class="cmd-header">
              <span>一键安装命令</span>
              <n-button size="tiny" @click="copyCmd">复制</n-button>
            </div>
            <pre class="cmd-box">{{ generatedCmd }}</pre>
          </div>

        </div>
      </div>

      <!-- 右：手动部署 + 程序安装 -->
      <div class="install-card">
        <div class="card-header">
          <span class="card-title">手动部署</span>
        </div>

        <div class="manual-guide">
          <div class="guide-step">
            <span class="step-num">1</span>
            <span>下载对应架构的 Agent 二进制</span>
            <n-button size="tiny" @click="downloadAgent">下载 {{ os }}</n-button>
          </div>
          <div class="guide-step">
            <span class="step-num">2</span>
            <span>创建配置文件 agent.toml</span>
          </div>
          <pre class="config-preview">[agent]
server = "{{ serverAddr }}:50051"</pre>
          <div class="guide-step">
            <span class="step-num">3</span>
            <span>运行 Agent</span>
          </div>
          <pre class="config-preview">./agent --config agent.toml</pre>
          <div class="guide-step">
            <span class="step-num">4</span>
            <span>或使用 systemd 托管</span>
          </div>
          <pre class="config-preview">[Unit]
Description=eBPF Sentinel Agent
After=network.target

[Service]
ExecStart=/opt/sentinel/agent --config /opt/sentinel/agent.toml
Restart=always

[Install]
WantedBy=multi-user.target</pre>
        </div>
      </div>
    </div>
  </Layout>
</template>

<script setup>
import { ref, computed } from 'vue'
import Layout from '../layouts/MainLayout.vue'

const os = ref('linux-amd64')
const group = ref('未分组')
const serverAddr = ref(window.location.hostname)

const osOptions = [
  { label: 'Linux x86_64', value: 'linux-amd64' },
  { label: 'Linux ARM64', value: 'linux-arm64' },
]

const generatedCmd = computed(() => {
  return `curl -s http://${serverAddr.value}:8080/bin/agent-${os.value} -o /tmp/agent && chmod +x /tmp/agent && /tmp/agent --config <(echo '[agent]\\nserver="${serverAddr.value}:50051"')`
})

function copyCmd() {
  navigator.clipboard.writeText(generatedCmd.value)
}

function downloadAgent() {
  window.open(`http://${serverAddr.value}:8080/bin/agent-${os.value}`, '_blank')
}
</script>

<style scoped>
.install-container {
  display: flex;
  gap: 1vw;
  height: 100%;
}

.install-card {
  flex: 1;
  background: #FFFFFF;
  border-radius: 0.8vw;
  padding: 1.5vh 1.2vw;
  box-shadow: 0 0.3vh 1.5vh rgba(0,0,0,0.04);
  display: flex;
  flex-direction: column;
}

.card-header {
  margin-bottom: 1.5vh;
}

.card-title {
  font-size: 1vw;
  font-weight: 600;
  color: #202124;
}

.deploy-form {
  display: flex;
  flex-direction: column;
  gap: 1.2vh;
}

.form-row {
  display: flex;
  align-items: center;
  gap: 1vw;
}

.form-row label {
  font-size: 0.9vw;
  color: #5F6368;
  width: 6vw;
}

.cmd-preview {
  background: #F8F9FA;
  border-radius: 0.6vw;
  padding: 1vh 1vw;
}

.cmd-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5vh;
  font-size: 0.85vw;
  color: #5F6368;
}

.cmd-box {
  font-size: 0.8vw;
  color: #202124;
  white-space: pre-wrap;
  word-break: break-all;
}

.manual-guide {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 0.8vh;
  overflow-y: auto;
}

.guide-step {
  display: flex;
  align-items: center;
  gap: 0.6vw;
  font-size: 0.85vw;
  color: #5F6368;
}

.step-num {
  width: 1.5vw;
  height: 1.5vw;
  background: #1A73E8;
  color: #FFFFFF;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.75vw;
  flex-shrink: 0;
}

.config-preview {
  background: #F8F9FA;
  border-radius: 0.5vw;
  padding: 1vh 1vw;
  font-size: 0.8vw;
  color: #202124;
  white-space: pre-wrap;
}
</style>

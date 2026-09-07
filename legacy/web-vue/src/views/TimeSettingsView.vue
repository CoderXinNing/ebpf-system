<template>
  <Layout>
    <div class="settings-container">
      <div class="settings-card">
        <div class="card-header">
          <span class="card-title">系统时间设置</span>
        </div>

        <div class="settings-form">
          <div class="setting-row">
            <label>当前时间</label>
            <span class="time-display">{{ currentTime }}</span>
          </div>

          <div class="setting-row">
            <label>手动设置</label>
            <n-date-picker
              v-model:value="manualDatetime"
              type="datetime"
              size="small"
              style="width: 16vw"
            />
            <n-button size="small" @click="setTime">设置</n-button>
          </div>

          <div class="setting-row">
            <label>NTP 服务器</label>
            <n-input v-model:value="ntpServer" size="small" style="width: 14vw" placeholder="ntp.aliyun.com" />
            <n-button size="small" @click="syncNTP">立即同步</n-button>
          </div>
        </div>
      </div>
    </div>
  </Layout>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import Layout from '../layouts/MainLayout.vue'
import { useMessage } from 'naive-ui'

const message = useMessage()
const currentTime = ref('')
const manualDatetime = ref(Date.now())
const ntpServer = ref('ntp.aliyun.com')
let timer

function updateTime() {
  currentTime.value = new Date().toLocaleString()
}

async function setTime() {
  if (!manualDatetime.value) return
  const d = new Date(manualDatetime.value)
  const pad = (n) => String(n).padStart(2, '0')
  const datetime = `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  
  const token = localStorage.getItem('token')
  const resp = await fetch('/api/system/time', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
    body: JSON.stringify({ datetime })
  })
  const data = await resp.json()
  if (data.success) message.success('时间已设置')
  else message.error(data.error || '设置失败')
  updateTime()
}

async function syncNTP() {
  const token = localStorage.getItem('token')
  const resp = await fetch('/api/system/ntp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
    body: JSON.stringify({ server: ntpServer.value })
  })
  const data = await resp.json()
  if (data.success) message.success('NTP 同步成功')
  else message.error(data.error || '同步失败')
  updateTime()
}

onMounted(() => {
  updateTime()
  timer = setInterval(updateTime, 1000)
})
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.settings-container { display: flex; justify-content: center; padding-top: 3vh; }
.settings-card { background: #FFFFFF; border-radius: 0.8vw; padding: 2vh 2vw; box-shadow: 0 0.3vh 1.5vh rgba(0,0,0,0.04); width: 40vw; }
.card-header { margin-bottom: 2vh; }
.card-title { font-size: 1vw; font-weight: 600; color: #202124; }
.settings-form { display: flex; flex-direction: column; gap: 1.5vh; }
.setting-row { display: flex; align-items: center; gap: 0.8vw; }
.setting-row label { font-size: 0.9vw; color: #5F6368; width: 8vw; }
.time-display { font-size: 1vw; font-weight: 500; color: #202124; }
</style>

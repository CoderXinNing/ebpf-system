<template>
  <Layout>
    <div class="settings-container">
      <div class="settings-card">
        <div class="card-header">
          <span class="card-title">日志管理</span>
        </div>

        <div class="settings-form">
          <div class="setting-row">
            <label>事件流保存天数</label>
            <n-input-number v-model:value="eventDays" :min="1" :max="365" size="small" style="width: 8vw" />
            <span class="unit">天</span>
          </div>
          <div class="setting-row">
            <label>告警保存天数</label>
            <n-input-number v-model:value="alertDays" :min="1" :max="365" size="small" style="width: 8vw" />
            <span class="unit">天</span>
          </div>
          <div class="setting-row">
            <label>审计日志保存天数</label>
            <n-input-number v-model:value="auditDays" :min="1" :max="365" size="small" style="width: 8vw" />
            <span class="unit">天</span>
          </div>

          <n-button type="primary" size="small" @click="save">保存</n-button>
        </div>
      </div>
    </div>
  </Layout>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import Layout from '../layouts/MainLayout.vue'
import { useMessage } from 'naive-ui'

const message = useMessage()
const eventDays = ref(30)
const alertDays = ref(90)
const auditDays = ref(180)

async function load() {
  const token = localStorage.getItem('token')
  const resp = await fetch('/api/log-settings', { headers: { 'Authorization': 'Bearer ' + token } })
  const data = await resp.json()
  if (data.event_days) eventDays.value = parseInt(data.event_days)
  if (data.alert_days) alertDays.value = parseInt(data.alert_days)
  if (data.audit_days) auditDays.value = parseInt(data.audit_days)
}

async function save() {
  const token = localStorage.getItem('token')
  await fetch('/api/log-settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
    body: JSON.stringify({
      event_days: String(eventDays.value),
      alert_days: String(alertDays.value),
      audit_days: String(auditDays.value),
    })
  })
  message.success('已保存')
}

onMounted(load)
</script>

<style scoped>
.settings-container {
  display: flex;
  justify-content: center;
  padding-top: 3vh;
}

.settings-card {
  background: #FFFFFF;
  border-radius: 0.8vw;
  padding: 2vh 2vw;
  box-shadow: 0 0.3vh 1.5vh rgba(0,0,0,0.04);
  width: 36vw;
}

.card-header {
  margin-bottom: 2vh;
}

.card-title {
  font-size: 1vw;
  font-weight: 600;
  color: #202124;
}

.settings-form {
  display: flex;
  flex-direction: column;
  gap: 1.5vh;
}

.setting-row {
  display: flex;
  align-items: center;
  gap: 0.8vw;
}

.setting-row label {
  font-size: 0.9vw;
  color: #5F6368;
  width: 12vw;
}

.unit {
  font-size: 0.85vw;
  color: #5F6368;
}
</style>

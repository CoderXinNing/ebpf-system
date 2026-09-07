<template>
  <Layout>
    <div class="settings-container">
      <div class="settings-card">
        <div class="card-header">
          <span class="card-title">个性化设置</span>
        </div>

        <div class="settings-form">
          <div class="setting-row">
            <label>平台名称</label>
            <n-input v-model:value="platformName" size="small" style="width: 16vw" />
          </div>
          <div class="setting-row">
            <label>网页标题</label>
            <n-input v-model:value="pageTitle" size="small" style="width: 16vw" />
          </div>
          <div class="setting-row">
            <label>平台 Logo</label>
            <n-input v-model:value="logoUrl" size="small" style="width: 16vw" placeholder="/logo.png" />
          </div>

          <n-button type="primary" size="small" @click="save">保存</n-button>
        </div>
      </div>
    </div>
  </Layout>
</template>

<script setup>
import { ref } from 'vue'
import Layout from '../layouts/MainLayout.vue'
import { useMessage } from 'naive-ui'

const message = useMessage()
const platformName = ref('eBPF Sentinel')
const pageTitle = ref('主机安全监控平台')
const logoUrl = ref('')

async function save() {
  const token = localStorage.getItem('token')
  await fetch('/api/log-settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
    body: JSON.stringify({
      platform_name: platformName.value,
      page_title: pageTitle.value,
      logo_url: logoUrl.value,
    })
  })
  message.success('已保存')
  document.title = pageTitle.value
}
</script>

<style scoped>
.settings-container { display: flex; justify-content: center; padding-top: 3vh; }
.settings-card { background: #FFFFFF; border-radius: 0.8vw; padding: 2vh 2vw; box-shadow: 0 0.3vh 1.5vh rgba(0,0,0,0.04); width: 36vw; }
.card-header { margin-bottom: 2vh; }
.card-title { font-size: 1vw; font-weight: 600; color: #202124; }
.settings-form { display: flex; flex-direction: column; gap: 1.5vh; }
.setting-row { display: flex; align-items: center; gap: 0.8vw; }
.setting-row label { font-size: 0.9vw; color: #5F6368; width: 10vw; }
</style>

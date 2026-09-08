<template>
  <div class="login-container">
    <div class="login-bg"></div>
    <n-card class="login-card" :bordered="false">
      <div class="login-header">
        <div class="logo">⭐</div>
        <h1 class="title">AsterTrack</h1>
        <p class="subtitle">星轨安全感知平台</p>
      </div>
      <n-space vertical :size="16">
        <n-input v-model:value="username" placeholder="用户名" size="large" />
        <n-input v-model:value="password" type="password" placeholder="密码" size="large" @keyup.enter="handleLogin" />
        <n-button type="primary" block size="large" :loading="loading" @click="handleLogin">
          登 录
        </n-button>
        <n-alert v-if="error" type="error" :show-icon="true">
          {{ error }}
        </n-alert>
      </n-space>
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { NCard, NSpace, NInput, NButton, NAlert } from 'naive-ui'
import { login } from '../api/auth'

const username = ref('')
const password = ref('')
const loading = ref(false)
const error = ref('')
const router = useRouter()

async function handleLogin() {
  if (!username.value || !password.value) {
    error.value = '请输入用户名和密码'
    return
  }

  loading.value = true
  error.value = ''

  try {
    const resp = await login(username.value, password.value)
    localStorage.setItem('token', resp.token)
    localStorage.setItem('user', JSON.stringify(resp.user))
    router.push('/dashboard')
  } catch (err: any) {
    error.value = err.response?.data?.error || '登录失败'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-container {
  position: relative;
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh;
  overflow: hidden;
  background: #0f172a;
}

.login-bg {
  position: absolute;
  inset: 0;
  background: 
    radial-gradient(circle at 30% 50%, rgba(66, 153, 225, 0.15), transparent 50%),
    radial-gradient(circle at 70% 50%, rgba(72, 187, 120, 0.12), transparent 50%),
    radial-gradient(circle at 50% 80%, rgba(237, 137, 54, 0.1), transparent 40%);
}

.login-card {
  position: relative;
  width: 400px;
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(10px);
  border-radius: 16px;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
}

.login-header {
  text-align: center;
  margin-bottom: 24px;
}

.logo {
  font-size: 48px;
  margin-bottom: 8px;
}

.title {
  font-size: 28px;
  font-weight: 700;
  margin: 0;
  color: #1a202c;
}

.subtitle {
  font-size: 14px;
  color: #64748b;
  margin-top: 4px;
}
</style>

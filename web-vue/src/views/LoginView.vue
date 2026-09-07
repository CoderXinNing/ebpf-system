<template>
  <div class="login-container">
    <n-card title="AsterTrack 登录" style="width: 400px">
      <n-space vertical>
        <n-input v-model:value="username" placeholder="用户名" />
        <n-input v-model:value="password" type="password" placeholder="密码" @keyup.enter="handleLogin" />
        <n-button type="primary" block :loading="loading" @click="handleLogin">
          登录
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
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh;
}
</style>

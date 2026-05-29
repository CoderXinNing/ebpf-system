<template>
  <div class="login-wrapper">
    <n-card title="🛡️ eBPF Sentinel" style="width:380px">
      <n-form>
        <n-form-item label="用户名">
          <n-input v-model:value="username" placeholder="admin" />
        </n-form-item>
        <n-form-item label="密码">
          <n-input v-model:value="password" type="password" placeholder="admin123" @keyup.enter="login" />
        </n-form-item>
        <n-button type="primary" block @click="login" :loading="loading">登 录</n-button>
      </n-form>
      <p v-if="error" style="color:#e04a5a;text-align:center;margin-top:12px">{{ error }}</p>
    </n-card>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import { api } from '../utils/api'

const router = useRouter()
const auth = useAuthStore()
const username = ref('admin')
const password = ref('admin123')
const loading = ref(false)
const error = ref('')

async function login() {
  loading.value = true; error.value = ''
  try {
    const data = await api.login(username.value, password.value)
    if (data.token) {
      auth.setAuth(data.token, data.user)
      router.push('/')
    } else {
      error.value = data.error || '登录失败'
    }
  } catch(e) {
    error.value = '连接失败'
  }
  loading.value = false
}
</script>

<style scoped>
.login-wrapper { height: 100vh; display: flex; align-items: center; justify-content: center; background: #101014; }
</style>

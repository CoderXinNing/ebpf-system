<template>
  <div class="login-page">
    <div class="login-left">
      <div class="login-left-content">
        <h1>eBPF Sentinel</h1>
        <p>主机安全资产管理平台</p>
      </div>
    </div>
    <div class="login-right">
      <div class="login-card">
        <h2>欢迎登录</h2>
        <p style="color:#86909c;margin-bottom:24px">请输入账号密码</p>
        <n-input v-model:value="u" placeholder="用户名" size="large" style="margin-bottom:16px" />
        <n-input v-model:value="p" type="password" placeholder="密码" size="large" @keyup.enter="login" />
        <n-button type="primary" block size="large" @click="login" :loading="loading" style="margin-top:24px">登 录</n-button>
        <p v-if="err" style="color:#e04a5a;text-align:center;margin-top:12px">{{ err }}</p>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api'

const router = useRouter()
const u = ref('admin'), p = ref('admin123'), loading = ref(false), err = ref('')

async function login() {
  loading.value = true; err.value = ''
  try {
    const d = await api.login(u.value, p.value)
    if (d.token) {
      localStorage.setItem('token', d.token)
      localStorage.setItem('user', JSON.stringify(d.user))
      router.push('/')
    } else err.value = d.error || '登录失败'
  } catch (e) { err.value = '连接失败' }
  loading.value = false
}
</script>

<style scoped>
.login-page { display: flex; height: 100vh; }
.login-left {
  flex: 1; background: linear-gradient(135deg, #001529 0%, #003a70 50%, #1e6fff 100%);
  display: flex; align-items: center; justify-content: center;
}
.login-left-content { text-align: center; color: #fff; padding: 40px; }
.login-left-content h1 { font-size: clamp(28px, 4vw, 48px); font-weight: 700; margin-bottom: 8px; }
.login-left-content p { font-size: clamp(14px, 1.5vw, 18px); opacity: 0.8; }
.login-right {
  width: 480px; display: flex; align-items: center; justify-content: center; background: #fff; padding: 40px;
}
.login-card { width: 100%; max-width: 360px; }
.login-card h2 { font-size: 24px; font-weight: 600; color: #1d2129; margin-bottom: 4px; }
@media (max-width: 768px) {
  .login-left { display: none; }
  .login-right { width: 100%; }
}
</style>

<template>
  <div class="login">
    <n-card style="width:380px">
      <h2 style="color:#18c08c;text-align:center">eBPF Sentinel</h2>
      <n-input v-model:value="u" placeholder="用户名" style="margin:12px 0" />
      <n-input v-model:value="p" type="password" placeholder="密码" @keyup.enter="login" />
      <n-button type="primary" block @click="login" :loading="loading" style="margin-top:16px">登录</n-button>
      <p v-if="err" style="color:#e04a5a;text-align:center;margin-top:8px">{{ err }}</p>
    </n-card>
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
.login { height: 100vh; display: flex; align-items: center; justify-content: center; }
</style>

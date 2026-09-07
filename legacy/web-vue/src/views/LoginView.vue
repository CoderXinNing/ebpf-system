<template>
  <div class="login-page">
    <div class="login-card">
      <div class="card-left">
        <div class="logo-placeholder">🐝</div>
        <h1 class="login-title">登录</h1>
        <p class="login-subtitle">使用您的账户继续</p>
      </div>

      <div class="card-right">
        <input v-model="username" type="text" placeholder="用户名" class="login-input" @keyup.enter="handleLogin" />
        <input v-model="password" type="password" placeholder="密码" class="login-input" @keyup.enter="handleLogin" />
        <a href="#" class="forgot-link">忘记密码</a>
        <button class="login-btn" :disabled="loading" @click="handleLogin">
          {{ loading ? '登录中...' : '登录' }}
        </button>
        <p v-if="error" class="error-text">{{ error }}</p>
      </div>
    </div>

    <div class="lang-select">
      <select v-model="lang" class="lang-dropdown">
        <option value="zh-CN">简体中文</option>
        <option value="en">English</option>
      </select>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const username = ref('admin')
const password = ref('admin123')
const loading = ref(false)
const error = ref('')
const lang = ref('zh-CN')

async function handleLogin() {
  if (!username.value || !password.value) {
    error.value = '请输入用户名和密码'
    return
  }
  loading.value = true
  error.value = ''
  try {
    const resp = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username.value, password: password.value })
    })
    const data = await resp.json()
    if (resp.ok && data.token) {
      localStorage.setItem('token', data.token)
      localStorage.setItem('user', JSON.stringify(data.user || { username: username.value }))
      router.push('/')
    } else {
      error.value = data.error || '登录失败'
    }
  } catch (e) {
    error.value = '无法连接服务器'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
* {
  font-family: Arial, -apple-system, 'Segoe UI', Roboto, sans-serif;
}

.login-page {
  position: relative;
  width: 100vw;
  height: 100vh;
  background: #E8EDF4;
  display: flex;
  align-items: center;
  justify-content: center;
}

.login-card {
  display: flex;
  width: 56vw;
  min-width: 360px;
  max-width: 720px;
  aspect-ratio: 16 / 9;
  background: #FFFFFF;
  border-radius: 2vw;
  box-shadow: 0 0.5vh 3vh rgba(0,0,0,0.08);
  overflow: hidden;
}

.card-left {
  flex: 1;
  padding: 8% 6%;
  text-align: center;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}

.logo-placeholder {
  font-size: 6vw;
  margin-bottom: 1.5vh;
}

.login-title {
  font-size: 1.8vw;
  font-weight: 700;
  color: #202124;
  margin: 0 0 0.8vh;
}

.login-subtitle {
  font-size: 0.95vw;
  color: #5F6368;
  margin: 0;
}

.card-right {
  flex: 1;
  padding: 8% 6%;
  display: flex;
  flex-direction: column;
  justify-content: center;
  gap: 2vh;
}

.login-input {
  width: 100%;
  height: 5.5vh;
  min-height: 40px;
  padding: 0 1vw;
  border: 1px solid #DADCE0;
  border-radius: 0.6vw;
  font-size: 1vw;
  color: #202124;
  outline: none;
  box-sizing: border-box;
  transition: border 0.2s, box-shadow 0.2s;
}

.login-input:focus {
  border-color: #1A73E8;
  box-shadow: 0 0 0 2px rgba(26,115,232,0.15);
}

.forgot-link {
  font-size: 0.85vw;
  color: #1A73E8;
  text-decoration: none;
  text-align: right;
}

.forgot-link:hover {
  text-decoration: underline;
}

.login-btn {
  height: 5vh;
  min-height: 40px;
  background: #1A73E8;
  color: #FFFFFF;
  border: none;
  border-radius: 0.8vw;
  font-size: 1vw;
  font-weight: 500;
  cursor: pointer;
  transition: background 0.2s;
}

.login-btn:hover {
  background: #1765CC;
}

.login-btn:disabled {
  background: #A8C7FA;
  cursor: not-allowed;
}

.error-text {
  color: #D93025;
  font-size: 0.85vw;
  margin: 0;
  text-align: center;
}

.lang-select {
  position: absolute;
  bottom: 2vh;
  left: 2vw;
}

.lang-dropdown {
  border: none;
  background: transparent;
  color: #5F6368;
  font-size: 0.9vw;
  cursor: pointer;
  outline: none;
}

@media (max-width: 768px) {
  .login-card {
    width: 90vw;
    flex-direction: column;
    aspect-ratio: auto;
  }
  .login-title { font-size: 6vw; }
  .login-subtitle { font-size: 3.5vw; }
  .login-input { font-size: 4vw; height: 6vh; }
  .login-btn { font-size: 4vw; height: 6vh; }
  .forgot-link { font-size: 3vw; }
  .logo-placeholder { font-size: 15vw; }
}
</style>

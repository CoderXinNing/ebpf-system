<template>
  <div class="login-container">
    <n-card title="AsterTrack 登录" style="width: 400px">
      <n-space vertical>
        <n-input v-model:value="username" placeholder="用户名" />
        <n-input v-model:value="password" type="password" placeholder="密码" />
        <n-button type="primary" block @click="handleLogin">登录</n-button>
      </n-space>
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { NCard, NSpace, NInput, NButton } from 'naive-ui'

const username = ref('')
const password = ref('')

function handleLogin() {
  // TODO: 调用登录 API
  localStorage.setItem('token', 'test-token')
  window.location.href = '/star'
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

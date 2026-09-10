<template>
  <div class="not-found-container">
    <n-card :bordered="false" class="not-found-card">
      <div class="content">
        <div class="code">404</div>
        <div class="message">页面不存在</div>
        <p class="description">你访问的页面可能已被移除或不存在</p>
        <n-button type="primary" @click="goHome">返回仪表盘</n-button>
      </div>
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { NCard, NButton } from 'naive-ui'
import { useRouter } from 'vue-router'

const router = useRouter()

function goHome() {
  router.push('/dashboard')
}
</script>

<style scoped>
.not-found-container {
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh;
  background: linear-gradient(135deg, #f5f7fa 0%, #e8eef5 100%);
}

.not-found-card {
  width: 400px;
  text-align: center;
}

.content {
  padding: 40px 0;
}

.code {
  font-size: 80px;
  font-weight: 800;
  color: #e2e8f0;
}

.message {
  font-size: 24px;
  font-weight: 600;
  margin-top: 8px;
  color: #1a202c;
}

.description {
  font-size: 14px;
  color: #64748b;
  margin: 12px 0 24px;
}
</style>

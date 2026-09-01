<template>
  <Layout>
    <div class="about-container">
      <div class="about-card">
        <div class="logo-area">
          <span style="font-size: 3vw">🐝</span>
        </div>
        <h1 class="system-name">eBPF Sentinel</h1>
        <p class="system-desc">基于 eBPF 的主机安全监控平台</p>

        <div class="info-list">
          <div class="info-row">
            <span class="info-label">版本</span>
            <span class="info-value">v1.0.0-beta</span>
          </div>
          <div class="info-row">
            <span class="info-label">状态</span>
            <span class="info-value">长期 Beta，持续演进</span>
          </div>
          <div class="info-row">
            <span class="info-label">技术栈</span>
            <span class="info-value">Go + eBPF + Vue 3</span>
          </div>
          <div class="info-row">
            <span class="info-label">架构</span>
            <span class="info-value">四层降级 + 双通道告警</span>
          </div>
          <div class="info-row">
            <span class="info-label">仓库</span>
            <span class="info-value">github.com/CoderXinNing/ebpf-system</span>
          </div>
        </div>
      </div>
    </div>
  </Layout>
</template>

<script setup>
import Layout from '../layouts/MainLayout.vue'
</script>

<style scoped>
.about-container {
  display: flex;
  justify-content: center;
  padding-top: 5vh;
}

.about-card {
  background: #FFFFFF;
  border-radius: 0.8vw;
  padding: 3vh 3vw;
  text-align: center;
  box-shadow: 0 0.3vh 1.5vh rgba(0,0,0,0.04);
  width: 40vw;
}

.logo-area {
  margin-bottom: 1.5vh;
}

.system-name {
  font-size: 1.5vw;
  font-weight: 600;
  color: #202124;
  margin: 0 0 0.5vh;
}

.system-desc {
  font-size: 0.9vw;
  color: #5F6368;
  margin: 0 0 2vh;
}

.info-list {
  display: flex;
  flex-direction: column;
  gap: 0.8vh;
  text-align: left;
}

.info-row {
  display: flex;
  justify-content: space-between;
  padding: 0.8vh 0;
  border-bottom: 1px solid #F1F3F4;
  font-size: 0.9vw;
}

.info-label {
  color: #5F6368;
}

.info-value {
  color: #202124;
  font-weight: 500;
}
</style>

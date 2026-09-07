<template>
  <n-config-provider :theme-overrides="theme">
    <n-message-provider>
      <n-notification-provider>
        <n-dialog-provider>
          <router-view />
        </n-dialog-provider>
      </n-notification-provider>
    </n-message-provider>
  </n-config-provider>
</template>

<script setup>
const theme = {
  common: {
    bodyColor: '#E8EDF4',
    cardColor: '#FFFFFF',
    primaryColor: '#1A73E8',
    primaryColorHover: '#1765CC',
    borderRadius: '0.6vw',
    fontSizeSmall: '0.85vw',
    fontSizeMedium: '0.95vw',
    fontSizeLarge: '1.1vw',
    textColor1: '#202124',
    textColor2: '#5F6368',
    textColor3: '#9AA0A6',
  },
  Card: {
    borderRadius: '0.8vw',
    paddingMedium: '1.5vh 1.2vw',
  },
  DataTable: {
    thPaddingSmall: '1vh 0.8vw',
    tdPaddingSmall: '1vh 0.8vw',
    borderRadius: '0.6vw',
  },
  Button: {
    borderRadiusMedium: '0.5vw',
    heightMedium: '4vh',
  },
  Input: {
    borderRadius: '0.5vw',
    heightMedium: '4vh',
  },
}
</script>

<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

html, body {
  width: 100vw;
  height: 100vh;
  overflow: hidden;
  background: #E8EDF4;
  font-family: Arial, -apple-system, 'Segoe UI', Roboto, sans-serif;
  color: #202124;
}

#app {
  width: 100vw;
  height: 100vh;
}

/* 全局卡片 */
.n-card {
  border-radius: 0.8vw !important;
  box-shadow: 0 0.3vh 1.5vh rgba(0,0,0,0.04) !important;
}

/* 全局表格 */
.n-data-table {
  border-radius: 0.6vw;
}

/* 全局按钮 */
.n-button {
  border-radius: 0.5vw !important;
  transition: all 0.25s !important;
}

/* 全局卡片间距 */
.n-card {
  margin-bottom: 1vh;
}

/* 全局表格容器 */
.n-card .n-data-table {
  font-size: 0.85vw;
}

/* 全局标签页 */
.n-tabs .n-tabs-tab {
  font-size: 0.9vw;
  padding: 0.8vh 1vw;
}

/* 全局描述列表 */
.n-descriptions {
  font-size: 0.85vw;
}

.n-button:hover {
  transform: translateY(-0.1vh);
  box-shadow: 0 0.4vh 1.2vh rgba(26,115,232,0.2);
}
</style>

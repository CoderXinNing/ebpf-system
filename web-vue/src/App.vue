<template>
  <n-config-provider :theme="darkTheme" :theme-overrides="theme">
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
import { darkTheme } from 'naive-ui'
const theme = {
  common: {
    bodyColor: '#f0f2f5',
    cardColor: '#ffffff',
    inputColor: '#ffffff',
    borderColor: '#e4e7ed',
    primaryColor: '#1e6fff',
    primaryColorHover: '#3d85ff',
    borderRadius: '4px',
    fontSizeSmall: '13px',
    fontSizeMedium: '14px',
    textColor1: '#1d2129',
    textColor2: '#4e5969',
    textColor3: '#86909c',
    modalColor: '#ffffff',
  },
  Card: { paddingMedium: '20px', borderRadius: '8px' },
  DataTable: { thPaddingSmall: '10px 16px', tdPaddingSmall: '10px 16px' },
  Menu: { itemHeight: '44px', borderRadius: '6px' },
  Layout: { siderColor: '#001529' },
  Modal: { borderRadius: '12px' },
  Dialog: { borderRadius: '12px', titleFontSize: '18px', titleFontWeight: '600' },
  Button: { borderRadiusMedium: '6px' }
}
</script>

<style>
html, body { margin: 0; padding: 0; height: 100%; overflow: hidden; background: #f0f2f5; font-family: -apple-system, 'Segoe UI', 'PingFang SC', sans-serif; color: #1d2129; }
a { color: #1e6fff; text-decoration: none; }
.n-modal-mask { background: rgba(0,0,0,.3) !important; }
.n-modal .n-card { border-radius: 12px; box-shadow: 0 8px 40px rgba(0,0,0,.08); background: #fff !important; color: #1d2129 !important; }
.n-modal .n-card > .n-card-header { font-size: 18px; font-weight: 600; color: #1d2129 !important; border-bottom: 1px solid #f0f2f5; }
</style>

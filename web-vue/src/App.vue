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
    bodyColor: '#0d1117',
    cardColor: '#161b22',
    inputColor: '#0d1117',
    borderColor: '#30363d',
    primaryColor: '#58a6ff',
    primaryColorHover: '#79c0ff',
    borderRadius: '6px',
    fontSizeSmall: '13px',
    fontSizeMedium: '14px',
  },
  Card: { paddingMedium: '16px' },
  DataTable: { thPaddingSmall: '8px 12px', tdPaddingSmall: '6px 12px' },
  Menu: { itemHeight: '36px' }
}
</script>

<style>
body { margin: 0; background: #0d1117; font-family: -apple-system, 'Segoe UI', sans-serif; color: #c9d1d9; }
a { color: #58a6ff; text-decoration: none; }
.n-layout-sider { background: #161b22 !important; }
.n-menu { background: #161b22 !important; }
</style>

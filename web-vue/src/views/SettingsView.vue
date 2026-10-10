<template>
  <div class="settings-page">
    <!-- 左侧菜单 -->
    <div class="settings-menu">
      <div class="menu-title">系统设置</div>
      <div
        v-for="item in menuItems"
        :key="item.key"
        class="menu-item"
        :class="{ active: activeMenu === item.key }"
        @click="activeMenu = item.key"
      >
        <span class="menu-icon">{{ item.icon }}</span>
        <span class="menu-name">{{ item.name }}</span>
      </div>
    </div>

    <!-- 右侧内容 -->
    <div class="settings-content">
      <div class="content-header">
        <h3>{{ currentMenu?.name }}</h3>
        <n-button type="primary" size="small" :loading="saving" @click="handleSave">保存</n-button>
      </div>

      <div class="content-body">
        <!-- 通用设置 -->
        <div v-if="activeMenu === 'general'" class="form-section">
          <div class="form-item">
            <div class="form-label">系统名称</div>
            <n-input v-model:value="settings.system_name" placeholder="AsterTrack" style="max-width: 400px" />
            <div class="form-hint">显示在登录页和导航栏的系统名称</div>
          </div>
          <div class="form-item">
            <div class="form-label">默认首页</div>
            <n-select v-model:value="settings.default_page" :options="defaultPageOptions" style="max-width: 400px" />
            <div class="form-hint">用户登录后默认跳转的页面</div>
          </div>
        </div>

        <!-- 安全设置 -->
        <div v-if="activeMenu === 'security'" class="form-section">
          <div class="form-item">
            <div class="form-label">最大登录尝试次数</div>
            <n-input-number v-model:value="security.max_login_attempts" :min="1" :max="20" style="max-width: 200px" />
            <div class="form-hint">超过此次数后账户将被锁定</div>
          </div>
          <div class="form-item">
            <div class="form-label">账户锁定时长（分钟）</div>
            <n-input-number v-model:value="security.lock_minutes" :min="1" :max="1440" style="max-width: 200px" />
            <div class="form-hint">账户锁定后需等待的分钟数</div>
          </div>
          <div class="form-item">
            <div class="form-label">最小密码长度</div>
            <n-input-number v-model:value="security.min_password_len" :min="6" :max="32" style="max-width: 200px" />
            <div class="form-hint">用户密码至少需要的字符数</div>
          </div>
        </div>

        <!-- 日志设置 -->
        <div v-if="activeMenu === 'log'" class="form-section">
          <div class="form-item">
            <div class="form-label">事件保留天数</div>
            <n-input-number v-model:value="logSettings.event_days" :min="1" :max="365" style="max-width: 200px">
              <template #suffix>天</template>
            </n-input-number>
            <div class="form-hint">events 表数据保留时长</div>
          </div>
          <div class="form-item">
            <div class="form-label">告警保留天数</div>
            <n-input-number v-model:value="logSettings.alert_days" :min="1" :max="365" style="max-width: 200px">
              <template #suffix>天</template>
            </n-input-number>
            <div class="form-hint">alerts 表数据保留时长</div>
          </div>
          <div class="form-item">
            <div class="form-label">审计日志保留天数</div>
            <n-input-number v-model:value="logSettings.audit_days" :min="1" :max="365" style="max-width: 200px">
              <template #suffix>天</template>
            </n-input-number>
            <div class="form-hint">audit_logs 表数据保留时长</div>
          </div>
          <div class="form-item">
            <div class="form-label">Token 保留天数</div>
            <n-input-number v-model:value="logSettings.token_days" :min="1" :max="365" style="max-width: 200px">
              <template #suffix>天</template>
            </n-input-number>
            <div class="form-hint">enrollment_tokens 中已过期/已撤销数据的保留时长</div>
          </div>

          <n-space justify="end" style="margin-top: 8px;">
            <n-button size="small" @click="handleRestoreLogDefaults">
              恢复默认
            </n-button>
          </n-space>

          <n-divider />

          <div class="form-item">
            <div class="form-label">手动清理数据</div>
            <div class="form-hint" style="margin-bottom: 12px;">
              仅影响历史数据，不影响后续采集。清理动作会记录到审计日志。
            </div>
            <n-space vertical :size="12">
              <n-space v-for="t in cleanupTargets" :key="t.key" align="center" :size="8">
                <n-text style="width: 100px;">{{ t.label }}</n-text>
                <n-input-number
                  v-model:value="cleanupDays[t.key]"
                  :min="1"
                  :max="3650"
                  size="small"
                  style="width: 120px;"
                >
                  <template #suffix>天前</template>
                </n-input-number>
                <n-button size="small" @click="handleCleanup(t.key, 'before_days')">
                  清理 N 天前
                </n-button>
                <n-button size="small" type="error" ghost @click="handleCleanup(t.key, 'all')">
                  清空全部
                </n-button>
              </n-space>
            </n-space>
          </div>
        </div>

        <!-- Agent 设置 -->
        <div v-if="activeMenu === 'agent'" class="form-section">
          <div class="form-item">
            <div class="form-label">心跳间隔</div>
            <n-input v-model:value="settings.agent_heartbeat" placeholder="10s" style="max-width: 200px" />
            <div class="form-hint">Agent 向 Server 上报心跳的间隔（如 10s / 30s）</div>
          </div>
          <div class="form-item">
            <div class="form-label">资产采集间隔</div>
            <n-input v-model:value="settings.collect_interval" placeholder="300s" style="max-width: 200px" />
            <div class="form-hint">Agent 资产盘点间隔（如 300s / 600s）</div>
          </div>
          <div class="form-item">
            <div class="form-label">离线判定阈值（秒）</div>
            <n-input-number v-model:value="settings.offline_threshold" :min="60" :max="3600" style="max-width: 200px" />
            <div class="form-hint">超过此时间未收到心跳，判定主机离线</div>
          </div>
        </div>

        <!-- 告警设置 -->
        <div v-if="activeMenu === 'alert'" class="form-section">
          <div class="form-item">
            <div class="form-label">软基线灵敏度</div>
            <n-radio-group v-model:value="settings.baseline_sensitivity">
              <n-space>
                <n-radio value="high">高（2.5σ）</n-radio>
                <n-radio value="standard">标准（3.0σ）</n-radio>
                <n-radio value="low">低（4.0σ）</n-radio>
              </n-space>
            </n-radio-group>
            <div class="form-hint">值越高越敏感，误报率也越高</div>
          </div>
          <div class="form-item">
            <div class="form-label">告警去重窗口（秒）</div>
            <n-input-number v-model:value="settings.alert_dedup_window" :min="10" :max="600" style="max-width: 200px" />
            <div class="form-hint">相同规则在此时长内只告警一次</div>
          </div>
        </div>

        <!-- 用户管理 -->
        <div v-if="activeMenu === 'users'" class="form-section" style="max-width: 100%">
          <n-space vertical :size="16">
            <n-space justify="space-between">
              <n-text depth="3" style="font-size: 12px">共 {{ users.length }} 个用户</n-text>
              <n-button type="primary" size="small" @click="showCreateModal = true">
                + 新建用户
              </n-button>
            </n-space>

            <n-data-table
              :columns="userColumns"
              :data="users"
              :loading="userLoading"
              :bordered="false"
              size="small"
            />
          </n-space>
        </div>

        <!-- 关于 -->
        <div v-if="activeMenu === 'about'" class="form-section">
          <div class="about-card">
            <div class="about-logo">⭐</div>
            <div class="about-title">AsterTrack</div>
            <div class="about-version">Version 1.0.0 Beta</div>
            <div class="about-desc">基于 eBPF 的主机安全监控平台</div>
            <n-divider />
            <div class="about-info">
              <div class="about-row"><span>Server 版本</span><span>1.0.0</span></div>
              <div class="about-row"><span>Agent 版本</span><span>1.0.0</span></div>
              <div class="about-row"><span>内核支持</span><span>5.15+</span></div>
              <div class="about-row"><span>数据库</span><span>PostgreSQL 14+</span></div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 创建用户弹窗 -->
    <n-modal v-model:show="showCreateModal" preset="card" title="新建用户" style="max-width: 400px">
      <n-space vertical :size="16">
        <div>
          <div class="form-label">用户名</div>
          <n-input v-model:value="newUser.username" placeholder="请输入用户名" />
        </div>
        <div>
          <div class="form-label">密码</div>
          <n-input v-model:value="newUser.password" type="password" placeholder="至少 6 位" show-password-on="click" />
        </div>
        <div>
          <div class="form-label">角色</div>
          <n-select v-model:value="newUser.role" :options="roleOptions" />
        </div>
        <n-space justify="end">
          <n-button @click="showCreateModal = false">取消</n-button>
          <n-button type="primary" @click="handleCreateUser" :loading="userSaving">创建</n-button>
        </n-space>
      </n-space>
    </n-modal>

    <!-- 编辑用户弹窗 -->
    <n-modal v-model:show="showEditModal" preset="card" title="编辑用户" style="max-width: 400px">
      <n-space vertical :size="16">
        <div>
          <div class="form-label">用户名</div>
          <n-input :value="editUser.username" disabled />
        </div>
        <div>
          <div class="form-label">角色</div>
          <n-select v-model:value="editUser.role" :options="roleOptions" />
        </div>
        <div>
          <div class="form-label">新密码（留空则不修改）</div>
          <n-input v-model:value="editUser.password" type="password" placeholder="留空保持原密码" show-password-on="click" />
        </div>
        <n-space justify="end">
          <n-button @click="showEditModal = false">取消</n-button>
          <n-button type="primary" @click="handleUpdateUser" :loading="userSaving">保存</n-button>
        </n-space>
      </n-space>
    </n-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, h } from 'vue'
import { NButton, NInput, NInputNumber, NSelect, NRadioGroup, NRadio, NSpace, NDivider, useMessage, NDataTable, NModal, NTag, useDialog } from 'naive-ui'
import http from '../api/http'
import { cleanup, type CleanupTarget, type CleanupMode } from '../api/admin'

const message = useMessage()

const menuItems = [
  { key: 'general', name: '通用设置', icon: '⚙️' },
  { key: 'security', name: '安全设置', icon: '🔒' },
  { key: 'users', name: '用户管理', icon: '👥' },
  { key: 'log', name: '日志设置', icon: '📋' },
  { key: 'agent', name: 'Agent 设置', icon: '🖥️' },
  { key: 'alert', name: '告警设置', icon: '🚨' },
  { key: 'about', name: '关于系统', icon: 'ℹ️' },
]

const activeMenu = ref('general')
const saving = ref(false)

const currentMenu = computed(() => menuItems.find(m => m.key === activeMenu.value))

const defaultPageOptions = [
  { label: '仪表盘', value: '/dashboard' },
  { label: '攻击链', value: '/star' },
  { label: '告警', value: '/alerts' },
  { label: '资产', value: '/assets' },
]

// 通用
const settings = ref<Record<string, any>>({
  system_name: 'AsterTrack',
  default_page: '/dashboard',
  agent_heartbeat: '10s',
  collect_interval: '300s',
  offline_threshold: 120,
  baseline_sensitivity: 'standard',
  alert_dedup_window: 30,
})

// 安全
const security = ref({
  max_login_attempts: 5,
  lock_minutes: 15,
  min_password_len: 8,
})

// 日志
const logSettings = ref({
  event_days: 180,
  alert_days: 90,
  audit_days: 180,
  token_days: 180,
})

// 用户管理
const users = ref<any[]>([])
const userLoading = ref(false)
const userSaving = ref(false)
const showCreateModal = ref(false)
const showEditModal = ref(false)
const newUser = ref({ username: '', password: '', role: 'viewer' })
const editUser = ref({ id: 0, username: '', role: '', password: '' })
const dialog = useDialog()

// 数据清理
const cleanupTargets = [
  { key: 'events' as CleanupTarget, label: '事件（events）' },
  { key: 'alerts' as CleanupTarget, label: '告警（alerts）' },
  { key: 'audit_logs' as CleanupTarget, label: '审计（audit_logs）' },
  { key: 'tokens' as CleanupTarget, label: '令牌（tokens）' },
]
const cleanupDays = ref<Record<string, number>>({
  events: 180,
  alerts: 90,
  audit_logs: 180,
  tokens: 180,
})

const LOG_DEFAULTS = {
  event_days: 180,
  alert_days: 90,
  audit_days: 180,
  token_days: 180,
}

function handleRestoreLogDefaults() {
  dialog.warning({
    title: '恢复默认',
    content: '将保留天数重置为系统默认值（事件 180 / 告警 90 / 审计 180 / 令牌 180）。仅修改表单，需点击"保存"才生效。',
    positiveText: '恢复',
    negativeText: '取消',
    onPositiveClick: () => {
      logSettings.value = { ...LOG_DEFAULTS }
      message.info('已恢复默认值，请点击"保存"生效')
    },
  })
}

const CONFIRM_ALL = 'I_UNDERSTAND_TOTAL_LOSS'

async function handleCleanup(target: CleanupTarget, mode: CleanupMode) {
  const days = mode === 'before_days' ? cleanupDays.value[target] : 0
  const label = cleanupTargets.find(t => t.key === target)?.label || target

  // audit_logs 等保前置校验
  if (target === 'audit_logs') {
    if (mode === 'all') {
      message.error('审计日志不允许全清（等保要求），请使用"清理 N 天前"')
      return
    }
    if (days < 180) {
      message.error('审计日志至少保留 180 天（等保要求）')
      return
    }
  }

  if (mode === 'all') {
    // 危险操作：要求输入确认串
    const inputValue = ref('')
    dialog.warning({
      title: '⚠️ 危险操作',
      content: () => h('div', [
        h('p', { style: 'margin-bottom: 12px; color: #d03050; font-weight: bold;' },
          `即将清空全部「${label}」数据，此操作不可恢复！`),
        h('p', { style: 'margin-bottom: 8px; font-size: 13px;' },
          '请输入以下确认串以继续：'),
        h('code', {
          style: 'display:block; padding:6px 8px; background:#f5f5f5; margin-bottom:12px; font-size:12px; border-radius:4px;',
        }, CONFIRM_ALL),
        h(NInput, {
          value: inputValue.value,
          'onUpdate:value': (v: string) => { inputValue.value = v },
          placeholder: '输入上方确认串',
          size: 'small',
        }),
      ]),
      positiveText: '确认清空',
      negativeText: '取消',
      onPositiveClick: async () => {
        if (inputValue.value !== CONFIRM_ALL) {
          message.error('确认串不匹配')
          return false
        }
        try {
          const resp = await cleanup(target, mode, days, CONFIRM_ALL)
          message.success(`清理完成，影响 ${resp.affected} 条`)
        } catch (err: any) {
          message.error(err.response?.data?.error || '清理失败')
        }
      },
    })
  } else {
    // 普通清理：单次确认
    dialog.warning({
      title: '清理确认',
      content: `确认清理「${label}」中 ${days} 天前的数据？`,
      positiveText: '确认清理',
      negativeText: '取消',
      onPositiveClick: async () => {
        try {
          const resp = await cleanup(target, mode, days, 'CLEANUP')
          message.success(`清理完成，影响 ${resp.affected} 条`)
        } catch (err: any) {
          message.error(err.response?.data?.error || '清理失败')
        }
      },
    })
  }
}

const roleOptions = [
  { label: '管理员 (admin)', value: 'admin' },
  { label: '操作员 (operator)', value: 'operator' },
  { label: '查看者 (viewer)', value: 'viewer' },
]

const roleLabel = (role: string) => {
  const map: Record<string, string> = { admin: '管理员', operator: '操作员', viewer: '查看者' }
  return map[role] || role
}

const roleTagType = (role: string): 'error' | 'warning' | 'info' => {
  if (role === 'admin') return 'error'
  if (role === 'operator') return 'warning'
  return 'info'
}

const userColumns = [
  { title: 'ID', key: 'id', width: 80 },
  { title: '用户名', key: 'username', width: 200 },
  {
    title: '角色', key: 'role', width: 150,
    render: (row: any) => h(NTag, { type: roleTagType(row.role), size: 'small', round: true }, { default: () => roleLabel(row.role) }),
  },
  {
    title: '操作', key: 'actions', width: 200,
    render: (row: any) => h(NSpace, { size: 8 }, {
      default: () => [
        h(NButton, { size: 'small', onClick: () => {
          editUser.value = { id: row.id, username: row.username, role: row.role, password: '' }
          showEditModal.value = true
        }}, { default: () => '编辑' }),
        h(NButton, { size: 'small', type: 'error', onClick: () => handleDeleteUser(row) }, { default: () => '删除' }),
      ],
    }),
  },
]

async function loadUsers() {
  userLoading.value = true
  try {
    const { data } = await http.get('/users')
    users.value = data.users || []
  } catch (err: any) {
    message.error(err.response?.data?.error || '加载失败')
  } finally {
    userLoading.value = false
  }
}

async function handleCreateUser() {
  if (!newUser.value.username || !newUser.value.password) {
    message.warning('用户名和密码不能为空')
    return
  }
  if (newUser.value.password.length < 6) {
    message.warning('密码至少 6 位')
    return
  }
  userSaving.value = true
  try {
    await http.post('/users', newUser.value)
    message.success('用户已创建')
    showCreateModal.value = false
    newUser.value = { username: '', password: '', role: 'viewer' }
    await loadUsers()
  } catch (err: any) {
    message.error(err.response?.data?.error || '创建失败')
  } finally {
    userSaving.value = false
  }
}

async function handleUpdateUser() {
  userSaving.value = true
  try {
    const payload: any = { id: editUser.value.id, role: editUser.value.role }
    if (editUser.value.password) payload.password = editUser.value.password
    await http.put('/users', payload)
    message.success('用户已更新')
    showEditModal.value = false
    await loadUsers()
  } catch (err: any) {
    message.error(err.response?.data?.error || '更新失败')
  } finally {
    userSaving.value = false
  }
}

function handleDeleteUser(row: any) {
  dialog.warning({
    title: '确认删除',
    content: `确定要删除用户 "${row.username}" 吗？`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await http.delete('/users', { data: { id: row.id } })
        message.success('用户已删除')
        await loadUsers()
      } catch (err: any) {
        message.error(err.response?.data?.error || '删除失败')
      }
    },
  })
}

onMounted(async () => {
  await loadSettings()
  await loadUsers()
})

async function loadSettings() {
  try {
    // 通用设置
    const { data: allSettings } = await http.get('/settings')
    if (allSettings.settings) {
      Object.assign(settings.value, allSettings.settings)
    }

    // 安全设置
    const { data: sec } = await http.get('/security-settings')
    security.value = {
      max_login_attempts: sec.max_login_attempts || 5,
      lock_minutes: sec.lock_minutes || 15,
      min_password_len: sec.min_password_len || 8,
    }

    // 日志设置
    const { data: logs } = await http.get('/log-settings')
    logSettings.value = {
      event_days: parseInt(logs.event_days) || 180,
      alert_days: parseInt(logs.alert_days) || 90,
      audit_days: parseInt(logs.audit_days) || 180,
      token_days: parseInt(logs.token_days) || 180,
    }
  } catch (err) {
    console.error('加载设置失败:', err)
  }
}

async function handleSave() {
  saving.value = true
  try {
    if (activeMenu.value === 'general' || activeMenu.value === 'agent' || activeMenu.value === 'alert') {
      await http.post('/settings', settings.value)
    } else if (activeMenu.value === 'security') {
      await http.post('/security-settings', security.value)
    } else if (activeMenu.value === 'log') {
      await http.post('/log-settings', {
        event_days: String(logSettings.value.event_days),
        alert_days: String(logSettings.value.alert_days),
        audit_days: String(logSettings.value.audit_days),
        token_days: String(logSettings.value.token_days),
      })
    } else {
      message.info('无需保存')
      return
    }
    message.success('保存成功')
  } catch (err: any) {
    message.error(err.response?.data?.error || '保存失败')
  } finally {
    saving.value = false
  }
}
</script>

<style scoped>
.settings-page {
  display: flex;
  height: calc(100vh - 60px);
  background: #f5f7fa;
  padding: 12px;
  gap: 12px;
}

/* 左侧菜单 */
.settings-menu {
  flex: 0 0 200px;
  background: #fff;
  border-radius: 8px;
  padding: 8px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.06);
  overflow-y: auto;
}

.menu-title {
  font-size: 12px;
  color: #94a3b8;
  padding: 12px 12px 8px;
  font-weight: 600;
  letter-spacing: 0.5px;
}

.menu-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  border-radius: 6px;
  cursor: pointer;
  transition: background 0.15s;
  font-size: 13px;
  color: #334155;
}

.menu-item:hover {
  background: #f1f5f9;
}

.menu-item.active {
  background: #eef2ff;
  color: #4f46e5;
  font-weight: 600;
  border-left: 3px solid #4f46e5;
  padding-left: 9px;
}

.menu-icon {
  font-size: 16px;
}

/* 右侧内容 */
.settings-content {
  flex: 1;
  background: #fff;
  border-radius: 8px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.06);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.content-header {
  padding: 16px 24px;
  border-bottom: 1px solid #e2e8f0;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.content-header h3 {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
  color: #1e293b;
}

.content-body {
  flex: 1;
  padding: 24px;
  overflow-y: auto;
}

.form-section {
  max-width: 600px;
}

.form-item {
  margin-bottom: 28px;
}

.form-label {
  font-size: 13px;
  font-weight: 600;
  color: #334155;
  margin-bottom: 8px;
}

.form-hint {
  font-size: 12px;
  color: #94a3b8;
  margin-top: 6px;
}

/* 关于 */
.about-card {
  text-align: center;
  padding: 40px 0;
  max-width: 500px;
  margin: 0 auto;
}

.about-logo {
  font-size: 64px;
  margin-bottom: 12px;
}

.about-title {
  font-size: 24px;
  font-weight: 700;
  color: #1e293b;
}

.about-version {
  font-size: 13px;
  color: #64748b;
  margin-top: 4px;
}

.about-desc {
  font-size: 13px;
  color: #94a3b8;
  margin-top: 8px;
}

.about-info {
  text-align: left;
  padding: 0 40px;
}

.about-row {
  display: flex;
  justify-content: space-between;
  padding: 8px 0;
  font-size: 13px;
  border-bottom: 1px solid #f1f5f9;
}

.about-row span:first-child {
  color: #64748b;
}

.about-row span:last-child {
  color: #1e293b;
  font-weight: 500;
}
</style>

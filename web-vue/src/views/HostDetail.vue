<template>
  <Layout>
    <n-button @click="$router.back()" size="small" style="margin-bottom:12px">← 返回</n-button>
    
    <n-tabs type="line" animated v-model:value="tab">
      <n-tab-pane v-for="tp in tabs" :key="tp.key" :name="tp.key" :tab="tp.label">
        <n-data-table
          v-if="tp.hasTable"
          :columns="tp.cols"
          :data="tp.data.length ? tp.data : [{_empty: true}]"
          size="small"
          :bordered="false"
          :pagination="pagination"
          :row-key="tp.rowKey"><template #empty><div style="padding:16px;text-align:center;color:#999">暂无数据</div></template></n-data-table>
        <n-descriptions v-else-if="tp.key==='sys'" :column="3" size="small" bordered>
          <n-descriptions-item label="OS">{{ sys.os?.name || sys.name }}</n-descriptions-item>
          <n-descriptions-item label="内核">{{ sys.os?.kernel || sys.kernel }}</n-descriptions-item>
          <n-descriptions-item label="CPU">{{ sys.cpu?.model }} x{{ sys.cpu?.cores }}</n-descriptions-item>
          <n-descriptions-item label="内存">{{ sys.memory?.total_mb }}MB</n-descriptions-item>
          <n-descriptions-item label="启动时间">{{ hw.boot_time }}</n-descriptions-item>
          <n-descriptions-item label="制造商">{{ hw.manufacturer }} {{ hw.model }}</n-descriptions-item>
        </n-descriptions>
      </n-tab-pane>
    </n-tabs>
  </Layout>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '../api'
import Layout from '../layouts/MainLayout.vue'

const route = useRoute()
const tab = ref('sys')
const sys = ref({}), hw = ref({})
const allData = ref({})

const pagination = reactive({ page: 1, pageSize: 15, showSizePicker: true, pageSizes: [10, 15, 20, 50] })

const portCols = [
  { title: '端口:进程', key: 'port_proc', minWidth: 130, render: (r) => `${r.port}:${r.name}` },
  { title: '绑定IP', key: 'bind_ip', minWidth: 120 }, { title: '协议', key: 'protocol', minWidth: 60 },
  { title: 'PID', key: 'pid', minWidth: 60 }, { title: '用户', key: 'user', minWidth: 80 }
]
const procCols = [
  { title: '进程名', key: 'name', minWidth: 140 }, { title: 'PID', key: 'pid', minWidth: 60 },
  { title: '用户', key: 'user', minWidth: 80 }, { title: '状态', key: 'state', minWidth: 50 },
  { title: '路径', key: 'exe_path', ellipsis: { tooltip: true }, minWidth: 200 }
]
const appCols = [
  { title: '应用名', key: 'name', minWidth: 130 }, { title: '版本', key: 'version', minWidth: 100 },
  { title: 'PID', key: 'pid', minWidth: 60 }
]
const webSvcCols = [
  { title: '服务名', key: 'name', minWidth: 120 }, { title: '版本', key: 'version', minWidth: 100 },
  { title: 'PID', key: 'pid', minWidth: 60 }
]
const fwCols = [
  { title: '框架名', key: 'name', minWidth: 120 }, { title: '版本', key: 'version', minWidth: 100 },
  { title: '路径', key: 'base_path', ellipsis: { tooltip: true }, minWidth: 200 }
]
const dbCols = [
  { title: '数据库名', key: 'name', minWidth: 120 }, { title: '版本', key: 'version', minWidth: 100 }
]
const jarCols = [
  { title: '包名', key: 'name', minWidth: 180 }, { title: '版本', key: 'version', minWidth: 80 },
  { title: '类型', key: 'type', minWidth: 80 }, { title: '路径', key: 'path', ellipsis: { tooltip: true }, minWidth: 200 }
]
const npmCols = [
  { title: '包名', key: 'name', minWidth: 150 }, { title: '版本', key: 'version', minWidth: 80 }
]
const pyCols = [
  { title: '包名', key: 'name', minWidth: 150 }, { title: '版本', key: 'version', minWidth: 80 }
]
const svcCols = [
  { title: '服务名', key: 'name', minWidth: 200 }, { title: '启用', key: 'enabled', minWidth: 60, render: (r) => r.enabled ? '✅' : '❌' },
  { title: '运行状态', key: 'active', minWidth: 80 }
]
const cronCols = [
  { title: '用户', key: 'user', minWidth: 80 }, { title: '周期', key: 'schedule', minWidth: 120 },
  { title: '命令', key: 'command', ellipsis: { tooltip: true }, minWidth: 200 }
]
const kmCols = [
  { title: '模块名', key: 'name', minWidth: 150 }, { title: '版本', key: 'version', minWidth: 80 },
  { title: '大小', key: 'size', minWidth: 60 }, { title: '依赖数', key: 'used_by', minWidth: 60 }
]
const envCols = [
  { title: '变量名', key: 'name', minWidth: 120 }, { title: '值', key: 'value', ellipsis: { tooltip: true }, minWidth: 200 },
  { title: '类型', key: 'type', minWidth: 60 }, { title: '用户', key: 'user', minWidth: 80 }
]
const userCols = [
  { title: '用户名', key: 'username' }, { title: 'UID', key: 'uid', minWidth: 60 },
  { title: 'Shell', key: 'shell' }, { title: 'root', key: 'is_root', render: (r) => r.is_root ? '✅' : '', minWidth: 50 },
  { title: 'sudo', key: 'has_sudo', render: (r) => r.has_sudo ? '✅' : '', minWidth: 50 }
]

const tabs = computed(() => {
  const d = allData.value
  const procs = d.processes || []
  const s = d.system || {}
  return [
    { key: 'sys', label: '系统', hasTable: false },
    { key: 'port', label: '端口服务', hasTable: true, cols: portCols, data: procs.filter(p => (p.listening_ports||[]).length).flatMap(p => (p.listening_ports||[]).map(port => ({ port, name: p.name, bind_ip: '0.0.0.0', protocol: 'TCP', pid: p.pid, user: p.user }))), rowKey: (r) => r.pid + ':' + r.port },
    { key: 'proc', label: '运行进程', hasTable: true, cols: procCols, data: procs, rowKey: (r) => r.pid },
    { key: 'app', label: '软件应用', hasTable: true, cols: appCols, data: s.services || [], rowKey: (r) => r.name },
    { key: 'web', label: 'Web服务', hasTable: true, cols: webSvcCols, data: (s.web_components||[]).filter(w => w.type==='Web应用'), rowKey: (r) => r.name },
    { key: 'framework', label: 'Web框架', hasTable: true, cols: fwCols, data: (s.web_components||[]).filter(w => w.type==='框架'), rowKey: (r) => r.name },
    { key: 'db', label: '数据库', hasTable: true, cols: dbCols, data: (s.services||[]).filter(w => w.type==='数据库'), rowKey: (r) => r.name },
    { key: 'jar', label: 'Jar包', hasTable: true, cols: jarCols, data: s.jar_packages || [], rowKey: (r) => r.path || r.name },
    { key: 'npm', label: 'Npm包', hasTable: true, cols: npmCols, data: s.npm_packages || [], rowKey: (r) => r.name },
    { key: 'python', label: 'Python包', hasTable: true, cols: pyCols, data: s.python_packages || [], rowKey: (r) => r.name },
    { key: 'service', label: '启动服务', hasTable: true, cols: svcCols, data: s.service_status || [], rowKey: (r) => r.name },
    { key: 'cron', label: '计划任务', hasTable: true, cols: cronCols, data: s.crons || [], rowKey: (r) => `${r.user}-${r.schedule}-${r.command}` },
    { key: 'kernel', label: '内核模块', hasTable: true, cols: kmCols, data: s.kernel_modules || [], rowKey: (r) => r.name },
    { key: 'env', label: '环境变量', hasTable: true, cols: envCols, data: s.env_variables || [], rowKey: (r) => `${r.name}-${r.user}` },
    { key: 'user', label: '用户', hasTable: true, cols: userCols, data: d.users || [], rowKey: (r) => r.username },
  ]
})

onMounted(async () => {
  try {
    const d = await api.getAssetDetail(route.params.id)
    allData.value = d
    const s = d.system || {}
    sys.value = s.system || s || {}
    hw.value = s.hardware || {}
  } catch(e) {}
})
</script>

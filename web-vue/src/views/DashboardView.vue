<template>
  <Layout>
    <n-grid :cols="3" :x-gap="12" style="margin-bottom:12px">
      <n-grid-item v-for="card in cards" :key="card.title">
        <n-card size="small" :bordered="false" :title="card.title">
          <div style="display:flex;align-items:center;gap:12px">
            <div :ref="el => { if (el) rings[card.key] = el }" style="width:120px;height:120px;flex-shrink:0"></div>
            <div style="display:flex;flex-direction:column;gap:3px;font-size:11px;flex-shrink:0">
              <span v-for="lv in card.levels" :key="lv.label" :style="{color:lv.color}">{{ lv.label }} {{ lv.count }}</span>
            </div>
            <div style="flex:1;min-width:0">
              <div style="font-size:12px;color:#86909c;border-bottom:1px solid #e4e7ed;padding-bottom:4px;margin-bottom:4px">{{ card.topLabel }}</div>
              <div v-for="h in card.topList" :key="h.ip" style="font-size:12px;padding:4px 8px;border-bottom:1px solid #e4e7ed;display:flex;justify-content:space-between">
                <span>{{ h.ip }}</span>
                <span :style="{color:h.color}">{{ h.label }}</span>
              </div>
            </div>
          </div>
        </n-card>
      </n-grid-item>
    </n-grid>

    <n-card title="主机列表" size="small" :bordered="false">
      <n-data-table :columns="cols" :data="agents" :bordered="false" size="small" :pagination="pagination" :row-key="(r) => r.id" />
    </n-card>
  </Layout>
</template>

<script setup>
import { ref, reactive, onMounted, h, nextTick } from 'vue'
import { api } from '../api'
import Layout from '../layouts/MainLayout.vue'
import * as echarts from 'echarts'

const agents = ref([])
const rings = reactive({})
const pagination = reactive({ page: 1, pageSize: 20, showSizePicker: true, pageSizes: [10, 20, 50, 100] })
const cols = [
  { title: '主机名', key: 'hostname', minWidth: 140 }, { title: 'IP', key: 'ip_addr', minWidth: 130 },
  { title: 'CPU', key: 'cpu', minWidth: 80 }, { title: '内存', key: 'mem', minWidth: 80 },
  { title: '磁盘', key: 'disk', minWidth: 80 }, { title: 'OS', key: 'os', minWidth: 150 },
  { title: '操作', key: 'id', minWidth: 60, render: (r) => h('a', { href: '#/host/' + r.id }, '详情') }
]

const cards = reactive([
  { key: 'cpu', title: '主机资源负载分布', topLabel: '系统负载TOP5', topList: [], levels: [], avg: 0, color: '#1e6fff' },
  { key: 'mem', title: '内存使用率分布', topLabel: '内存使用TOP5', topList: [], levels: [], avg: 0, color: '#e04a5a' },
  { key: 'disk', title: '磁盘使用率分布', topLabel: '磁盘使用TOP5', topList: [], levels: [], avg: 0, color: '#e6a23c' },
])

function makeRing(el, value, color) {
  if (!el || value === undefined) return
  echarts.init(el).setOption({ series: [{ type: 'pie', radius: ['55%', '70%'], label: { show: false }, data: [{ value, itemStyle: { color } }, { value: 100 - value, itemStyle: { color: '#f0f2f5' } }] }] })
}

onMounted(async () => {
  const ag = await api.getAgents()
  const list = ag.agents || []

  // 从assets获取perf和OS
  const as = await api.getAssets()
  const assetMap = {}
  ;(as.agents || []).forEach(a => { assetMap[a.agent_id] = a })

  const cpuL = [], memL = [], diskL = []
  for (const a of list) {
    const ast = assetMap[a.id] || {}
    cpuL.push({ ip: a.ip_addr, v: ast.cpu_percent || 0 })
    memL.push({ ip: a.ip_addr, v: ast.mem_percent || 0 })
    diskL.push({ ip: a.ip_addr, v: ast.disk_percent || 0 })
  }

  const build = (list2, card, colorFn, levelsFn) => {
    const s = list2.sort((a,b) => b.v - a.v)
    card.topList = s.slice(0,5).map(c => ({ ip: c.ip, label: c.v.toFixed(1) + (card.key==='cpu'?'/4核':'%'), color: colorFn(c.v) }))
    card.avg = s.length > 0 ? s.reduce((x,c) => x + c.v, 0) / s.length : 0
    card.levels = levelsFn(s)
  }

  build(cpuL, cards[0], v => v > 80 ? '#e04a5a' : v > 50 ? '#e6a23c' : '#1e6fff', s => {
    const l = { high: 0, medium: 0, low: 0, unknown: 0 }
    s.forEach(c => { if (c.v > 80) l.high++; else if (c.v > 50) l.medium++; else if (c.v > 0) l.low++; else l.unknown++ })
    return [{ label: '高', count: l.high, color: '#e04a5a' }, { label: '中', count: l.medium, color: '#e6a23c' }, { label: '低', count: l.low, color: '#1e6fff' }, { label: '未知', count: l.unknown, color: '#999' }]
  })

  build(memL, cards[1], v => v > 80 ? '#e04a5a' : v > 50 ? '#1e6fff' : v > 20 ? '#67c23a' : '#999', s => {
    const l = { red: 0, blue: 0, green: 0, low: 0 }
    s.forEach(c => { if (c.v > 80) l.red++; else if (c.v > 50) l.blue++; else if (c.v > 20) l.green++; else l.low++ })
    return [{ label: '80~100%', count: l.red, color: '#e04a5a' }, { label: '50~80%', count: l.blue, color: '#1e6fff' }, { label: '20~50%', count: l.green, color: '#67c23a' }, { label: '0~20%', count: l.low, color: '#999' }]
  })

  build(diskL, cards[2], v => v > 80 ? '#e04a5a' : v > 50 ? '#1e6fff' : v > 20 ? '#67c23a' : '#999', s => {
    const l = { red: 0, blue: 0, green: 0, low: 0 }
    s.forEach(c => { if (c.v > 80) l.red++; else if (c.v > 50) l.blue++; else if (c.v > 20) l.green++; else l.low++ })
    return [{ label: '80~100%', count: l.red, color: '#e04a5a' }, { label: '50~80%', count: l.blue, color: '#1e6fff' }, { label: '20~50%', count: l.green, color: '#67c23a' }, { label: '0~20%', count: l.low, color: '#999' }]
  })

  agents.value = list.map((a, i) => ({
    ...a, os: (assetMap[a.id] || {}).os || '-',
    cpu: cpuL[i]?.v.toFixed(1)+'%', mem: memL[i]?.v.toFixed(1)+'%', disk: diskL[i]?.v.toFixed(1)+'%'
  }))

  nextTick(() => {
    makeRing(rings['cpu'], Math.round(cards[0].avg), cards[0].color)
    makeRing(rings['mem'], Math.round(cards[1].avg), cards[1].color)
    makeRing(rings['disk'], Math.round(cards[2].avg), cards[2].color)
  })
})
</script>

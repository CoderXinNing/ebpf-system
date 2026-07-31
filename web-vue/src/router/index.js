import { createRouter, createWebHashHistory } from 'vue-router'

const routes = [
  { path: '/login', component: () => import('../views/LoginView.vue') },
  { path: '/', component: () => import('../views/DashboardView.vue') },
  { path: '/hosts', component: () => import('../views/HostManage.vue') },
  { path: '/host/:id', component: () => import('../views/HostDetail.vue') },
  { path: '/processes', component: () => import('../views/ProcessesView.vue') },
  { path: '/port_detail/:name', component: () => import('../views/PortDetail.vue') },
  { path: '/proc_agg', component: () => import('../views/ProcAggView.vue') },
  { path: '/proc_agg/:name', component: () => import('../views/ProcAggDetail.vue') },
  { path: '/web', component: () => import('../views/WebAssetsView.vue') },
  { path: '/web_detail/:name', component: () => import('../views/WebDetail.vue') },
  { path: '/packages', component: () => import('../views/PackagesView.vue') },
  { path: '/pkg_detail/:name', component: () => import('../views/PkgDetail.vue') },
  { path: '/events', component: () => import('../views/EventsView.vue') },
  { path: '/probes', component: () => import('../views/ProbesView.vue') },
  { path: '/install', component: () => import('../views/AgentInstall.vue') },
]

const router = createRouter({
  history: createWebHashHistory(),
  routes
})

router.beforeEach((to, from, next) => {
  const token = localStorage.getItem('token')
  if (to.path !== '/login' && !token) {
    next('/login')
  } else {
    next()
  }
})

export default router

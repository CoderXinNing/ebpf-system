import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      redirect: '/dashboard',
    },
    {
      path: '/login',
      name: 'Login',
      component: () => import('../views/LoginView.vue'),
    },
    {
      path: '/dashboard',
      name: 'Dashboard',
      component: () => import('../views/DashboardView.vue'),
    },
    {
      path: '/star',
      name: 'StarChain',
      component: () => import('../views/StarChainView.vue'),
    },
    {
      path: '/alerts',
      name: 'AlertList',
      component: () => import('../views/AlertListView.vue'),
    },
  ],
})

export default router

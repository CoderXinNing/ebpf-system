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
    {
      path: '/whitelist',
      name: 'Whitelist',
      component: () => import('../views/WhitelistView.vue'),
    },
  ],
})

// 路由守卫：未登录跳转登录页
router.beforeEach((to, from, next) => {
  const token = localStorage.getItem('token')
  if (to.path !== '/login' && !token) {
    next('/login')
  } else {
    next()
  }
})

export default router

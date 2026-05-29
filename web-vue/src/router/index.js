import { createRouter, createWebHashHistory } from 'vue-router'
import DashboardView from '../views/DashboardView.vue'
import EventsView from '../views/EventsView.vue'
import DeployView from '../views/DeployView.vue'
import UsersView from '../views/UsersView.vue'
import LoginView from '../views/LoginView.vue'

const routes = [
  { path: '/', component: DashboardView },
  { path: '/events', component: EventsView },
  { path: '/deploy', component: DeployView },
  { path: '/users', component: UsersView },
  { path: '/login', component: LoginView },
]

const router = createRouter({
  history: createWebHashHistory(),
  routes,
})

export default router

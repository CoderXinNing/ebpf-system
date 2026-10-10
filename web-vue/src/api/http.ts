import axios from 'axios'

const http = axios.create({
  baseURL: '/api',
  timeout: 10000,
})

// 请求拦截器：添加 JWT token
http.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// 响应拦截器：记录活动 + 处理 401
let redirecting = false
http.interceptors.response.use(
  (response) => {
    const url = response.config.url || ''
    // 排除纯查询配置（不算用户活动）
    if (!url.includes('/session/config')) {
      // 广播活动事件，useSession 监听后重置倒数
      window.dispatchEvent(new CustomEvent('astertrack:activity'))
    }
    return response
  },
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      localStorage.removeItem('session')

      if (!redirecting && window.location.pathname !== '/login') {
        redirecting = true
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  }
)

export default http

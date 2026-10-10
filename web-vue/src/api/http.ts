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

// 响应拦截器：处理 401
let redirecting = false
http.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // 清理本地凭证
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      localStorage.removeItem('session')

      // 防抖：避免并发请求多次跳转
      if (!redirecting && window.location.pathname !== '/login') {
        redirecting = true
        // 用 location.href 而非 router，因为不在 Vue 组件上下文
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  }
)

export default http

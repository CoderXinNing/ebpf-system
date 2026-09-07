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
http.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token')
      // 暂时不跳转，后续对接登录
    }
    return Promise.reject(error)
  }
)

export default http

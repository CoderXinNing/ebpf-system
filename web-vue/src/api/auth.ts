import http from './http'

export interface LoginResponse {
  token: string
  user: {
    id: number
    username: string
    role: string
  }
  session: {
    idle_minutes: number
    absolute_hours: number          // 0 = 禁用
    heartbeat_enabled: boolean
    heartbeat_interval_seconds: number
  }
}

export async function login(username: string, password: string): Promise<LoginResponse> {
  const { data } = await http.post('/login', { username, password })
  return data
}

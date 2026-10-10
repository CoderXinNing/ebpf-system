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
    absolute_hours: number
    keepalive: boolean
  }
}

export async function login(
  username: string,
  password: string,
  keepalive: boolean = false,
): Promise<LoginResponse> {
  const { data } = await http.post('/login', { username, password, keepalive })
  return data
}

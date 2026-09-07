import http from './http'

export interface LoginResponse {
  token: string
  user: {
    id: number
    username: string
    role: string
  }
}

export async function login(username: string, password: string): Promise<LoginResponse> {
  const { data } = await http.post('/login', { username, password })
  return data
}

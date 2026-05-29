import { useAuthStore } from '../stores/auth'

const BASE = ''

async function request(path, opts = {}) {
  const auth = useAuthStore()
  const headers = opts.headers || {}
  if (auth.token) headers['Authorization'] = 'Bearer ' + auth.token
  const resp = await fetch(BASE + path, { ...opts, headers })
  if (resp.status === 401) { auth.logout(); throw new Error('未登录') }
  return resp.json()
}

export const api = {
  login: (username, password) => request('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  }),
  getAgents: () => request('/api/agents'),
  getEvents: () => request('/api/events'),
  getHealth: () => request('/api/health'),
  sendCommand: (data) => request('/api/command', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  }),
  getUsers: () => request('/api/users'),
}

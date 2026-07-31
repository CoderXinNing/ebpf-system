const BASE = ''

async function request(path, opts = {}) {
  const token = localStorage.getItem('token')
  const headers = { ...opts.headers }
  if (token) headers['Authorization'] = 'Bearer ' + token

  const resp = await fetch(BASE + path, { ...opts, headers })
  if (resp.status === 401) {
    localStorage.clear()
    window.location.hash = '#/login'
    throw new Error('未登录')
  }
  return resp.json()
}

export const api = {
  login: (u, p) => request('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: u, password: p })
  }),

  getHealth: () => request('/api/health'),
  getAgents: () => request('/api/agents'),
  getEvents: () => request('/api/events'),
  getUsers: () => request('/api/users'),

  getAssets: () => request('/api/assets'),
  getAssetDetail: (id) => request('/api/assets/' + id),
  getAssetsByCategory: (type, agentId) => {
    let url = '/api/assets/category?type=' + encodeURIComponent(type || '所有')
    if (agentId) url += '&agent_id=' + agentId
    return request(url)
  },

  sendCommand: (data) => request('/api/command', {
  moveHosts: (ids, group) => request("/api/move", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ agent_ids: ids, group }) }),
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  })
}

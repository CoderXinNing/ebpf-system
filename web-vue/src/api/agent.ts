import http from './http'

export interface AgentInfo {
  id: string
  hostname: string
  ip_addr: string
  version: string
  active_probes: number
  last_seen: number
  capability_level: string
}

export async function getAgents(): Promise<AgentInfo[]> {
  const { data } = await http.get('/agents')
  return data.agents || []
}

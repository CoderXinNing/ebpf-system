import http from './http'

export interface ProbeStatusEntry {
  name: string
  status: string
  reason?: string
  last_event_at: number
  last_check_at: number
  selftest_ok: boolean
  consecutive_failures: number
  loaded_at: number
}

export interface AgentInfo {
  id: string
  hostname: string
  ip_addr: string
  version: string
  active_probes: number
  last_seen: number
  capability_level: string
  probe_status?: Record<string, ProbeStatusEntry>
}

export async function getAgents(): Promise<AgentInfo[]> {
  const { data } = await http.get('/agents')
  return data.agents || []
}

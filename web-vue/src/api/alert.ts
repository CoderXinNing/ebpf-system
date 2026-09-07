import http from './http'

export interface AlertItem {
  id: number
  rule_name: string
  severity: string
  description: string
  agent_id: string
  pid: number
  comm: string
  filename: string
  details: string
  correlation_id: string
  status: string
  detected_at: string
}

export async function getAlerts(limit = 50): Promise<AlertItem[]> {
  const { data } = await http.get('/alerts', { params: { limit } })
  return data.alerts || []
}

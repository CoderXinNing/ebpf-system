import http from './http'

export interface StarEvent {
  id: string
  agent_id: string
  probe_name: string
  event_type: string
  pid: number
  comm: string
  filename: string
  details: string
  correlation_id: string
  timestamp: number
}

export interface StarChainResponse {
  correlation_id: string
  total: number
  events: StarEvent[]
}

export async function getStarChain(correlationId: string): Promise<StarChainResponse> {
  const { data } = await http.get(`/star/${correlationId}`)
  return data
}

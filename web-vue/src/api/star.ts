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

export interface ChainNode {
  id: string
  event_type: string
  pid: number
  comm: string
  filename: string
  details: string
  timestamp: number
  count?: number
  children?: ChainNode[]
}

export interface StarChainResponse {
  correlation_id: string
  total: number
  events?: StarEvent[]
  tree?: ChainNode[]
}

export async function getStarChain(correlationId: string): Promise<StarChainResponse> {
  const { data } = await http.get(`/star/${correlationId}`)
  return data
}

export interface StarSearchResponse {
  query: string
  match_type: 'correlation_id' | 'alerts'
  correlation_id?: string
  total?: number
  tree?: ChainNode[]
  alerts?: any[]
}

export async function searchStarChain(query: string): Promise<StarSearchResponse> {
  const { data } = await http.get('/star/search', { params: { q: query } })
  return data
}

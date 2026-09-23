import http from './http'

export interface Token {
  id: number
  name: string
  group_id: number | null
  max_uses: number
  used_count: number
  expires_at: string
  created_by: string
  created_at: string
  revoked_at: string | null
}

export async function listTokens(): Promise<Token[]> {
  const { data } = await http.get('/enrollment-tokens')
  return data.tokens || []
}

export async function createToken(payload: {
  name: string
  group_id?: number | null
  max_uses: number
  ttl_hours: number
}): Promise<{ token: string; message: string }> {
  const { data } = await http.post('/enrollment-tokens', payload)
  return data
}

export async function revokeToken(id: number): Promise<void> {
  await http.delete('/enrollment-tokens', { data: { id } })
}

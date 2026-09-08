import http from './http'

export interface WhitelistItem {
  process_name: string
  reason?: string
}

export async function getWhitelist(): Promise<string[]> {
  const { data } = await http.get('/whitelist')
  return data.whitelist || []
}

export async function addWhitelist(processName: string): Promise<void> {
  await http.post('/whitelist', { process_name: processName })
}

export async function removeWhitelist(processName: string): Promise<void> {
  await http.delete(`/whitelist/${processName}`)
}

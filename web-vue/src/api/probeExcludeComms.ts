import http from './http'

export interface ProbeExcludeCommsItem {
  comm: string
  reason?: string
}

export async function getProbeExcludeComms(): Promise<string[]> {
  const { data } = await http.get('/probe-exclude-comms')
  return data.comms || []
}

export async function addProbeExcludeComms(comm: string): Promise<void> {
  await http.post('/probe-exclude-comms', { comm })
}

export async function removeProbeExcludeComms(comm: string): Promise<void> {
  await http.delete(`/probe-exclude-comms/${comm}`)
}

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

export interface FrameworkInfo {
  bcc_available: boolean
  libbpf_available: boolean
  libbpf_core: boolean
  bpftrace_available: boolean
  clang_available: boolean
  llvm_available: boolean
  kernel_headers_available: boolean
  go_ebpf_available: boolean
}

export interface KernelInfo {
  version: string
  arch: string
  btf_enabled: boolean
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
  framework?: FrameworkInfo
  kernel_info?: KernelInfo
}

export async function getAgents(): Promise<AgentInfo[]> {
  const { data } = await http.get('/agents')
  return data.agents || []
}

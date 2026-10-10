import http from './http'

export type CleanupTarget = 'events' | 'alerts' | 'audit_logs' | 'tokens'
export type CleanupMode = 'all' | 'before_days'

export interface CleanupResponse {
  success: boolean
  target: string
  mode: string
  affected: number
}

/**
 * 数据/日志清理
 *
 * target: events / alerts / audit_logs / tokens
 * mode:   all（清空全部） / before_days（清 N 天前）
 * days:   仅 before_days 时有效，必须 > 0
 *         audit_logs 时最小 180（等保）
 * confirm: 后端按 mode 校验
 *          - before_days: "CLEANUP"
 *          - all:         "I_UNDERSTAND_TOTAL_LOSS"
 */
export async function cleanup(
  target: CleanupTarget,
  mode: CleanupMode,
  days: number = 0,
  confirm: string = 'CLEANUP',
): Promise<CleanupResponse> {
  const { data } = await http.post('/admin/cleanup', {
    target,
    mode,
    days,
    confirm,
  })
  return data
}

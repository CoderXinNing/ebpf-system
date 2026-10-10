-- ============================================
-- AsterTrack session 配置 v2
-- 日期：2026-10-10
--
-- 变更：
--   1. absolute_hours 默认值 8 → 0（0 表示禁用绝对超时）
--   2. 新增 heartbeat_interval_seconds（心跳间隔，秒）
--   3. keepalive_extend_minutes 语义废止（保留字段，不再使用）
--
-- 设计说明：
--   统一模型 = 任何后端交互（API 请求 / 心跳）都刷 idle
--   心跳 = 用户显式开启的"自动交互"
--   不使用心跳 → 用户不操作 idle 秒后踢
--   使用心跳 → 每 N 秒自动刷 idle，会话保活
-- ============================================

BEGIN;

-- 1. absolute_hours 默认禁用
UPDATE system_config
SET value = '0',
    description = '绝对超时（小时，0=禁用；开启后无论是否活动都会强制登出）'
WHERE namespace = 'session' AND key = 'absolute_hours';

-- 2. 新增心跳间隔
INSERT INTO system_config (namespace, key, value, value_type, description)
VALUES ('session', 'heartbeat_interval_seconds', '180', 'int',
        '心跳间隔（秒），需 < idle_minutes*30（留 2 次窗口容忍 1 次丢包）')
ON CONFLICT (namespace, key) DO NOTHING;

-- 3. 废止 keepalive_extend_minutes（保留，不再读）
UPDATE system_config
SET description = '[已废止] 旧“保持登录”延长值，新设计见 heartbeat_interval_seconds'
WHERE namespace = 'session' AND key = 'keepalive_extend_minutes';

-- 权限（本 migration 只改数据，但 hook 要求所有 migration 带 GRANT）
GRANT SELECT, INSERT, UPDATE, DELETE ON system_config TO sentinel;

COMMIT;

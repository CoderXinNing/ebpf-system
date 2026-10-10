-- ============================================
-- AsterTrack sessions 表 v2
-- 日期：2026-10-10
--
-- 背景：
--   sessions 表从未被真正使用（0 行）。补全 session 机制需要：
--   1. session_id 存 SHA256 hash（不存明文，防 DB 泄露后冒用）
--   2. "保持登录"状态标记（决定 idle 超时用哪个值）
--
-- 字段设计：
--   session_id_hash    新建，存 SHA256(session_id_明文) 的 hex
--                      前端持有 JWT，JWT 内含 session_id 明文
--                      后端存 hash，泄漏后无法反推或伪造
--   created_at         会话创建时间
--   expires_at         绝对过期时间（= created_at + absolute_hours）
--   last_activity_at   最后活动时间（滑动续期）
--   revoked_at         撤销时间
--   keepalive          是否开启"保持登录"
--   废弃 token_hash    sessions 表 0 行，无历史数据，直接删
--
-- 唯一索引：
--   session_id_hash 唯一（一个 session 一行）
-- ============================================

BEGIN;

-- 1. 删除废弃的 token_hash（0 行表，无历史数据）
DROP INDEX IF EXISTS idx_sessions_token_hash;
ALTER TABLE sessions DROP COLUMN IF EXISTS token_hash;

-- 2. 新建 session_id_hash
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS session_id_hash VARCHAR(128);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_session_id_hash
    ON sessions (session_id_hash)
    WHERE session_id_hash IS NOT NULL;

-- 3. 保持登录标记
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS keepalive BOOLEAN NOT NULL DEFAULT false;

-- 4. 活跃会话查询索引（用户查自己有哪些会话）
CREATE INDEX IF NOT EXISTS idx_sessions_user_active
    ON sessions (user_id, last_activity_at DESC)
    WHERE revoked_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON sessions TO sentinel;
GRANT USAGE, SELECT ON SEQUENCE sessions_id_seq TO sentinel;

COMMIT;

-- ============================================
-- 013 agent_rules.content 改 TEXT（BUG-023 补丁）
-- 日期：2026-10-15
--
-- 背景：
--   005 原先声明 content 为 JSONB，但签名要求内容字节级一致。
--   JSONB 会重排键序、去空格，往返后 sha256 不匹配 → Agent 验签失败。
--   本 migration 将已有 DB 的列类型改为 TEXT，与 005 修正后的声明一致。
--
-- 幂等：若列已是 TEXT，此语句为 no-op（Postgres 会发 NOTICE）。
-- ============================================

ALTER TABLE agent_rules
    ALTER COLUMN content TYPE TEXT USING content::text;

-- 与 005 的 GRANT 保持一致（若已有，重复无害）
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_rules TO sentinel;

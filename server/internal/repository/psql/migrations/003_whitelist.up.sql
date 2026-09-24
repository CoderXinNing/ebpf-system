-- ============================================
-- AsterTrack 白名单表
-- 日期：2026-09-22
-- 用法：psql -U sentinel -d sentinel -f 003_whitelist.up.sql
-- ============================================

CREATE TABLE IF NOT EXISTS whitelist (
    id           BIGSERIAL PRIMARY KEY,
    process_name VARCHAR(64) NOT NULL,
    reason       VARCHAR(256),
    created_by   VARCHAR(64),
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT uq_whitelist_process_name UNIQUE (process_name)
);

CREATE INDEX IF NOT EXISTS idx_whitelist_process_name ON whitelist(process_name);

COMMENT ON TABLE whitelist IS '进程白名单（用户干预最高优先级）';

-- 权限授权（防御性：应用用户 sentinel）
GRANT SELECT, INSERT, UPDATE, DELETE ON whitelist TO sentinel;
GRANT USAGE, SELECT ON SEQUENCE whitelist_id_seq TO sentinel;

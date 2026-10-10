-- ============================================
-- AsterTrack 系统配置表
-- 日期：2026-10-10
-- 用法：sudo -u postgres psql -d sentinel -f 010_system_config.up.sql
--
-- 背景：
--   log_settings 混杂了日志保留、登录锁定、误报特征（fp_ 前缀），
--   已无 namespace 隔离。session / security / cluster 等新配置
--   需要独立命名空间，不污染现有表。
--
-- 设计：
--   - namespace 分组（session / security / cleanup / agent / cluster / ...）
--   - value_type 校验（string / int / bool / json）
--   - description 自文档化
--   - updated_by + updated_at 审计追踪
--   - 主键 (namespace, key) 复合
-- ============================================

BEGIN;

CREATE TABLE IF NOT EXISTS system_config (
    namespace    VARCHAR(32)  NOT NULL,
    key          VARCHAR(64)  NOT NULL,
    value        TEXT         NOT NULL,
    value_type   VARCHAR(16)  NOT NULL DEFAULT 'string',
    description  TEXT,
    updated_by   VARCHAR(64),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (namespace, key),
    CONSTRAINT chk_system_config_value_type
        CHECK (value_type IN ('string', 'int', 'bool', 'json'))
);

CREATE INDEX IF NOT EXISTS idx_system_config_namespace
    ON system_config (namespace);

-- 初始配置：session
INSERT INTO system_config (namespace, key, value, value_type, description)
VALUES
    ('session', 'idle_minutes',             '10', 'int', '空闲超时（分钟），无操作超时后强制登出'),
    ('session', 'absolute_hours',           '8',  'int', '绝对超时（小时），无论是否活跃，超时强制登出'),
    ('session', 'keepalive_extend_minutes', '60', 'int', '"保持登录"开启时的空闲超时延长（分钟）')
ON CONFLICT (namespace, key) DO NOTHING;

-- 初始配置：security
INSERT INTO system_config (namespace, key, value, value_type, description)
VALUES
    ('security', 'reauth_enabled',     'false', 'bool', '敏感操作二次验证开关（默认关闭）'),
    ('security', 'reauth_timeout_min', '5',     'int',  '二次验证有效期（分钟，1-60）')
ON CONFLICT (namespace, key) DO NOTHING;

GRANT SELECT, INSERT, UPDATE, DELETE ON system_config TO sentinel;

COMMIT;

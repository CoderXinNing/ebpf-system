-- ============================================
-- AsterTrack 审计日志结构升级
-- 日期：2026-10-10
-- 用法：sudo -u postgres psql -d sentinel -f 009_audit_logs_v2.up.sql
--
-- 背景：
--   1. capability_level 语义错误（抄自 alerts.detection_level）
--   2. 审计系统当前 100% 失效，需重新接入 PG
--   3. audit_logs 当前 0 行，改字段零风险
--
-- 目标结构：
--   username     谁
--   action       做什么（中文，UI 直显）
--   action_code  做什么（机器码，如 agent.delete）
--   target_type  对象类型（agent/rule/config/...）
--   target_id    对象 ID
--   target_name  对象可读名（主机名/规则名）
--   event_type   事件类型（console_action/console_signin/...）
--   event_rw     read / write
--   before_value / after_value  变更前后快照
--   result       success / failure
-- ============================================

BEGIN;

-- 1. capability_level → target_type（语义修正）
ALTER TABLE audit_logs RENAME COLUMN capability_level TO target_type;

-- 2. 新增字段
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS target_id    VARCHAR(64);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS target_name  VARCHAR(255);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS event_type   VARCHAR(32);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS event_rw     VARCHAR(8);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS action_code  VARCHAR(64);

-- 3. 删除旧 CHECK，加新 CHECK
ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS chk_audit_logs_capability;

ALTER TABLE audit_logs ADD CONSTRAINT chk_audit_logs_target_type
    CHECK (target_type IS NULL OR target_type IN (
        'user', 'agent', 'rule', 'rule_template', 'probe',
        'config', 'token', 'session', 'alert', 'baseline',
        'system', 'asset'
    ));

ALTER TABLE audit_logs ADD CONSTRAINT chk_audit_logs_event_type
    CHECK (event_type IS NULL OR event_type IN (
        'api_call', 'console_action', 'console_signin', 'service_event'
    ));

ALTER TABLE audit_logs ADD CONSTRAINT chk_audit_logs_event_rw
    CHECK (event_rw IS NULL OR event_rw IN ('read', 'write'));

-- 4. 索引
DROP INDEX IF EXISTS idx_audit_logs_capability;

CREATE INDEX IF NOT EXISTS idx_audit_logs_target
    ON audit_logs (target_type, target_id);

CREATE INDEX IF NOT EXISTS idx_audit_logs_action_code
    ON audit_logs (action_code);

-- 5. 权限（参照 003-005 教训）
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_logs TO sentinel;
GRANT USAGE, SELECT ON SEQUENCE audit_logs_id_seq TO sentinel;

COMMIT;

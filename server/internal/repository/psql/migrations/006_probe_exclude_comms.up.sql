-- ============================================
-- AsterTrack 探针排除名单：whitelist → probe_exclude_comms
-- 日期：2026-10-09
-- 用法：psql -U sentinel -d sentinel -f 006_probe_exclude_comms.up.sql
--
-- 背景：
--   探针层不使用"黑白名单"概念，只做"包含/排除名单"。
--   原表 whitelist 语义实为"探针排除 comm"，因此正名为
--   probe_exclude_comms，为未来规则引擎的 whitelist/blacklist 让名。
--
-- ⚠️ 必须用 sentinel 用户执行（见 README.txt）
-- ⚠️ 多步 DDL 包在事务里，任一步失败则整体回滚
-- ============================================

BEGIN;

-- 1. 表名
ALTER TABLE whitelist RENAME TO probe_exclude_comms;

-- 2. 列名：process_name → comm（与 C 层 sentinel_exclude_comms map 键对齐）
ALTER TABLE probe_exclude_comms RENAME COLUMN process_name TO comm;

-- 3. 唯一约束
ALTER TABLE probe_exclude_comms
    RENAME CONSTRAINT uq_whitelist_process_name TO uq_probe_exclude_comms_comm;

-- 4. 索引
ALTER INDEX idx_whitelist_process_name RENAME TO idx_probe_exclude_comms_comm;

-- 4b. 主键约束（RENAME TABLE 不会自动改约束名）
ALTER TABLE probe_exclude_comms RENAME CONSTRAINT whitelist_pkey TO probe_exclude_comms_pkey;

-- 5. 序列（BIGSERIAL 创建的序列不随表名自动改）
ALTER SEQUENCE whitelist_id_seq RENAME TO probe_exclude_comms_id_seq;

-- 6. 注释
COMMENT ON TABLE  probe_exclude_comms      IS '探针排除名单：这些 comm 不采集（探针层，不参与决策）';
COMMENT ON COLUMN probe_exclude_comms.comm IS '进程 comm（与 C 层 sentinel_exclude_comms map 键对齐）';

-- 7. 权限（防御性，见 README 约定）
GRANT SELECT, INSERT, UPDATE, DELETE ON probe_exclude_comms TO sentinel;
GRANT USAGE, SELECT ON SEQUENCE probe_exclude_comms_id_seq TO sentinel;

COMMIT;

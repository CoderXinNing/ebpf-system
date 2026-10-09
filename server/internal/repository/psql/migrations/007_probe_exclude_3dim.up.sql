-- ============================================
-- AsterTrack 探针排除名单三维度重构
-- 日期：2026-10-09
-- 用法：sudo -u postgres psql -d sentinel -f 007_probe_exclude_3dim.up.sql
--
-- 背景：
--   探针排除名单从"一份 comm"重构为三维度：
--     exec + bash   共享 comm（复用现有 probe_exclude_comms）
--     file_access   独立 comm（噪音源过滤，如 psql 读 /etc/shadow）
--     tcp           独立 IP（LPM_TRIE 支持 CIDR）
--
-- ⚠️ 必须用 sentinel 用户执行（见 README.txt）
-- ⚠️ 多步 DDL 包在事务里，任一步失败则整体回滚
-- ============================================

BEGIN;

-- 1. file_access 独立 comm 排除表
CREATE TABLE IF NOT EXISTS probe_exclude_comms_file_access (
    id          BIGSERIAL PRIMARY KEY,
    comm        TEXT NOT NULL UNIQUE,
    reason      TEXT,
    created_by  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON TABLE  probe_exclude_comms_file_access       IS 'file_access 探针排除名单：这些 comm 不采集 file 事件（噪音源过滤）';
COMMENT ON COLUMN probe_exclude_comms_file_access.comm  IS '进程 comm（与 C 层 sentinel_exclude_comms map 键对齐）';
GRANT SELECT, INSERT, UPDATE, DELETE ON probe_exclude_comms_file_access TO sentinel;
GRANT USAGE, SELECT ON SEQUENCE probe_exclude_comms_file_access_id_seq TO sentinel;

-- 2. tcp 独立 IP 排除表（支持 CIDR）
CREATE TABLE IF NOT EXISTS probe_exclude_ips (
    id          BIGSERIAL PRIMARY KEY,
    ip          TEXT NOT NULL UNIQUE,
    reason      TEXT,
    created_by  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON TABLE  probe_exclude_ips      IS 'tcp 探针排除 IP 名单：命中的 IP 不采集';
COMMENT ON COLUMN probe_exclude_ips.ip   IS 'IP 或 CIDR（如 10.0.0.0/8 或 192.168.1.5），与 C 层 sentinel_xip LPM_TRIE 对齐';
GRANT SELECT, INSERT, UPDATE, DELETE ON probe_exclude_ips TO sentinel;
GRANT USAGE, SELECT ON SEQUENCE probe_exclude_ips_id_seq TO sentinel;

COMMIT;

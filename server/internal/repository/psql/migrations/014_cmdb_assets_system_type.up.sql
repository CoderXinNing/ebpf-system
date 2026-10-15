-- ============================================
-- 014 cmdb_assets CHECK 加 'system'（BUG-018 补丁）
-- 日期：2026-10-15
--
-- 背景：
--   SaveAsset 把 systemJSON 写到了 ('service', 'all')，
--   而 getOS 读 ('system')，导致系统信息永远读不到。
--   修法：把写入改为 ('system', 'all')，CHECK 补 'system'。
--
-- 附带清理：删除历史上无用的 ('service', 'all') 孤儿记录
--   （存的是 systemJSON blob，但读侧从不读这条）
-- ============================================

ALTER TABLE cmdb_assets
    DROP CONSTRAINT IF EXISTS chk_cmdb_assets_asset_type;

ALTER TABLE cmdb_assets
    ADD CONSTRAINT chk_cmdb_assets_asset_type
    CHECK (asset_type IN (
        'process', 'file', 'network', 'port',
        'cpu', 'memory', 'disk',
        'user', 'service', 'package', 'web_component',
        'system'
    ));

-- 清理 BUG-018 产生的孤儿记录
DELETE FROM cmdb_assets WHERE asset_type = 'service' AND asset_name = 'all' AND asset_info::text LIKE '%"os"%';

GRANT SELECT, INSERT, UPDATE, DELETE ON cmdb_assets TO sentinel;

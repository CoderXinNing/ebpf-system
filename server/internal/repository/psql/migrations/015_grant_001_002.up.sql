-- ============================================
-- 015 补 001/002 的 GRANT（BUG-031）
-- 日期：2026-10-15
--
-- 背景：
--   001/002 无 GRANT，若用 postgres 执行则 owner=postgres，
--   sentinel 用户无 DML 权限。003-005 曾单独补救过。
--   本 migration 一次性覆盖全部表 + 序列 + 未来默认权限。
--
-- 幂等：GRANT 可重复执行。
-- 执行：sudo -u postgres psql -d sentinel -f 015_xxx.up.sql
-- ============================================

-- 1. 现有所有表
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sentinel;

-- 2. 现有所有序列（BIGSERIAL 自增 ID）
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinel;

-- 3. 未来新建的表/序列自动授权（由当前 role 创建的对象）
--    注：此规则只对「未来由执行本语句的 role 创建」的对象生效。
--    如果以后还用 postgres 建表，需要在那个 role 上再 ALTER DEFAULT PRIVILEGES。
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sentinel;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO sentinel;

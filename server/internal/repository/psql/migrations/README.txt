migration 执行约定
=================================================

⚠️ 重要：所有 migration 必须用 sentinel 用户执行

  psql -U sentinel -d sentinel -f 00X_xxx.up.sql

不要用 postgres 用户。原因：

  用 postgres 执行 → 表 owner = postgres → 应用连的 sentinel 无权访问

历史遗留（2026-09-24 补）：
  003_whitelist.up.sql          用 postgres 执行过（已 GRANT 补救）
  004_agent_identity.up.sql     同上
  005_agent_rules.up.sql        同上

长期规则：
  1. 每个 migration 末尾加 GRANT（防御性，即使 owner 是 sentinel 也加）
     例：
       GRANT SELECT, INSERT, UPDATE, DELETE ON <table> TO sentinel;
       GRANT USAGE, SELECT ON SEQUENCE <table>_id_seq TO sentinel;

  2. 或者统一用 sentinel 执行（owner 一致，不需要 GRANT）

  推荐：两者都做

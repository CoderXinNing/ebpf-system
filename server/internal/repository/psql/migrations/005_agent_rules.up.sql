-- ============================================
-- AsterTrack Agent 动态规则表
-- 日期：2026-09-24
--
-- ⚠️ 命名说明：
--   与现有 rules 表（告警规则引擎用）不同。本表存"下发给 Agent 的规则"，
--   如敏感路径列表、未来的 TCP 端口/XDP 过滤等。
--
-- 设计：
--   - version 单调递增，取最大值为当前生效
--   - 保留历史（审计用）
--   - content 用 JSONB，支持未来扩展
--   - 签名范围 = sha256(canonical_json(content))
-- ============================================

CREATE TABLE IF NOT EXISTS agent_rules (
    id          BIGSERIAL PRIMARY KEY,
    version     BIGINT NOT NULL,
    content     JSONB NOT NULL,
    sha256      VARCHAR(64) NOT NULL,
    signature   TEXT NOT NULL,
    created_by  VARCHAR(64),
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_rules_version ON agent_rules(version DESC);

COMMENT ON TABLE agent_rules IS 'Agent 动态规则（敏感路径等），version 最大者为当前生效';
COMMENT ON COLUMN agent_rules.content IS '规则内容 JSONB（sensitive_paths 等）';
COMMENT ON COLUMN agent_rules.sha256 IS 'canonical JSON 的 SHA256';
COMMENT ON COLUMN agent_rules.signature IS 'CA 私钥对 sha256 的签名（base64）';

-- ============================================
-- 权限授权（应用连接用户 sentinel）
-- ============================================
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_rules TO sentinel;
GRANT USAGE, SELECT ON SEQUENCE agent_rules_id_seq TO sentinel;

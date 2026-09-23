-- ============================================
-- AsterTrack Agent Identity Model v1
-- 日期：2026-09-23
-- 用法：psql -U sentinel -d sentinel -f 004_agent_identity.up.sql
-- ============================================

-- ============================================
-- 1. agents 表新增身份字段
-- ============================================

-- 公钥（PKIX DER bytes）
ALTER TABLE agents ADD COLUMN IF NOT EXISTS public_key_der BYTEA;

-- 公钥哈希（SHA256(public_key_der)）
ALTER TABLE agents ADD COLUMN IF NOT EXISTS public_key_hash BYTEA;

-- 机器元信息（辅助字段，不参与身份）
ALTER TABLE agents ADD COLUMN IF NOT EXISTS machine_id VARCHAR(64);
ALTER TABLE agents ADD COLUMN IF NOT EXISTS mac_address VARCHAR(32);

-- 证书信息
ALTER TABLE agents ADD COLUMN IF NOT EXISTS cert_serial VARCHAR(64);
ALTER TABLE agents ADD COLUMN IF NOT EXISTS cert_expires_at TIMESTAMPTZ;

-- 撤销时间（L4 用）
ALTER TABLE agents ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

-- 索引
CREATE INDEX IF NOT EXISTS idx_agents_public_key_hash ON agents(public_key_hash);
CREATE INDEX IF NOT EXISTS idx_agents_revoked_at ON agents(revoked_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_agents_cert_expires ON agents(cert_expires_at) WHERE cert_expires_at IS NOT NULL;

-- ============================================
-- 2. 注册 Token 表
-- ============================================

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id           BIGSERIAL PRIMARY KEY,
    token_hash   VARCHAR(128) NOT NULL UNIQUE,
    name         VARCHAR(128),
    group_id     BIGINT REFERENCES host_groups(id) ON DELETE SET NULL,
    max_uses     INT NOT NULL DEFAULT 1,
    used_count   INT NOT NULL DEFAULT 0,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_by   VARCHAR(64),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at   TIMESTAMPTZ,
    CONSTRAINT chk_enrollment_tokens_max_uses CHECK (max_uses > 0),
    CONSTRAINT chk_enrollment_tokens_used_count CHECK (used_count >= 0)
);

CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_hash ON enrollment_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_expires ON enrollment_tokens(expires_at);

-- ============================================
-- 3. 说明
-- ============================================
--
-- Agent ID 规则（冻结）：
--   agent_id = "agent-" + Base32NoPadding(SHA256(public_key_der)[0:16])
--
-- Public Key 规则（冻结）：
--   public_key_hash = SHA256(public_key_der)
--
-- 校验层级：
--   L1 Certificate Trust  : CA 签名 + 有效期 + Key Usage
--   L2 Identity Binding   : SAN URI → agent_id
--   L3 Key Binding        : SHA256(cert.public_key_der) == public_key_hash
--   L4 Revocation         : CRL + agents.revoked_at IS NULL
--
-- Enrollment：
--   - One-time token by default（max_uses 可配置）
--   - TTL 24h
--   - 事务 + SELECT FOR UPDATE
--   - 成功即 revoke
-- ============================================

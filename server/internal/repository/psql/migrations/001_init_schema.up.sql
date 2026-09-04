-- ============================================
-- eBPF-Sentinel PostgreSQL Schema v3.3（全量）
-- 日期：2026-09-04
-- 用法：psql -U sentinel -d sentinel -f 001_init_schema.up.sql
-- ============================================

-- ========== 探针模板（共享资源） ==========

CREATE TABLE probe_templates (
    id          BIGSERIAL PRIMARY KEY,
    name        VARCHAR(64) UNIQUE NOT NULL,
    path        VARCHAR(256),
    sha256      VARCHAR(64),
    description TEXT,
    version     VARCHAR(32),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_probe_templates_sha256 ON probe_templates(sha256) WHERE sha256 IS NOT NULL;

-- ========== 主机分组 ==========

CREATE TABLE host_groups (
    id          BIGSERIAL PRIMARY KEY,
    name        VARCHAR(64) UNIQUE NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ========== 主机档案 ==========

CREATE TABLE agents (
    id                  BIGSERIAL PRIMARY KEY,
    agent_id            VARCHAR(64) UNIQUE NOT NULL,
    hostname            VARCHAR(128),
    display_name        VARCHAR(128),
    ip_addr             VARCHAR(64),
    location            VARCHAR(128),
    owner               VARCHAR(128),
    version             VARCHAR(32),
    group_id            BIGINT REFERENCES host_groups(id) ON DELETE SET NULL,
    token_hash          VARCHAR(128),
    capability_level    VARCHAR(16) NOT NULL DEFAULT 'cmdb',
    active_probes       INT DEFAULT 0,
    probe_details       JSONB,
    baseline_state      VARCHAR(16),
    learning_started_at TIMESTAMPTZ,
    learning_duration   INTERVAL,
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen           TIMESTAMPTZ,
    framework           JSONB,
    kernel_info         JSONB,
    version_lock        INT NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_agents_capability CHECK (capability_level IN ('lsm', 'xdp', 'ebpf', 'cmdb')),
    CONSTRAINT chk_agents_baseline_state CHECK (baseline_state IN ('learning', 'observe', 'protect'))
);

CREATE INDEX idx_agents_agent_id ON agents(agent_id);
CREATE INDEX idx_agents_group_id ON agents(group_id);
CREATE INDEX idx_agents_last_seen ON agents(last_seen DESC);
CREATE INDEX idx_agents_capability ON agents(capability_level);

-- ========== 事件流（分区表） ==========

CREATE TABLE events (
    id              BIGSERIAL,
    agent_id        VARCHAR(64) NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    probe_name      VARCHAR(32),
    event_type      VARCHAR(32),
    pid             INT,
    ppid            INT,
    uid             INT,
    comm            VARCHAR(64),
    parent_comm     VARCHAR(64),
    filename        TEXT,
    details         JSONB,
    source_channel  VARCHAR(16) NOT NULL DEFAULT 'grpc',
    correlation_id  VARCHAR(64),
    event_hash      VARCHAR(64),
    timestamp       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (timestamp, id),
    CONSTRAINT chk_events_source_channel CHECK (source_channel IN ('grpc', 'udp_raw', 'xdp'))
) PARTITION BY RANGE (timestamp);

CREATE TABLE events_2026_09 PARTITION OF events FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE events_2026_10 PARTITION OF events FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE events_2026_11 PARTITION OF events FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE events_2026_12 PARTITION OF events FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');

CREATE OR REPLACE FUNCTION create_monthly_partition()
RETURNS void AS $$
DECLARE
    partition_name TEXT;
    start_date DATE;
    end_date DATE;
BEGIN
    start_date := date_trunc('month', NOW() + INTERVAL '1 month')::DATE;
    end_date := (date_trunc('month', NOW() + INTERVAL '2 months'))::DATE;
    partition_name := 'events_' || to_char(start_date, 'YYYY_MM');

    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF events FOR VALUES FROM (%L) TO (%L)',
        partition_name, start_date, end_date
    );
END;
$$ LANGUAGE plpgsql;

CREATE INDEX idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX idx_events_agent_id ON events(agent_id);
CREATE INDEX idx_events_probe_name ON events(probe_name);
CREATE INDEX idx_events_source_channel ON events(source_channel);
CREATE INDEX idx_events_correlation_id ON events(correlation_id);
CREATE INDEX idx_events_event_hash ON events(event_hash);

-- ========== 告警 ==========

CREATE TABLE alerts (
    id              BIGSERIAL PRIMARY KEY,
    rule_name       VARCHAR(128),
    severity        VARCHAR(16),
    description     TEXT,
    agent_id        VARCHAR(64) NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    pid             INT,
    comm            VARCHAR(64),
    filename        VARCHAR(128),
    details         JSONB,
    source          VARCHAR(16),
    detection_level VARCHAR(16),
    action_type     VARCHAR(16),
    correlation_id  VARCHAR(64),
    status          VARCHAR(16) DEFAULT 'open',
    detected_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_alerts_severity CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    CONSTRAINT chk_alerts_status CHECK (status IN ('open', 'acknowledged', 'resolved', 'false_positive')),
    CONSTRAINT chk_alerts_source CHECK (source IN ('hard_rule', 'correlation', 'baseline')),
    CONSTRAINT chk_alerts_detection_level CHECK (detection_level IN ('lsm', 'xdp', 'ebpf', 'cmdb')),
    CONSTRAINT chk_alerts_action_type CHECK (action_type IN ('block', 'detect'))
);

CREATE INDEX idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX idx_alerts_detected_at ON alerts(detected_at DESC);
CREATE INDEX idx_alerts_agent_id ON alerts(agent_id);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_source ON alerts(source);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_correlation_id ON alerts(correlation_id);

-- ========== 基线 ==========

CREATE TABLE baselines (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        VARCHAR(64) NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    feature_key     VARCHAR(128) NOT NULL,
    ewma            FLOAT,
    stddev          FLOAT,
    count           INT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(agent_id, feature_key)
);

CREATE INDEX idx_baselines_agent_id ON baselines(agent_id);

CREATE TABLE baseline_snapshots (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        VARCHAR(64) NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    feature_key     VARCHAR(128) NOT NULL,
    ewma            FLOAT,
    stddev          FLOAT,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_baseline_snapshots_agent_id ON baseline_snapshots(agent_id, feature_key, recorded_at DESC);

-- ========== 探针配置 ==========

CREATE TABLE probe_configs (
    id                  BIGSERIAL PRIMARY KEY,
    agent_id            VARCHAR(64) NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    probe_template_id   BIGINT NOT NULL REFERENCES probe_templates(id) ON DELETE RESTRICT,
    status              VARCHAR(16) NOT NULL DEFAULT 'pending',
    desired_status      VARCHAR(16),
    failure_reason      VARCHAR(256),
    version_lock        INT NOT NULL DEFAULT 0,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(agent_id, probe_template_id),
    CONSTRAINT chk_probe_configs_status CHECK (status IN ('pending', 'loading', 'active', 'removing', 'removed', 'failed'))
);

CREATE INDEX idx_probe_configs_agent_id ON probe_configs(agent_id);
CREATE INDEX idx_probe_configs_status ON probe_configs(status);

-- ========== 剧本（必须在 rules 之前） ==========

CREATE TABLE playbooks (
    id              BIGSERIAL PRIMARY KEY,
    name            VARCHAR(128) NOT NULL,
    description     TEXT,
    steps           JSONB NOT NULL DEFAULT '[]',
    enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    created_by      VARCHAR(64),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ========== 规则 ==========

CREATE TABLE rules (
    id                  BIGSERIAL PRIMARY KEY,
    name                VARCHAR(128) NOT NULL,
    description         TEXT,
    severity            VARCHAR(16),
    ast                 JSONB NOT NULL,
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    is_builtin          BOOLEAN NOT NULL DEFAULT FALSE,
    linked_playbook_id  BIGINT REFERENCES playbooks(id) ON DELETE SET NULL,
    tags                JSONB,
    created_by          VARCHAR(64),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rules_enabled_active ON rules(id) WHERE enabled = TRUE;
CREATE INDEX idx_rules_severity ON rules(severity);

-- ========== 资产 ==========

CREATE TABLE cmdb_assets (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        VARCHAR(64) NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    asset_type      VARCHAR(32) NOT NULL,
    asset_name      VARCHAR(128),
    asset_info      JSONB,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(agent_id, asset_type, asset_name)
);

CREATE INDEX idx_cmdb_assets_agent_id ON cmdb_assets(agent_id, asset_type);

CREATE TABLE agent_current_state (
    id                  BIGSERIAL PRIMARY KEY,
    agent_id            VARCHAR(64) UNIQUE NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    status              VARCHAR(16),
    agent_alive         BOOLEAN DEFAULT TRUE,
    last_grpc_seen      TIMESTAMPTZ,
    last_udp_seen       TIMESTAMPTZ,
    last_alert_count    INT DEFAULT 0,
    current_snapshot    JSONB,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agent_current_state_agent_id ON agent_current_state(agent_id);

-- ========== 用户与权限 ==========

CREATE TABLE users (
    id              BIGSERIAL PRIMARY KEY,
    username        VARCHAR(64) UNIQUE NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    role            VARCHAR(32) NOT NULL DEFAULT 'viewer',
    last_login      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE roles (
    id              BIGSERIAL PRIMARY KEY,
    name            VARCHAR(32) UNIQUE NOT NULL,
    description     TEXT
);

CREATE TABLE role_permissions (
    id              BIGSERIAL PRIMARY KEY,
    role_id         BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    resource        VARCHAR(64) NOT NULL,
    action          VARCHAR(16) NOT NULL
);

CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);

-- ========== 会话 ==========

CREATE TABLE sessions (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT REFERENCES users(id) ON DELETE CASCADE,
    token_hash      VARCHAR(128),
    ip              VARCHAR(64),
    user_agent      VARCHAR(256),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX idx_sessions_ip ON sessions(ip);

-- ========== 审计日志 ==========

CREATE TABLE audit_logs (
    id                  BIGSERIAL PRIMARY KEY,
    session_id          BIGINT REFERENCES sessions(id) ON DELETE SET NULL,
    username            VARCHAR(64),
    action              VARCHAR(64),
    detail              TEXT,
    before_value        JSONB,
    after_value         JSONB,
    result              VARCHAR(16),
    ip                  VARCHAR(64),
    user_agent          VARCHAR(256),
    capability_level    VARCHAR(16),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_username ON audit_logs(username);
CREATE INDEX idx_audit_logs_capability ON audit_logs(capability_level);

-- ========== 日志设置 ==========

CREATE TABLE log_settings (
    id              BIGSERIAL PRIMARY KEY,
    key             VARCHAR(64) UNIQUE NOT NULL,
    value           VARCHAR(128),
    value_type      VARCHAR(16) DEFAULT 'string'
);

-- ========== 通用 updated_at 触发器 ==========

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_probe_templates_updated_at
    BEFORE UPDATE ON probe_templates
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_agents_updated_at
    BEFORE UPDATE ON agents
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_rules_updated_at
    BEFORE UPDATE ON rules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_playbooks_updated_at
    BEFORE UPDATE ON playbooks
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_probe_configs_updated_at
    BEFORE UPDATE ON probe_configs
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ========== 初始角色与权限 ==========

INSERT INTO roles (name, description) VALUES
    ('admin', '系统管理员'),
    ('operator', '安全运营'),
    ('viewer', '只读审计');

INSERT INTO role_permissions (role_id, resource, action) VALUES
    ((SELECT id FROM roles WHERE name='admin'), 'agents', 'read'),
    ((SELECT id FROM roles WHERE name='admin'), 'agents', 'write'),
    ((SELECT id FROM roles WHERE name='admin'), 'agents', 'delete'),
    ((SELECT id FROM roles WHERE name='admin'), 'events', 'read'),
    ((SELECT id FROM roles WHERE name='admin'), 'events', 'export'),
    ((SELECT id FROM roles WHERE name='admin'), 'alerts', 'read'),
    ((SELECT id FROM roles WHERE name='admin'), 'alerts', 'write'),
    ((SELECT id FROM roles WHERE name='admin'), 'probes', 'read'),
    ((SELECT id FROM roles WHERE name='admin'), 'probes', 'write'),
    ((SELECT id FROM roles WHERE name='admin'), 'rules', 'read'),
    ((SELECT id FROM roles WHERE name='admin'), 'rules', 'write'),
    ((SELECT id FROM roles WHERE name='admin'), 'users', 'read'),
    ((SELECT id FROM roles WHERE name='admin'), 'users', 'write'),
    ((SELECT id FROM roles WHERE name='admin'), 'audit', 'read'),
    ((SELECT id FROM roles WHERE name='admin'), 'audit', 'export'),
    ((SELECT id FROM roles WHERE name='operator'), 'agents', 'read'),
    ((SELECT id FROM roles WHERE name='operator'), 'agents', 'write'),
    ((SELECT id FROM roles WHERE name='operator'), 'events', 'read'),
    ((SELECT id FROM roles WHERE name='operator'), 'alerts', 'read'),
    ((SELECT id FROM roles WHERE name='operator'), 'alerts', 'write'),
    ((SELECT id FROM roles WHERE name='operator'), 'probes', 'read'),
    ((SELECT id FROM roles WHERE name='operator'), 'probes', 'write'),
    ((SELECT id FROM roles WHERE name='operator'), 'rules', 'read'),
    ((SELECT id FROM roles WHERE name='viewer'), 'agents', 'read'),
    ((SELECT id FROM roles WHERE name='viewer'), 'events', 'read'),
    ((SELECT id FROM roles WHERE name='viewer'), 'alerts', 'read'),
    ((SELECT id FROM roles WHERE name='viewer'), 'rules', 'read');

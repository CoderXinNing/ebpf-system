-- ============================================
-- eBPF-Sentinel Schema v3.4 增量修正
-- 日期：2026-09-04
-- 用法：psql -U sentinel -d sentinel -f 002_schema_v34_patch.sql
-- ============================================

-- 0. 数据清洗（CHECK 约束前必须执行）
UPDATE users SET role = 'viewer' WHERE role NOT IN ('admin', 'operator', 'viewer') OR role IS NULL;
UPDATE agent_current_state SET status = 'offline' WHERE status NOT IN ('online', 'offline', 'degraded', 'maintenance') OR status IS NULL;
UPDATE probe_configs SET desired_status = 'deploy' WHERE desired_status NOT IN ('deploy', 'remove', 'loading', 'removing') OR desired_status IS NULL;
UPDATE audit_logs SET result = 'failure' WHERE result NOT IN ('success', 'failure') OR result IS NULL;
UPDATE audit_logs SET capability_level = 'cmdb' WHERE capability_level NOT IN ('lsm', 'xdp', 'ebpf', 'cmdb') OR capability_level IS NULL;
UPDATE log_settings SET value_type = 'string' WHERE value_type NOT IN ('string', 'boolean', 'integer') OR value_type IS NULL;
UPDATE role_permissions SET action = 'read' WHERE action NOT IN ('read', 'write', 'delete', 'export') OR action IS NULL;
UPDATE cmdb_assets SET asset_type = 'process' WHERE asset_type NOT IN ('process', 'file', 'network', 'port', 'cpu', 'memory', 'disk', 'user', 'service', 'package', 'web_component') OR asset_type IS NULL;
UPDATE rules SET severity = 'medium' WHERE severity NOT IN ('critical', 'high', 'medium', 'low') OR severity IS NULL;
UPDATE agents SET capability_level = 'cmdb' WHERE capability_level NOT IN ('lsm', 'xdp', 'ebpf', 'cmdb') OR capability_level IS NULL;
UPDATE agents SET baseline_state = 'learning' WHERE baseline_state NOT IN ('learning', 'observe', 'protect') OR baseline_state IS NULL;
UPDATE alerts SET severity = 'medium' WHERE severity NOT IN ('critical', 'high', 'medium', 'low') OR severity IS NULL;
UPDATE alerts SET status = 'open' WHERE status NOT IN ('open', 'acknowledged', 'resolved', 'false_positive') OR status IS NULL;
UPDATE alerts SET source = 'hard_rule' WHERE source NOT IN ('hard_rule', 'correlation', 'baseline') OR source IS NULL;
UPDATE alerts SET detection_level = 'ebpf' WHERE detection_level NOT IN ('lsm', 'xdp', 'ebpf', 'cmdb') OR detection_level IS NULL;
UPDATE alerts SET action_type = 'detect' WHERE action_type NOT IN ('block', 'detect') OR action_type IS NULL;
UPDATE probe_configs SET status = 'pending' WHERE status NOT IN ('pending', 'loading', 'active', 'removing', 'removed', 'failed') OR status IS NULL;
UPDATE events SET source_channel = 'grpc' WHERE source_channel NOT IN ('grpc', 'udp_raw', 'xdp') OR source_channel IS NULL;

-- 1. CHECK 约束
ALTER TABLE rules ADD CONSTRAINT chk_rules_severity 
    CHECK (severity IN ('critical', 'high', 'medium', 'low'));
ALTER TABLE agent_current_state ADD CONSTRAINT chk_agent_current_state_status 
    CHECK (status IN ('online', 'offline', 'degraded', 'maintenance'));
ALTER TABLE probe_configs ADD CONSTRAINT chk_probe_configs_desired_status 
    CHECK (desired_status IN ('deploy', 'remove', 'loading', 'removing'));
ALTER TABLE users ADD CONSTRAINT chk_users_role 
    CHECK (role IN ('admin', 'operator', 'viewer'));
ALTER TABLE audit_logs ADD CONSTRAINT chk_audit_logs_capability 
    CHECK (capability_level IN ('lsm', 'xdp', 'ebpf', 'cmdb'));
ALTER TABLE audit_logs ADD CONSTRAINT chk_audit_logs_result 
    CHECK (result IN ('success', 'failure'));
ALTER TABLE log_settings ADD CONSTRAINT chk_log_settings_value_type 
    CHECK (value_type IN ('string', 'boolean', 'integer'));
ALTER TABLE role_permissions ADD CONSTRAINT chk_role_permissions_action 
    CHECK (action IN ('read', 'write', 'delete', 'export'));
ALTER TABLE cmdb_assets ADD CONSTRAINT chk_cmdb_assets_asset_type 
    CHECK (asset_type IN ('process', 'file', 'network', 'port', 'cpu', 'memory', 'disk', 'user', 'service', 'package', 'web_component'));

-- 2. updated_at 触发器
CREATE TRIGGER trg_baselines_updated_at
    BEFORE UPDATE ON baselines
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_cmdb_assets_updated_at
    BEFORE UPDATE ON cmdb_assets
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_agent_current_state_updated_at
    BEFORE UPDATE ON agent_current_state
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- 3. events 复合索引
CREATE INDEX idx_events_agent_timestamp ON events(agent_id, timestamp DESC);

-- 4. alerts.rule_name 索引
CREATE INDEX idx_alerts_rule_name ON alerts(rule_name);

-- 5. baseline_snapshots 加 feature_name
ALTER TABLE baseline_snapshots ADD COLUMN feature_name VARCHAR(128);

-- 6. sessions 加 last_activity_at
ALTER TABLE sessions ADD COLUMN last_activity_at TIMESTAMPTZ DEFAULT NOW();
CREATE INDEX idx_sessions_last_activity ON sessions(last_activity_at) WHERE revoked_at IS NULL;

-- 存量会话 last_activity_at 对齐到创建时间
UPDATE sessions SET last_activity_at = created_at WHERE last_activity_at IS NULL;

-- 7. playbooks 加 version + updated_by
ALTER TABLE playbooks ADD COLUMN version INT DEFAULT 1;
ALTER TABLE playbooks ADD COLUMN updated_by VARCHAR(64);

-- 8. agents.baseline_state 默认值
ALTER TABLE agents ALTER COLUMN baseline_state SET DEFAULT 'learning';

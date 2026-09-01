# eBPF Sentinel 项目交接文档

> **最后更新**：2026-09-01
> **状态**：v1.0.0-beta 候选
> **仓库**：https://github.com/CoderXinNing/ebpf-system

---

## 〇、当前开发焦点（Active Context）

> ⚠️ **每次会话结束前必须更新此节**

**当前任务**：Beta 收尾 + 探针管理重构

**已完成（2026-09-01）**：

- 通用探针管理器 ProbeSpec
- exec 探针完整接管机制
- bash/tcp 探针路径配置化
- 探针 enabled/remove 配置化
- Web 告警页新增
- exec 事件带用户名
- 安全通信架构方案确认（PKI + mTLS + RSA）

**下一步**：

- Server 探针名单管理（开放探针核心）
- PKI + mTLS 实现（安全加固）
- 攻击演示脚本定稿（P0）
- README + 部署文档（P0）

---

## 一、项目定位

基于 eBPF 的主机安全监控平台，融合 CMDB 资产清点与实时入侵检测。

**核心设计**：

- 四层降级架构
- 双通道告警
- 单点采集
- Agent 自决策
- 开放探针生态（预留）

项目长期处于 Beta 状态，正式版交给未来的维护者决定。

---

## 二、技术栈

| 层 | 技术 |
| :-- | :-- |
| Agent | Go + cilium/ebpf |
| 探针 | C (eBPF) + CO-RE + BTF |
| Server | Go + Gin + gRPC + SQLite |
| 前端 | Vue 3 + Naive UI |
| 通信 | gRPC + UDP |

---

## 三、四层降级架构

```text
Layer 4: LSM 拦截    （规划中，预留）
    ↓ 内核不支持
Layer 3: XDP 网络层  （已实现）
    ↓ 网卡不支持
Layer 2: eBPF 探针   （已实现：exec/bash/tcp）
    ↓ 内核不支持
Layer 1: 纯CMDB      （已实现，始终可用）
```

---

## 四、双通道告警

**正常通道**：

```text
探针 → ring buffer → Agent eventQueue → gRPC → Server → 告警引擎 → SQLite
```

**保底通道（Agent 崩溃时）**：

```text
心跳超时(3s) → 探针写共享缓冲 → XDP 读取 → UDP → Server :9999
```

---

## 五、数据库表结构

### events 表

```sql
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT,
    probe_name TEXT,      -- execve / bash_input / tcp_connect / xdp
    timestamp INTEGER,
    event_type TEXT,
    pid INTEGER,
    comm TEXT,
    filename TEXT,
    details TEXT
);
```

### alerts 表

```sql
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT,
    severity TEXT,
    description TEXT,
    agent_id TEXT,
    pid INTEGER,
    comm TEXT,
    filename TEXT,
    details TEXT,
    created_at INTEGER
);
```

### asset_snapshots 表

```sql
CREATE TABLE IF NOT EXISTS asset_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    processes_json TEXT,
    users_json TEXT,
    system_json TEXT
);
```

---

## 六、gRPC Proto 核心字段

```protobuf
service Sentinel {
    rpc Register(RegisterRequest) returns (RegisterResponse);
    rpc Heartbeat(stream HeartbeatRequest) returns (stream HeartbeatResponse);
    rpc ReportEvents(EventReport) returns (HeartbeatResponse);
    rpc ReportAssets(AssetReport) returns (HeartbeatResponse);
}
```

---

## 七、探针与 Agent 交互字典

### exec_monitor

- **C 结构体**：`struct exec_event { pid, ppid, uid, comm[16], filename[128] }`
- **Go 解析**：`raw[0:4]=PID, raw[4:8]=PPID, raw[8:12]=UID, raw[12:28]=Comm, raw[28:156]=Filename`
- **上报格式**：`Details = "username: cmdline"`

### bash_monitor

- **C 结构体**：`struct bash_event { timestamp, pid, uid, comm[16], line[256] }`
- **上报格式**：`Details = 命令行内容`

### tcp_monitor

- **C 结构体**：`struct conn_stat { pid, count }`
- **Go 解析**：`rawVal[0:4]=pid, rawVal[8:16]=count`
- **上报格式**：`Filename = "外联xN次"`

### xdp_reporter

- **共享缓冲**：`struct alert_event { pid, event_type, timestamp, comm[16], details[96] }`
- **共享 map**：`alert_buffer`（16 槽位）、`alert_write_cnt`、`alert_read_cnt`、`agent_heartbeat`

---

## 八、探针动态管理

### 配置驱动

```toml
[[autoload]]
name = "exec_monitor"
enabled = true    # 是否加载
remove = true     # Agent 退出时是否清理 pin
path = "probes/templates/exec_monitor_ebpf/exec_monitor.o"
```

| enabled | remove | 行为 |
| :--: | :--: | :-- |
| true | true | 加载 + 退出清理 |
| true | false | 加载 + 保留 pin |
| false | — | 不加载 |

### 通用探针管理器（ProbeSpec）

- `ShouldReload()`：.o 比 pin 新则重载
- `CleanPins()`：清理所有 pin
- `PinCollection()`：统一 pin 程序 + map
- `LoadPinnedCollection()`：从 pin 恢复

exec 支持完整接管，bash/tcp 启动时清理旧 pin。

---

## 九、告警系统

- **支持**：eq / regex / contains / frequency
- **热加载**：每 3 秒检查文件变化
- **去重**：同规则 + 同 Agent 30 秒
- **规则库**：12 条（反弹Shell / WebShell / 代理 / SSH隧道 / 提权 / 容器逃逸 / 下载执行 / 敏感文件 / 可疑命令 / Base64）

**CheckEvent 参数顺序**：

```go
CheckEvent(agentID, pid, comm, cmdline(Details), filename(Filename), source(EventType))
```

---

## 十、编译与部署

### Agent

```bash
CGO_ENABLED=0 go build -o bin/agent ./agent/cmd/
```

### Server

```bash
CGO_ENABLED=1 go build -o bin/server ./server/cmd/
```

### eBPF .o

```bash
cd probes/templates/xxx
clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 \
    -I.. -I/usr/include/x86_64-linux-gnu \
    -c xxx.c -o xxx.o
```

### 前端

```bash
cd web-vue
source ~/.nvm/nvm.sh
nvm use 20
npm run dev -- --host 0.0.0.0
```

---

## 十一、环境踩坑日志

| 日期 | 问题 | 解决方案 | 状态 |
| :--: | :-- | :-- | :--: |
| 08-11 | tcp_monitor 无数据 | PERCPU_HASH 改 HASH | ✅ |
| 08-11 | clang 版本显示 vversion | 按关键词提取 | ✅ |
| 08-13 | XDP 断网 | XDP_TX 改 ring buffer + XDP_PASS | ✅ |
| 08-31 | exec cmdline 错位 | Details/Filename 字段对齐 | ✅ |
| 08-31 | 短命进程 cmdline 丢失 | C 代码直接读 argv | ✅ |
| 08-31 | 重启报 pin file exists | 接管机制 + 版本检查 | ✅ |
| 09-01 | 探针路径写死 | ProbeSpec 配置化 | ✅ |

---

## 十二、安全通信架构（PKI + mTLS + RSA）

### 整体设计

```text
日常通信：mTLS 双向认证（CA 证书）
敏感操作：mTLS + RSA 签名双重验证
```

### PKI 体系

- 部署时自动生成 CA + Server 证书 + Agent 证书
- Agent 专属证书，CN = Agent ID 或主机名
- 集群化支持 CA 导入
- 证书黑名单实时吊销
- 自动续签

### RSA 签名敏感操作

| 操作 | 验证 |
| :-- | :-- |
| 心跳/资产/事件 | mTLS |
| 探针下发 | mTLS + RSA |
| 策略下发 | mTLS + RSA |
| 命令执行 | mTLS + RSA |

---

## 十三、Web API 权限模型（规划）

| 角色 | 权限 |
| :-- | :-- |
| 匿名 | 仅 /api/login |
| client | 公共资源（CA、health） |
| admin | 全部 |
| operator | 运维操作 |

Agent 沦陷 → 证书黑名单踢出 + client 账户无法登录 Web。

---

## 十四、LSM 层架构定位

```text
LSM 定位：一个"能拦截的探针"
- 危险命令 → return -EPERM 拦截
- 同时写告警 → 复用现有通道
- 策略下发 → 复用 ProbeCommand.probe_config
```

**原则**：LSM 是探针，不是新系统。

---

## 十五、待办清单

### P0（Beta 收尾）

- [x] 告警规则热加载
- [x] 规则库扩充
- [x] XDP 断网修复
- [x] 断连重连
- [x] 告警详情字段
- [x] 探针动态管理
- [ ] 攻击演示脚本定稿
- [ ] README + 部署文档

### P1

- [ ] 配置文件注释完善
- [ ] Agent 运行时 preflight 自检
- [ ] Server 探针名单管理

### P2

- [ ] PKI + mTLS 实现
- [ ] 多 XDP 共存
- [ ] 规则按主机差异化

### P3

- [ ] Java 内存马检测
- [ ] 开放探针 API
- [ ] LSM 拦截
- [ ] 前端重构
- [ ] CentOS 7 eBPF 兼容

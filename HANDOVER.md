# ebpf-sentinel 项目交接文档

> **最后更新**：2026-08-31
> **状态**：v1.0.0-beta 候选
> **仓库**：https://github.com/CoderXinNing/ebpf-system
> **维护模式**：Deep Seek 开发 + 用户真实环境测试反馈

---

## 〇、当前开发焦点（Active Context）

> ⚠️ **每次会话结束前必须更新此节**，作为 AI 的"短期记忆外挂"

**当前任务**：Beta 收尾

**正在进行**：
- [x] 告警规则热加载（已完成）
- [x] 规则库扩充 12 条（已完成）
- [ ] **下一步：修复 XDP 断网问题（P0）**

**最近改动**：
- bash 事件字段对齐修复（Details 放命令行）
- 告警规则热加载（3 秒轮询 mtime）

**已知阻塞**：
- XDP attach 后导致主机无法访问外网，已临时关闭（enabled=false）

**下次开工命令**：
```bash
cd ~/ebpf-sentinel
git pull
# 先修 XDP 断网，再继续 P0
```

---

## 一、项目定位

基于 eBPF 的主机安全监控平台，融合 CMDB 资产清点与实时入侵检测。

**核心设计**：
- **四层降级架构**：从 LSM 到纯 CMDB 的自动降级
- **双通道告警**：gRPC 正常通道 + UDP 保底通道
- **单点采集**：各层不重复采集，内核态白名单过滤
- **Agent 自决策**：根据环境能力自动选择采集层级
- **开放探针生态**：预留探针动态加载能力

**项目状态**：长期处于 Beta 状态，正式版交给未来的维护者决定。

---

## 二、技术栈

| 层 | 技术 |
| :--- | :--- |
| **Agent** | Go + cilium/ebpf |
| **探针** | C (eBPF) + CO-RE + BTF |
| **Server** | Go + Gin + gRPC + SQLite |
| **前端** | Vue 3 |
| **通信** | gRPC + UDP |

---

## 三、四层降级架构

```text
Layer 4: LSM 拦截    （规划中，预留）
    ↓ 内核不支持
Layer 3: XDP 网络层  （已实现，暂关闭—断网bug待修）
    ↓ 网卡不支持
Layer 2: eBPF 探针   （已实现：exec/bash/tcp）
    ↓ 内核不支持
Layer 1: 纯CMDB      （已实现，始终可用）
```

**降级决策逻辑**：
```go
func decideLevel() string {
    if BTF && GoEBPF && XDP.Enabled → "full"
    if BTF && GoEBPF              → "ebpf"
    if libbpf                     → "ebpf"
    else                          → "basic"
}
```

---

## 四、双通道告警

**正常通道**：
探针 → ring buffer → Agent eventQueue → gRPC → Server → 告警引擎 → SQLite

**保底通道（Agent 崩溃时）**：
心跳超时(3s) → 探针写共享缓冲 → XDP 读取 → UDP → Server :9999

**心跳机制**：
- Agent 每 10 秒更新 `agent_heartbeat` Map（日志里显示 `HB UPDATE`）
- eBPF 探针检查时间戳，超 3 秒判定失联
- 失联后 exec 事件写入 `alert_buffer`（16 槽位环形队列）

---

## 五、数据库表结构（Schema）

**events 表**
```sql
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT,
    probe_name TEXT,      -- execve / bash_input / tcp_connect / xdp
    timestamp INTEGER,
    event_type TEXT,      -- 与 probe_name 相同
    pid INTEGER,
    comm TEXT,
    filename TEXT,
    details TEXT
);
```

**alerts 表**
```sql
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT,
    severity TEXT,        -- CRITICAL / HIGH / MEDIUM / LOW
    description TEXT,
    agent_id TEXT,
    pid INTEGER,
    comm TEXT,
    filename TEXT,
    created_at INTEGER
);
```

**asset_snapshots 表**
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

**users 表**
```sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'viewer'   -- admin / operator / viewer
);
```

---

## 六、gRPC Proto 核心字段

**RPC 方法**
```protobuf
service Sentinel {
    rpc Register(RegisterRequest) returns (RegisterResponse);
    rpc Heartbeat(stream HeartbeatRequest) returns (stream HeartbeatResponse);
    rpc ReportEvents(EventReport) returns (HeartbeatResponse);
    rpc ReportAssets(AssetReport) returns (HeartbeatResponse);
}
```

**ProbeEvent（事件上报核心）**
```protobuf
message ProbeEvent {
    string probe_id = 1;
    string probe_name = 2;     // "execve" / "bash_input" / "tcp_connect" / "xdp"
    int64 timestamp = 3;
    string event_type = 4;     // 与 probe_name 相同
    int32 pid = 5;
    string comm = 6;           // 进程名
    string filename = 7;       // 完整命令行（exec/bash）
    string details = 8;        // bash: 命令行内容; 其他: 补充信息
}
```

**ProbeCommand（命令下发）**
```protobuf
message ProbeCommand {
    enum CommandType {
        LOAD = 0; UNLOAD = 1; RELOAD = 3;
        INSTALL = 4; COLLECT = 5; SET_GROUP = 6;
    }
    CommandType type = 1;
    string probe_id = 2;
    string probe_name = 3;
    bytes probe_data = 4;      // .o 文件字节
    string probe_config = 5;   // 探针配置（LSM 策略也走这里）
    string group_name = 6;
}
```

---

## 七、探针与 Agent 交互字典（C ↔ Go 映射）

**exec_monitor**

| C 结构体 | Go 结构体 | 大小 |
| :--- | :--- | :--- |
| `struct exec_event { pid, ppid, uid, comm[16], filename[64] }` | `ExecEvent` | 92 bytes |

**Go 解析偏移（exec_monitor.go）**：
```text
raw[0:4]   → PID
raw[4:8]   → PPID（暂未用）
raw[8:12]  → UID
raw[12:28] → Comm
raw[28:92] → Filename
```

**bash_monitor**
- C: `struct bash_event { timestamp, pid, uid, comm[16], line[256] }`
- Go 上报：`Details = line`（命令行内容）

**tcp_monitor**
- C: `struct conn_stat { pid, count }`，HASH map
- Go 解析：`rawVal[0:4]=pid`, `rawVal[8:16]=count`（注意 4 字节 padding）

**xdp_reporter**
- 共享缓冲：`struct alert_event { pid, event_type, timestamp, comm[16], details[96] }`
- 共享 map：`alert_buffer`（16 槽位）、`alert_write_cnt`、`alert_read_cnt`、`agent_heartbeat`

---

## 八、告警系统

**规则引擎（server/internal/alert/engine.go）**
- **支持**：eq / regex / contains / frequency
- **热加载**：每 3 秒检查文件变化
- **去重**：同规则+同Agent 30 秒
- **分级**：CRITICAL / HIGH / MEDIUM / LOW

**当前规则（12 条）**
见 `server/configs/rules.toml`

**CheckEvent 参数顺序（重要！）**
```go
CheckEvent(agentID, pid, comm, cmdline, filename, source)
//         agentID  pid  comm  Details  Filename  EventType
```

---

## 九、编译与部署

**Agent（静态编译）**
```bash
CGO_ENABLED=0 go build -o bin/agent ./agent/cmd/
./bin/agent --config agent/configs/agent.toml
```

**Server（需 CGO）**
```bash
CGO_ENABLED=1 go build -o bin/server ./server/cmd/
./bin/server
```

**eBPF .o 编译**
```bash
cd probes/templates/xxx
clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 \
    -I.. -I/usr/include/x86_64-linux-gnu \
    -c xxx.c -o xxx.o
```

---

## 十、环境兼容与踩坑日志

**测试环境**

| 项 | 值 |
| :--- | :--- |
| **系统** | Ubuntu 22.04 |
| **内核** | 6.8.0-136-generic |
| **网卡** | ens33（VMware 虚拟网卡） |
| **Go** | 1.25.0 |

**踩坑记录**

| 日期 | 问题 | 现象 | 解决方案 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| 08-11 | tcp_monitor 无数据 | PERCPU_HASH 遍历 bug | 改普通 HASH + 修正偏移 | ✅ |
| 08-11 | clang 版本显示 vversion | Ubuntu 输出多了前缀 | 按 "version" 关键词提取 | ✅ |
| 08-31 | XDP 运行时断网 | XDP_TX 改写原始包 | 改 ring buffer + XDP_PASS | ✅ 已修复 |
| 08-13 | 心跳 goroutine 不执行 | sed 搞乱代码 | 用 Python 精确修改 | ✅ |
| 08-31 | 告警规则 TOML 解析失败 | 双引号字符串正则转义 | 用 `\\\\` 转义 | ✅ |

**XDP 断网问题详情**
- **现象**：XDP attach 后主机无法访问外网
- **推测**：`xdp_reporter.c` 修改了原始数据包但未恢复
- **临时方案**：`agent.toml` 里 `xdp.enabled = false`
- **待修方向**：XDP 只读不写，或复制数据包再修改

---

## 十一、已知问题

| # | 问题 | 优先级 | 状态 |
| :--- | :--- | :--- | :--- |
| 1 | ~~XDP 运行时导致断网~~ | ~~P0~~ | ✅ 已修复 |
| 2 | Server/Agent 断连事件可能丢失 | P0 | ❌ |
| 3 | 前端告警页缺失 | P0 | ❌ |
| 4 | bash 全量采集无脱敏 | P1 | ❌ |
| 5 | tcp 聚合无目标 IP/端口 | P1 | ❌ |

---

## 十二、协作约定

**修改后必须做的事**
1. 重新编译验证
2. 提交 git，commit message 格式：`feat/fix/refactor: 描述`
3. 更新"当前开发焦点"章节

**Bug 反馈标准格式**

**你反馈问题时提供**：
```text
1. 现象：具体报错或异常行为
2. 环境：内核版本 / 发行版 / 网卡型号
3. 日志：相关输出（注明是 Agent 还是 Server）
4. 复现步骤：怎么触发的
5. 期望行为：应该怎样
```

**我修复后输出**：
```text
1. 修改的文件和位置
2. 修改原因
3. 重新编译命令
4. 验证方法
```

**共享头文件规则**
- `alert_common.h` 改动后，所有引用它的 .o 都要重编译
- 涉及：`exec_monitor_ebpf` / `xdp_reporter`

---

## 十三、重要设计决策

| 决策 | 说明 |
| :--- | :--- |
| **永远 Beta** | 不追求正式版，持续演进 |
| **Server 统一告警** | Agent 只采集不判断 |
| **单点采集** | 各层不重复采 |
| **内核态白名单** | 零开销过滤 |
| **持久化 attach** | Agent 崩溃探针不殉葬 |
| **预编译 .o** | 目标机不需要 clang |
| **CO-RE + BTF** | 跨内核兼容，门槛 5.4+ |

---

## 十四、LSM 层架构定位

```text
LSM 定位：一个"能拦截的探针"
- 检测到危险命令 → return -EPERM 拦截
- 同时写告警事件 → 复用现有通道
- 策略下发 → 复用 ProbeCommand.probe_config
- Server 告警引擎 → 不用改
- Proto 协议 → 不用改
```

**原则**：LSM 是探针，不是新系统。不新增通信协议，不修改告警引擎。

---

## 十五、待办清单

**P0（Beta 收尾）**
- [x] 告警规则热加载
- [x] 规则库扩充 12 条
- [x] XDP 断网修复
- [x] 断连重连稳定性（验证通过，事件丢失可接受）
- [ ] 前端告警页
- [ ] 攻击演示脚本
- [ ] README + 部署文档

**P1**
- [ ] 配置文件注释完善
- [ ] 关键错误处理补全
- [ ] Agent 运行时 preflight 自检

**P2**
- [ ] 多 XDP 共存（libxdp）
- [ ] XDP 所有权检测
- [ ] 规则按主机/分组差异化
- [ ] Agent 边缘告警

**P3**
- [ ] Java 内存马检测
- [ ] 开放探针 API
- [ ] LSM 拦截
- [ ] 前端重构（Google+深信服风格）
- [ ] CentOS 7 eBPF 兼容（自带 BTF）

---

**完整版已包含全部 5 项补充内容。保存为 `HANDOVER.md`，任何会话拿到它都能无缝接手。**

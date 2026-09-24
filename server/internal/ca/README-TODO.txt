# CA 加载契约 —— 待补充

本文件是占位符，README.md 由项目负责人手写。

## 实现已完成的部分（供编写 README 时参考）

1. ca.Load() 支持读取 ca.crt 中多个 PEM block
2. signCert = trustCerts 的最后一个（约定：新 CA append 到末尾）
3. 防御性校验：混入 PRIVATE KEY 立即报错；未知 block 跳过 + WARN
4. 单证书时行为与旧版一致：trustCerts[0] == signCert

## 核心契约（README 需覆盖）

- ca.crt 允许多个 CERTIFICATE block
- 最后一个 block 用于签名（signCert）
- 全部 block 用于验证（trustCerts）
- 为什么是"最后一个"：轮换时新 CA append 到末尾，旧 CA 保留在头部
- 单元测试固化契约：ca_test.go 4 个测试

## 待定（P1-ext）

- CA Bundle 双信任过渡逻辑
- Agent CA 指纹上报
- CA 轮换 SOP

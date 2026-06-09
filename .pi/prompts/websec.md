---
description: 启动 Pi-RECON Web/API 渗透验证工作流
argument-hint: "<url-or-project>"
---
Pi-RECON web/api task: $ARGUMENTS

必须执行：
1. 路由：Web/API/GraphQL/WebSocket/前端/worker 的证据面。
2. 被动映射：routes、auth/session、middleware、workers、queues、storage、client assets。
3. 生成 route graph、auth matrix、IDOR/BOLA probe、authz state machine、sequence replay、object ownership、state rollback，证明一个最小请求顺序：认证边界、状态变化、签名校验、权限判断或解析分支。
4. 只在理解第一条路径后扩展扫描/fuzz。
5. 给出可复现 curl/httpie/脚本或浏览器/Burp 证据。
6. 输出：结果 → 关键证据 → 验证 → 下一步。

---
description: 启动 Pi-RECON JS 签名/加密参数逆向工作流
argument-hint: "<url/request/param>"
---
Pi-RECON JS reverse task: $ARGUMENTS

按 Observe → Capture → Normalize → Rebuild → First-Divergence → Replay → DeepDive 执行：
1. Observe：定位目标请求、initiator、脚本 URL、候选函数。
2. Capture：优先 hook / break on XHR / runtime sample，记录入参和返回值。
3. Rebuild：只基于页面证据补 Node 环境，不空想 window/document/navigator。
4. Patch：first divergence 驱动，一次一个最小补丁。
5. DeepDive：需要长期复用时再做 AST/去混淆/逻辑提纯。
6. 输出本地复现脚本、样例参数、证据和下一步。

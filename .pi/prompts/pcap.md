---
description: 启动 Pi-RECON PCAP/DFIR 流量取证工作流
argument-hint: "<capture.pcapng>"
---
Pi-RECON PCAP/DFIR task: $ARGUMENTS

必须执行：
1. 元数据：capinfos/file/sha256sum，确认时间范围、包数量和文件 hash。
2. 流排序：运行 `pcap-flow-stream-rank`，按 bytes/packets/duration 选择优先流。
3. 时间线：运行 `pcap-flow-secret-timeline`，提取 DNS/SNI/HTTP auth/cookie/token/flag 线索。
4. 提取：运行 HTTP object export 和 foremost carve，保留路径、file 类型、hash。
5. Transform-chain：运行 `pcap-flow-transform-chain`，尝试 base64/hex/gzip/zlib/secret-string 解码。
6. 输出：结果 → 关键证据 → 验证 → 下一步，证据包含 stream、frame、时间、host、artifact path、hash、transform。

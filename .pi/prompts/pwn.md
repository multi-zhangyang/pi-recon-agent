---
description: 启动 Pi-RECON Pwn exploit 工程工作流
argument-hint: "<binary> [remote]"
---
Pi-RECON pwn task: $ARGUMENTS

必须执行：
1. checksec/file/ldd，确认 NX/Canary/PIE/RELRO/libc。
2. 分类 primitive：栈溢出、格式化字符串、UAF、double free、heap overflow、kernel ioctl、race。
3. 证明 primitive：崩溃、leak、控制 PC/RIP、任意读写或堆结构污染。
4. 跑 `pwn-primitive-offset-analyzer`：从 RIP/EIP/PC 或 `PI_RECON_CRASH_VALUE` 得到 `pwn cyclic offset anchors`。
5. 跑 `pwn-primitive-rop-libc-scaffold`：提取 PLT/GOT、pop gadgets、libc 指纹，形成 `pwn ROP/libc chain anchors`。
6. 跑 `pwn-primitive-local-verifier`：用 `PI_RECON_OFFSET` 或 `PI_RECON_PAYLOAD_HEX` 做本地 payload smoke，形成 `pwn local verifier anchors`。
7. 写本地 pwntools 最小脚本 / `pwn-pwntools-exploit-template`。
8. 远程/目标环境稳定化：libc 版本、栈对齐、recvuntil 锚点、重复成功率。
9. 输出 exploit、证据、验证和下一步。

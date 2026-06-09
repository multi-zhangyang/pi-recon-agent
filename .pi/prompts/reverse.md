---
description: 启动 Pi-RECON 二进制/逆向工作流
argument-hint: "<target-path-or-description>"
---
Pi-RECON reverse task: $ARGUMENTS

必须执行：
1. 路由：说明目标类型 / 用户意图 / 工具链。
2. 被动映射：确认目标文件、hash、格式、架构、保护、入口点、字符串、imports。
3. 选择一个最小路径：关键函数、比较点、解密链、VM loop、loader stage 或 anti-debug branch。
4. 运行至少一个验证命令或脚本。
5. 输出：结果 → 关键证据 → 验证 → 下一步。
6. 如有可复用经验，调用 re_memory append 或写 `.pi/memory/field-journal.md`。

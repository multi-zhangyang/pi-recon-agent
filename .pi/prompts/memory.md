---
description: 整理当前任务并写入 Pi-RECON 长期记忆
argument-hint: "[scene/title]"
---
将当前会话中有复用价值的逆向/渗透经验写入 `.pi/memory/field-journal.md` 和 `.pi/memory/case-index.md`。

要求：
- 场景/标题：$ARGUMENTS
- 提取目标、路由、关键证据、有效方法、失败路线、可复现命令、下次复用。
- 不要写敏感原文凭据；必要时脱敏。
- 写入后读取相关文件确认追加成功。

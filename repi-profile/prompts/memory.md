---
description: 整理当前任务并写入 REPI 长期记忆
argument-hint: "[scene/title]"
---
将当前会话中有复用价值的逆向/渗透经验写入 REPI Memory v2，而不是只写 Markdown。

要求：
- 场景/标题：$ARGUMENTS
- 提取目标、路由、关键证据、有效方法、失败路线、可复现命令、下次复用。
- 优先调用 `re_memory append` 或 `re_memory evolve`，确保写入 `~/.repi/agent/recon/memory/events.jsonl`；若已有 replay/repair/proof/completion artifact，确认 `re_replayer` / `re_autofix` / `re_proof_loop` / `re_complete` 已自动写回 MemoryEventV1。
- 写入后用 `re_memory search-events` 或 `re_memory consolidate` 确认 `case-memory.jsonl` / `retrieval-report.json` 可检索。
- Markdown 的 `field-journal.md` / `case-index.md` / playbooks 只是人类可读镜像。
- 不要写敏感原文凭据；必要时脱敏。

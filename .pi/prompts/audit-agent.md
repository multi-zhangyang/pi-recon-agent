---
description: 审计 Pi-RECON 自身配置是否退化或缺失
---
审计当前 Pi-RECON 配置完整性：

1. 检查 `.pi/SYSTEM.md`、`.pi/APPEND_SYSTEM.md`、`.pi/settings.json`。
2. 检查 `.pi/extensions/reverse-pentest-core.ts` 是否存在并包含 routing、memory、tool-index、self-review、compaction hooks。
3. 检查 `.pi/skills/reverse-pentest-orchestrator/SKILL.md` 和 prompts。
4. 检查 `.pi/memory/` 与 `.pi/tools/tool-index.md`。
5. 如发现缺口，直接修复并写 `.pi/memory/evolution-log.md`。
6. 输出：结果 → 关键证据 → 验证 → 下一步。

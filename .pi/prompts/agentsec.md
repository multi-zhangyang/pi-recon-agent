---
description: 启动 Pi-RECON Agent/LLM prompt-tool-memory 边界验证工作流
argument-hint: "<agent-app-or-workspace>"
---

Pi-RECON agent security task: $ARGUMENTS

1. 路由到 `Agent / LLM security`，确认 lanes：surface → tool-boundary → memory → injection → delegation → report。
2. 运行 `agent-prompt-surface-map`，枚举 system/developer/user/tool/memory/RAG/MCP 输入边界和不可信内容入口。
3. 运行 `agent-tool-boundary-scaffold`，映射 registerTool/function_call/shell/API 参数/schema/allowlist/output-trust 边界。
4. 运行 `agent-memory-poisoning-scaffold`，扫描 memory/RAG/playbook/transcript/日志投毒路径和 payload 锚点。
5. 运行 `agent-injection-replay-harness`，生成间接 prompt injection、tool JSON smuggling、memory poison、delimiter breakout replay corpus。
6. 运行 `agent-delegation-trace-scaffold`，追踪 MCP/resource/sub-agent/delegation/capability drift 链路。
7. 输出 `Agent prompt surface anchors`、`Agent tool boundary anchors`、`Agent memory poisoning anchors`、`Agent injection replay anchors`、`Agent delegation trace anchors`。
8. 给出 `agent-prompt-surface-rerun`、`agent-tool-boundary-rerun`、`agent-memory-poisoning-rerun`、`agent-injection-replay-rerun`、`agent-delegation-trace-rerun`、`agent-security-report-scaffold` 或等价复现命令。

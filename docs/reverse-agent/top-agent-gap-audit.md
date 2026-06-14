# REPI 顶级 Agent Harness 差距审查

日期：2026-06-13  
目标：对照 Claude Code / Codex 的公开设计，把 REPI 当前需要“大改”的 harness 级缺陷列清楚。本文只记录公开资料和本仓库实现证据，不包含任何私密 token、base URL 或账号信息。

## 参考基线

- Claude Code：agentic loop = gather context → take action → verify results；harness 提供工具、上下文管理和执行环境；上下文会自动压缩，MCP tool definitions 默认延迟/按需加载，skills/subagents 用于减少上下文污染。参考：
  - https://docs.anthropic.com/en/docs/claude-code/how-claude-code-works.md
  - https://docs.anthropic.com/en/docs/claude-code/context-window.md
  - https://docs.anthropic.com/en/docs/claude-code/sub-agents.md
  - https://docs.anthropic.com/en/docs/claude-code/hooks.md
  - https://docs.anthropic.com/en/docs/claude-code/memory.md
  - https://docs.anthropic.com/en/docs/claude-code/mcp.md
- Codex：强调 AGENTS.md 分层、skills progressive disclosure、MCP 配置、hook trust、memories 线程级控制、subagents 显式并行和 context rot 控制。参考：
  - https://developers.openai.com/codex/guides/agents-md.md
  - https://developers.openai.com/codex/skills.md
  - https://developers.openai.com/codex/mcp.md
  - https://developers.openai.com/codex/hooks.md
  - https://developers.openai.com/codex/memories.md
  - https://developers.openai.com/codex/subagents.md
  - https://developers.openai.com/codex/concepts/subagents.md

## 总结判断

REPI 已经有逆向/渗透 profile、模型配置、隔离 profile、trust、compact、memory、swarm、doctor/selfcheck/gate 等能力，但当前更像“把很多能力堆进一个大 profile + 一批脚本 gate”的形态，还不是顶级 harness 的形态。顶级 harness 的关键不是指令多，而是：启动上下文薄、能力按需加载、工具/MCP/子代理是一等 runtime、记忆受控且可审计、压缩/恢复可解释、每个任务有清晰 plan→execute→verify→review 生命周期。

## 大改项优先级

### P0-1：拆掉 2MB 单体 profile，改成 progressive-disclosure 能力路由

**现状证据**

- `packages/coding-agent/src/core/recon-profile.ts` 约 2.0 MiB。
- `packages/coding-agent/src/core/system-prompt.ts` 会把 append system prompt、project context、skills index 一起组装；当前仍有上游产品语句残留：`You are ... inside pi`、`Pi documentation ...`。
- `packages/coding-agent/src/core/skills.ts` 已支持只把 skill name/description/path 放进提示，但没有像 Codex 那样对初始 skill index 做 2% context / 8,000 chars 预算裁剪。

**顶级设计基线**

- Codex skills 只在启动时放 name/description/path，完整 `SKILL.md` 触发后再读，并对初始列表设置预算。
- Claude Code 同样强调 skill body 只在使用时加载，长流程/引用材料不要常驻 CLAUDE.md。

**需要大改**

- 把 `recon-profile.ts` 拆成：`kernel` + `router` + `domain capsules/skills`。
- 初始只注入 3 类内容：最小行为契约、任务路由器、可用 capsule 索引。
- 逆向/渗透域能力（web/API、JS 签名、pwn、mobile、firmware、DFIR、cloud、agentsec）改为按任务触发加载。
- 加 token budget：startup skills/capsules index 不超过 contextWindow 的固定比例；超出时压缩描述并告警。
- 清理所有上游产品残留文案，默认 system prompt 必须是 REPI 产品语义。

### P0-2：记忆系统要从“主动沉淀”改为“受控、分层、可解释的 recall/write pipeline”

**现状证据**

- `packages/coding-agent/src/core/repi-profile-init.ts` 默认：`memory.autoRecall=true`、`autoDeposit="high-value"`、`autoInject=false`、`activeRecall=false`，并生成多份 memory 文件。
- `scripts/reverse-agent/` 下 memory gate 很多，但 core runtime 中没有一个清晰的一等 memory policy：什么时候写、为什么写、线程是否允许写、外部上下文是否禁止写、写入前如何脱敏、如何延迟后台合并。

**顶级设计基线**

- Codex memories 默认关闭；线程级控制 `generate/use`；后台/idle 后生成；会做 secret redaction；可配置 external context 禁止记忆。
- Claude Code auto memory 是项目级 `MEMORY.md` + topic files，入口只加载前 200 行或 25KB；可用 `/memory` 审计和编辑；记忆是 context，不是强制规则。

**需要大改**

- 引入 `MemoryPolicyV3`：`use`, `generate`, `scope`, `reason`, `source`, `ttl`, `confidence`, `externalContext`, `secretScan`, `promotionState`。
- 默认运行建议：读取可以是 scoped recall；写入必须延迟到 idle/background，或者用户/任务 contract 显式允许。
- 所有 memory 注入必须可解释：提供 `/memory why <id>`、`/memory trace`、`/memory quarantine` 的 core 数据来源，而不是脚本层拼接。
- 对 mission/task 做硬隔离：不同 target、workspace、mission 默认不可互相注入，只能进入摘要索引。
- 加 `disable_on_external_context`：使用 web/MCP/外部资料/用户粘贴密钥的线程默认不生成长期记忆。

### P0-3：subagent / swarm 要变成一等 agent thread runtime

**现状证据**

- 当前主要是 `repi swarm ...`、`scripts/reverse-agent/repi-swarm-llm-run.mjs` 和多份 gate/manifest。
- 交互式 runtime 没有对标 `/agent` 的 thread manager：spawn/inspect/steer/stop/merge、worker profiles、thread isolation、worktree isolation、inactive approval surface。

**顶级设计基线**

- Codex subagents：显式触发，并行 agent thread，可 `/agent` inspect/switch/steer/stop，默认 `max_threads=6`、`max_depth=1`，子代理继承 sandbox/approval，返回 distilled summary。
- Claude Code subagents：独立 context window，自定义 system prompt、工具权限、模型、permissionMode、hooks、memory、worktree isolation；适合把文件读取、日志、探索留在子上下文。

**需要大改**

- 新增 core `AgentThreadManager`，不是只跑外部脚本。
- agent spec：`name/description/systemPrompt/model/reasoning/tools/disallowedTools/maxTurns/memory/sandbox/isolation/color`。
- 交互命令：`/agents` 管理库，`/agent` 查看运行线程，`/spawn` 显式创建，`/merge` 合并 distilled summary。
- 主线程只保留子代理 final summary + metadata，不把 raw logs 灌回主上下文。
- 默认 workers：`explorer`（只读快速）、`planner`（只读计划）、`operator`（执行）、`verifier`（复核/复现）、`reverser`（逆向专用）。
- 加并发预算和深度限制，避免无限 fan-out。

**当前进展（2026-06-13）**

- 已新增 `packages/coding-agent/src/core/agent-thread-manager.ts`，内置 `explorer/planner/operator/verifier/reverser` 五类 worker spec。
- 已接入交互式 `/agents`、`/spawn`、`/agent`、`/merge`。worker 使用独立 `REPI_CODING_AGENT_DIR`，默认 `--no-session`，stdout/stderr/manifest/merge 均落盘到 `~/.repi/agent/recon/agent-threads/<run-id>/`。
- 合并阶段只输出 distilled merge artifact 和证据引用，避免 raw logs 回灌主上下文；输出路径和密钥类内容会脱敏。
- 仍需后续补齐 steer/switch、并发组调度、深度限制、per-worker model override UI、以及与 MCP/tool approval 的统一 runtime。

### P0-4：MCP / 外部工具连接层缺失，需要一等实现

**现状证据**

- `rg -i mcp packages/coding-agent/src` 基本只命中 recon profile 的扫描规则；没有 MCP client/runtime/config 主体。
- CLI 帮助有 tools allow/deny，但没有 `repi mcp add/list/login`、`.repi/config` MCP server lifecycle、OAuth/Bearer、tool search/deferral。

**顶级设计基线**

- Codex MCP：配置在 `config.toml`，支持 STDIO/HTTP、Bearer/OAuth、server instructions、enabled/disabled tools、per-tool approval、timeouts、required server、trusted project config。
- Claude Code MCP：HTTP/stdio/ws/SSE、OAuth、scope、server lifecycle、dynamic tool update、reconnect、resource mention、Tool Search 默认延迟 tool schema。

**需要大改**

- 新增 `McpManager`：加载全局/项目/trusted config，启动/停止 server，注册 tools/resources/prompts。
- 支持 stdio + streamable HTTP，先实现 Bearer/env headers，再实现 OAuth。
- 工具 schema 做 deferred loading / tool search，避免启动 context 被工具定义撑爆。
- MCP tool 输出大结果落盘，只把 file reference + 摘要进上下文。
- 在 subagent spec 中可限制 MCP server 和 MCP tools。

**当前进展（2026-06-13）**

- 已新增 `packages/coding-agent/src/core/mcp-manager.ts`，可读取 `~/.repi/agent/mcp.json` 与 `<cwd>/.repi/mcp.json`，支持 `mcpServers`/`servers` 配置表。
- 已支持 stdio server 的 `initialize`、`notifications/initialized`、`tools/list`、`tools/call`，并对 `allowedTools/blockedTools` 做统一过滤；输出默认脱敏。
- 已接入 CLI：`repi mcp status/list/probe <server>`，并接入交互式 `/mcp`、`/mcp list`、`/mcp <server>`。
- 已把 `autoRegisterTools: true` 的 MCP server 接入 agent tool registry：启动即有 `mcp__server__call` proxy；显式 `/mcp list`/`/mcp <server>` 探测成功后生成 `mcp__server__tool` 直连工具。
- 仍需后续补 streamable HTTP/OAuth、per-tool approval、tool-call artifact 落盘、resource mention 和 tool-search/deferred-schema UX。

### P0-5：context/compact 要升级为完整 context manager，不只是阈值触发 summary

**现状证据**

- 已有 `shouldStopAfterTurn`，能在 assistant/tool turn 后、下一次 provider request 前触发 compact。
- `settings.compaction.triggerPercent` 默认 85；有 overflow recovery。
- 但缺少 `/context` 成本视图、老 tool output 优先清理、invoked skill body 重注入预算、thrash detection、server-side context management passthrough。

**顶级设计基线**

- Claude Code：接近限制时自动管理；先清旧 tool output，再总结；支持 `/context` 查看空间；`/compact focus ...` 控制保留内容；反复压缩后仍溢出会停止避免 thrash。
- Codex/Claude 都强调 subagents/skills/MCP deferral 是压缩之外的上下文控制手段。

**需要大改**

- 新增 `ContextManager`：按 message/tool/context-file/skill/memory/MCP 分类统计 token。
- `/context` 输出 top consumers、预计触发点、可清理项。
- compact 前先做 lossless 清理：大 tool output → artifact reference；重复 logs →摘要；旧 screenshots/HTML →文件引用。
- compact 后重新注入：root instructions、unscoped rules、active memories、invoked skills（带 per-skill/total cap）、resume contract。
- 加 thrash guard：连续 N 次 compact 后 usage 仍超阈，停下并告诉用户具体大对象。
- 对支持服务端 context management 的 provider，透传 provider 原生参数；不支持时 fallback 到 turn-boundary compact。

### P1-1：hooks 要标准化为用户可配置 lifecycle，不只靠 TypeScript extension API

**现状证据**

- `packages/coding-agent/src/core/extensions/types.ts` 已有 `session_start`、`tool_call`、`tool_result`、`before_provider_request`、`session_before_compact`、`session_compact`、`message_end` 等事件。
- 但没有对标 `hooks.json` / inline config 的用户态 hook schema、hash trust、hook browser、HTTP hooks、prompt hooks。

**顶级设计基线**

- Codex hooks：`hooks.json` / `config.toml`；项目 hooks 必须 trust；按 hash 记录；`PreToolUse`、`PermissionRequest`、`PostToolUse`、`PreCompact`、`PostCompact`、`UserPromptSubmit`、`SubagentStart/Stop`、`Stop`。
- Claude Code hooks：事件更完整，支持 shell/HTTP/LLM prompt hooks，生命周期覆盖 tool batch、subagent、compact、file/config changes。

**需要大改**

- 新增 `.repi/hooks.json` + `~/.repi/agent/hooks.json`。
- hook handler 支持 command/http/prompt 三类。
- hook trust by hash；`repi hooks`/`/hooks` 可 inspect/trust/disable。
- 把现有 extension event 映射到标准 hook event 名称。

### P1-2：instruction/rules discovery 需要 cap、override、path-scoped lazy load

**现状证据**

- `packages/coding-agent/src/core/resource-loader.ts` 从全局 agent dir + 当前目录到根目录加载 `AGENTS.md`/`CLAUDE.md`，没有 combined size cap，没有 `AGENTS.override.md`，没有 path-scoped `.repi/rules/*.md` 懒加载。

**顶级设计基线**

- Codex：global + project root→cwd 分层；closer guidance wins；`project_doc_max_bytes` 默认 32 KiB；支持 fallback filenames。
- Claude Code：CLAUDE.md 建议 <200 行；子目录 CLAUDE.md / path-scoped rules 可懒加载；大型规则用 skills/rules 分拆。

**需要大改**

- 加 `AGENTS.override.md` / `REPI.md` / fallback filenames。
- 加 `project_doc_max_bytes` 和启动告警。
- 加 `.repi/rules/*.md`，支持 `paths:` frontmatter，读到匹配文件时再加载。
- instruction debug：`/instructions` 或 `/context` 显示加载来源、顺序、是否截断。

### P1-3：逆向/渗透能力应由“工作流 + 工具胶水”驱动，不靠 profile 指令堆叠

**现状证据**

- `recon-profile.ts` 内含大量领域命令模板和检测规则。
- 这能增强知识覆盖，但会导致死板、启动上下文重、模型难以选择正确分支。

**需要大改**

- 每个领域做成 skill/capsule：
  - `web-api-authz`
  - `js-signature-rebuild`
  - `native-pwn-primitive`
  - `mobile-frida-trace`
  - `firmware-iot-rootfs`
  - `pcap-dfir-carve`
  - `cloud-identity-pivot`
  - `agentsec-boundary`
- 每个 capsule 必须包含：触发条件、passive mapping、live path trace、proof contract、常用工具、artifact schema、failure repair。
- REPI kernel 只负责路由、预算、证据、验证、合并。

### P2：开源产品打磨

- 系统提示和帮助文档中还存在上游产品残留，需要一次性扫干净。
- README 已经较完整，但架构图、模块边界、配置优先级、MCP/hooks/subagents roadmap 还应正式化。
- 版本号要从 `0.78.1-repi.1` 迁移到独立语义版本，例如 `0.1.0` / `0.2.0`。
- CI gate 需要拆分：install、unit、harness、product-surface、secret-scan、docs-link-check。

## 建议实施顺序

1. **先做 ContextManager + profile 拆分**：减少上下文污染，解决“死板、能力弱、越跑越乱”的根因。
2. **再做 MemoryPolicyV3**：修记忆污染，明确 write/recall/trace/quarantine。
3. **做 AgentThreadManager**：让并行/子代理成为交互式一等功能。
4. **做 MCP manager + tool search**：补齐顶级 harness 的工具连接层。
5. **做 hook standardization**：把 extension 能力开放给用户配置并纳入 trust。
6. **做 product polish sweep**：清理产品残留、统一 docs、版本、命令、错误提示。

## 一句话结论

REPI 当前不是“知识不够”，而是 harness 架构过重、上下文常驻太多、记忆/子代理/MCP/hooks 还没有完全一等化。下一阶段要从“魔改大 prompt”转向“薄 kernel + 按需技能 + 受控记忆 + 一等子代理 + 一等 MCP + 可审计 hooks”的架构。

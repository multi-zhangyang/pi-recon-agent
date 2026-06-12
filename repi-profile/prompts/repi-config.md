---
description: 说明 REPI 模型/provider/API key/auto compact 配置
argument-hint: "[provider-or-error]"
---

REPI configuration help: $ARGUMENTS

必须直接回答，不要只让用户看文档。输出：

1. 配置文件位置：`~/.repi/agent/models.json`、`~/.repi/agent/settings.json`、`~/.repi/agent/auth.json`；说明 REPI 独立于原版 `pi` / `~/.pi/agent`。
2. 给一个 OpenAI-compatible `models.json` 示例，使用占位符环境变量，不写真实 token。
3. 如问题涉及 Anthropic-compatible，则给 `api: "anthropic-messages"` 示例；如是本地模型，则给 `http://127.0.0.1:8000/v1` OpenAI-compatible 示例。
4. 网关格式不确定时先给 `repi provider-doctor --base-url <url> --model <id> --api auto`，让 REPI 探测 OpenAI Chat Completions / OpenAI Responses / Anthropic Messages endpoint 并输出 env-ref-only `models.json` template；如果 `openai-responses` 是 `endpoint_not_found`，就按通过的 `openai-completions` 或 `anthropic-messages` 配。
5. 给验证命令：`repi model doctor`、`repi --offline --list-models` 和 `repi --offline --list-models <provider-or-model>` 做离线解析；真实调用再用 `repi --provider <provider-id> --model <model-id> --thinking off --no-tools --no-session -p "Reply exactly: PROVIDER_OK"`。
6. 如果问价格/缓存，说明 `models[].cost.input/output/cacheRead/cacheWrite` 单位是美元 / 百万 tokens，并给 `repi model cost --provider <id> --model <id> --input-tokens N --output-tokens N --cache-read-tokens N --cache-write-tokens N`。
7. 说明 auto compact：`triggerPercent=85`、`warningPercent=80`、`reserveTokens=16384`、`keepRecentTokens=36000`，触发阈值 `min(contextWindow * triggerPercent / 100, contextWindow - reserveTokens)`。
8. 指向 `docs/reverse-agent/repi-runtime-configuration.md` 和 `docs/reverse-agent/model-provider-formats.md`。
